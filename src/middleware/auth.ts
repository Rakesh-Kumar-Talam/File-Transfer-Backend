import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import { getCache, setCache, deleteCache } from '../config/redis';

export interface JWTPayload {
    userId: string;
    walletAddress?: string;
    emailHash?: string;
    role: 'sender' | 'receiver' | 'admin' | 'user';
    loginMethod: 'wallet' | 'email';
}

// Extend Express Request type
declare global {
    namespace Express {
        interface Request {
            user?: JWTPayload;
        }
    }
}

/**
 * Generate JWT access token
 */
export const generateAccessToken = (payload: JWTPayload): string => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET not configured');
    }

    return jwt.sign({ ...payload }, secret, {
        expiresIn: (process.env.JWT_EXPIRY || '5m') as any,
        issuer: 'secure-file-transfer',
    });
};

/**
 * Generate JWT refresh token
 */
export const generateRefreshToken = (payload: JWTPayload): string => {
    const secret = process.env.JWT_REFRESH_SECRET;
    if (!secret) {
        throw new Error('JWT_REFRESH_SECRET not configured');
    }

    return jwt.sign({ ...payload }, secret, {
        expiresIn: (process.env.JWT_REFRESH_EXPIRY || '7d') as any,
        issuer: 'secure-file-transfer',
    });
};

/**
 * Verify JWT token
 */
export const verifyToken = (token: string, isRefresh: boolean = false): JWTPayload => {
    const secret = isRefresh
        ? process.env.JWT_REFRESH_SECRET
        : process.env.JWT_SECRET;

    if (!secret) {
        throw new Error('JWT secret not configured');
    }

    try {
        const decoded = jwt.verify(token, secret) as JWTPayload;
        return decoded;
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new AppError('Token expired', 401);
        } else if (error instanceof jwt.JsonWebTokenError) {
            throw new AppError('Invalid token', 401);
        }
        throw new AppError('Token verification failed', 401);
    }
};

/**
 * Authentication middleware
 */
export const authenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new AppError('No token provided', 401);
        }

        const token = authHeader.substring(7);

        // Check if token is blacklisted
        const isBlacklisted = await getCache(`blacklist:${token}`);
        if (isBlacklisted) {
            throw new AppError('Token has been revoked', 401);
        }

        // Verify token
        const payload = verifyToken(token);

        // Attach user to request
        req.user = payload;

        next();
    } catch (error) {
        next(error);
    }
};

/**
 * Role-based authorization middleware
 */
export const authorize = (...allowedRoles: Array<'sender' | 'receiver' | 'admin' | 'user'>) => {
    return (req: Request, res: Response, next: NextFunction): void => {
        if (!req.user) {
            throw new AppError('Authentication required', 401);
        }

        if (!allowedRoles.includes(req.user.role)) {
            throw new AppError('Insufficient permissions', 403);
        }

        next();
    };
};

/**
 * Admin-only middleware
 */
export const adminOnly = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    if (!req.user || req.user.role !== 'admin') {
        throw new AppError('Admin access required', 403);
    }
    next();
};

/**
 * Blacklist a token (for logout)
 */
export const blacklistToken = async (token: string): Promise<void> => {
    try {
        const decoded = jwt.decode(token) as any;
        if (decoded && decoded.exp) {
            const expiryTime = decoded.exp - Math.floor(Date.now() / 1000);
            if (expiryTime > 0) {
                await setCache(`blacklist:${token}`, 'true', expiryTime);
            }
        }
    } catch (error) {
        console.error('Error blacklisting token:', error);
    }
};

/**
 * Generate download access token (short-lived)
 */
export const generateDownloadToken = (
    fileId: string,
    receiverAddress: string
): string => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET not configured');
    }

    return jwt.sign(
        {
            fileId,
            receiverAddress,
            type: 'download',
        },
        secret,
        {
            expiresIn: '5m' as any,
            issuer: 'secure-file-transfer',
        }
    );
};

/**
 * Verify download token
 */
export const verifyDownloadToken = (
    token: string
): { fileId: string; receiverAddress: string } => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET not configured');
    }

    try {
        const decoded = jwt.verify(token, secret) as any;

        if (decoded.type !== 'download') {
            throw new AppError('Invalid token type', 401);
        }

        return {
            fileId: decoded.fileId,
            receiverAddress: decoded.receiverAddress,
        };
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new AppError('Download token expired. Please request access again.', 401);
        }
        throw new AppError('Invalid download token', 401);
    }
};
