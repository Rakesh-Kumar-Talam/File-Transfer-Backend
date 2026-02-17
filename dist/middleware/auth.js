"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyDownloadToken = exports.generateDownloadToken = exports.blacklistToken = exports.adminOnly = exports.authorize = exports.authenticate = exports.verifyToken = exports.generateRefreshToken = exports.generateAccessToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const errorHandler_1 = require("./errorHandler");
const redis_1 = require("../config/redis");
/**
 * Generate JWT access token
 */
const generateAccessToken = (payload) => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET not configured');
    }
    return jsonwebtoken_1.default.sign({ ...payload }, secret, {
        expiresIn: (process.env.JWT_EXPIRY || '5m'),
        issuer: 'secure-file-transfer',
    });
};
exports.generateAccessToken = generateAccessToken;
/**
 * Generate JWT refresh token
 */
const generateRefreshToken = (payload) => {
    const secret = process.env.JWT_REFRESH_SECRET;
    if (!secret) {
        throw new Error('JWT_REFRESH_SECRET not configured');
    }
    return jsonwebtoken_1.default.sign({ ...payload }, secret, {
        expiresIn: (process.env.JWT_REFRESH_EXPIRY || '7d'),
        issuer: 'secure-file-transfer',
    });
};
exports.generateRefreshToken = generateRefreshToken;
/**
 * Verify JWT token
 */
const verifyToken = (token, isRefresh = false) => {
    const secret = isRefresh
        ? process.env.JWT_REFRESH_SECRET
        : process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT secret not configured');
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, secret);
        return decoded;
    }
    catch (error) {
        if (error instanceof jsonwebtoken_1.default.TokenExpiredError) {
            throw new errorHandler_1.AppError('Token expired', 401);
        }
        else if (error instanceof jsonwebtoken_1.default.JsonWebTokenError) {
            throw new errorHandler_1.AppError('Invalid token', 401);
        }
        throw new errorHandler_1.AppError('Token verification failed', 401);
    }
};
exports.verifyToken = verifyToken;
/**
 * Authentication middleware
 */
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new errorHandler_1.AppError('No token provided', 401);
        }
        const token = authHeader.substring(7);
        // Check if token is blacklisted
        const isBlacklisted = await (0, redis_1.getCache)(`blacklist:${token}`);
        if (isBlacklisted) {
            throw new errorHandler_1.AppError('Token has been revoked', 401);
        }
        // Verify token
        const payload = (0, exports.verifyToken)(token);
        // Attach user to request
        req.user = payload;
        next();
    }
    catch (error) {
        next(error);
    }
};
exports.authenticate = authenticate;
/**
 * Role-based authorization middleware
 */
const authorize = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            throw new errorHandler_1.AppError('Authentication required', 401);
        }
        if (!allowedRoles.includes(req.user.role)) {
            throw new errorHandler_1.AppError('Insufficient permissions', 403);
        }
        next();
    };
};
exports.authorize = authorize;
/**
 * Admin-only middleware
 */
const adminOnly = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        throw new errorHandler_1.AppError('Admin access required', 403);
    }
    next();
};
exports.adminOnly = adminOnly;
/**
 * Blacklist a token (for logout)
 */
const blacklistToken = async (token) => {
    try {
        const decoded = jsonwebtoken_1.default.decode(token);
        if (decoded && decoded.exp) {
            const expiryTime = decoded.exp - Math.floor(Date.now() / 1000);
            if (expiryTime > 0) {
                await (0, redis_1.setCache)(`blacklist:${token}`, 'true', expiryTime);
            }
        }
    }
    catch (error) {
        console.error('Error blacklisting token:', error);
    }
};
exports.blacklistToken = blacklistToken;
/**
 * Generate download access token (short-lived)
 */
const generateDownloadToken = (fileId, receiverAddress) => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET not configured');
    }
    return jsonwebtoken_1.default.sign({
        fileId,
        receiverAddress,
        type: 'download',
    }, secret, {
        expiresIn: '5m',
        issuer: 'secure-file-transfer',
    });
};
exports.generateDownloadToken = generateDownloadToken;
/**
 * Verify download token
 */
const verifyDownloadToken = (token) => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET not configured');
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, secret);
        if (decoded.type !== 'download') {
            throw new errorHandler_1.AppError('Invalid token type', 401);
        }
        return {
            fileId: decoded.fileId,
            receiverAddress: decoded.receiverAddress,
        };
    }
    catch (error) {
        if (error instanceof jsonwebtoken_1.default.TokenExpiredError) {
            throw new errorHandler_1.AppError('Download token expired. Please request access again.', 401);
        }
        throw new errorHandler_1.AppError('Invalid download token', 401);
    }
};
exports.verifyDownloadToken = verifyDownloadToken;
//# sourceMappingURL=auth.js.map