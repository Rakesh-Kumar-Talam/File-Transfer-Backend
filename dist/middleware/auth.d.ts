import { Request, Response, NextFunction } from 'express';
export interface JWTPayload {
    userId: string;
    walletAddress?: string;
    emailHash?: string;
    role: 'sender' | 'receiver' | 'admin' | 'user';
    loginMethod: 'wallet' | 'email';
}
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
export declare const generateAccessToken: (payload: JWTPayload) => string;
/**
 * Generate JWT refresh token
 */
export declare const generateRefreshToken: (payload: JWTPayload) => string;
/**
 * Verify JWT token
 */
export declare const verifyToken: (token: string, isRefresh?: boolean) => JWTPayload;
/**
 * Authentication middleware
 */
export declare const authenticate: (req: Request, res: Response, next: NextFunction) => Promise<void>;
/**
 * Role-based authorization middleware
 */
export declare const authorize: (...allowedRoles: Array<"sender" | "receiver" | "admin" | "user">) => (req: Request, res: Response, next: NextFunction) => void;
/**
 * Admin-only middleware
 */
export declare const adminOnly: (req: Request, res: Response, next: NextFunction) => void;
/**
 * Blacklist a token (for logout)
 */
export declare const blacklistToken: (token: string) => Promise<void>;
/**
 * Generate download access token (short-lived)
 */
export declare const generateDownloadToken: (fileId: string, receiverAddress: string) => string;
/**
 * Verify download token
 */
export declare const verifyDownloadToken: (token: string) => {
    fileId: string;
    receiverAddress: string;
};
//# sourceMappingURL=auth.d.ts.map