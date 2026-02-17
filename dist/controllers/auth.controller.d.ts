import { Request, Response } from 'express';
/**
 * Get nonce for wallet login
 */
export declare const getNonce: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Verify signature and login via wallet
 */
export declare const verifyWallet: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Mock Google OAuth handler
 */
export declare const googleLogin: (req: Request, res: Response, next: import("express").NextFunction) => void;
//# sourceMappingURL=auth.controller.d.ts.map