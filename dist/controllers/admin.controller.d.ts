import { Request, Response } from 'express';
/**
 * Get system-wide dashboard stats for admin
 */
export declare const getAdminStats: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Get audit logs across the system
 */
export declare const getAuditLogs: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Get all users
 */
export declare const getUsers: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Toggle user freeze status
 */
export declare const toggleUserFreeze: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Get all files
 */
export declare const getFiles: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Update file policy (Admin)
 */
export declare const updateFilePolicy: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Emergency revoke a file (System Admin)
 */
export declare const emergencyRevoke: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Superuser: Generate download token for auditing any file
 */
export declare const getAdminDownloadToken: (req: Request, res: Response, next: import("express").NextFunction) => void;
export declare const freezeUser: (req: Request, res: Response, next: import("express").NextFunction) => void;
//# sourceMappingURL=admin.controller.d.ts.map