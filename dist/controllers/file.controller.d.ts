import { Request, Response } from 'express';
/**
 * Register file upload metadata
 */
export declare const registerFileUpload: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Get files for current user
 */
export declare const getMyFiles: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Request download access token
 */
export declare const requestDownloadToken: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Revoke file access
 */
export declare const revokeFile: (req: Request, res: Response, next: import("express").NextFunction) => void;
/**
 * Proxy IPFS content to avoid CORS issues in the browser
 */
export declare const proxyIPFS: (req: Request, res: Response, next: import("express").NextFunction) => void;
//# sourceMappingURL=file.controller.d.ts.map