import { Request, Response, NextFunction } from 'express';
/**
 * Rate limiter middleware using Redis
 */
export declare const rateLimiter: (req: Request, res: Response, next: NextFunction) => Promise<void>;
/**
 * Stricter rate limiter for sensitive endpoints (e.g., login)
 */
export declare const strictRateLimiter: (req: Request, res: Response, next: NextFunction) => Promise<void>;
/**
 * Check if client is rate limited
 */
export declare const isRateLimited: (identifier: string) => Promise<boolean>;
//# sourceMappingURL=rateLimiter.d.ts.map