import { Request, Response, NextFunction } from 'express';
import { incrementCounter, getCache } from '../config/redis';

interface RateLimitConfig {
    windowMs: number;
    maxRequests: number;
}

const defaultConfig: RateLimitConfig = {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
};

/**
 * Rate limiter middleware using Redis
 */
export const rateLimiter = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const identifier = getClientIdentifier(req);
        const key = `ratelimit:${identifier}`;
        const windowSeconds = Math.floor(defaultConfig.windowMs / 1000);

        const requestCount = await incrementCounter(key, windowSeconds);

        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', defaultConfig.maxRequests.toString());
        res.setHeader('X-RateLimit-Remaining', Math.max(0, defaultConfig.maxRequests - requestCount).toString());
        res.setHeader('X-RateLimit-Reset', new Date(Date.now() + defaultConfig.windowMs).toISOString());

        if (requestCount > defaultConfig.maxRequests) {
            res.status(429).json({
                success: false,
                message: 'Too many requests. Please try again later.',
                retryAfter: windowSeconds,
            });
            return;
        }

        next();
    } catch (error) {
        console.error('Rate limiter error:', error);
        // On error, allow the request to proceed (fail open)
        next();
    }
};

/**
 * Stricter rate limiter for sensitive endpoints (e.g., login)
 */
export const strictRateLimiter = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const identifier = getClientIdentifier(req);
        const key = `ratelimit:strict:${identifier}`;
        const windowSeconds = 300; // 5 minutes
        const maxRequests = 5;

        const requestCount = await incrementCounter(key, windowSeconds);

        res.setHeader('X-RateLimit-Limit', maxRequests.toString());
        res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - requestCount).toString());

        if (requestCount > maxRequests) {
            res.status(429).json({
                success: false,
                message: 'Too many authentication attempts. Please try again in 5 minutes.',
                retryAfter: windowSeconds,
            });
            return;
        }

        next();
    } catch (error) {
        console.error('Strict rate limiter error:', error);
        next();
    }
};

/**
 * Get client identifier (IP address or user ID)
 */
const getClientIdentifier = (req: Request): string => {
    // Try to get user ID from auth token if available
    const userId = (req as any).user?.userId;
    if (userId) {
        return `user:${userId}`;
    }

    // Fall back to IP address
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string'
        ? forwarded.split(',')[0].trim()
        : req.socket.remoteAddress || 'unknown';

    return `ip:${ip}`;
};

/**
 * Check if client is rate limited
 */
export const isRateLimited = async (identifier: string): Promise<boolean> => {
    try {
        const key = `ratelimit:${identifier}`;
        const count = await getCache<number>(key);
        return count !== null && count >= defaultConfig.maxRequests;
    } catch (error) {
        console.error('Rate limit check error:', error);
        return false;
    }
};
