import Redis from 'ioredis';

let redisClient: Redis | null = null;

export const initRedis = async (): Promise<Redis | null> => {
    try {
        redisClient = new Redis({
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379'),
            password: process.env.REDIS_PASSWORD || undefined,
            retryStrategy: (times) => {
                const delay = Math.min(times * 100, 3000);
                if (times > 3) {
                    console.error('❌ Redis connection failed after 3 attempts');
                    return null; // Stop retrying
                }
                return delay;
            },
            maxRetriesPerRequest: 3,
        });

        redisClient.on('error', (error) => {
            // Log error but don't let it crash the process
            console.error('Redis error:', error.message);
        });

        redisClient.on('connect', () => {
            console.log('✅ Redis connected');
        });

        // Test connection with timeout
        const pingPromise = redisClient.ping();
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Redis connection timeout')), 5000)
        );

        await Promise.race([pingPromise, timeoutPromise]);

        return redisClient;
    } catch (error) {
        console.warn('⚠️ Redis could not be initialized. Some features like rate limiting will fall back to in-memory/open state.');
        console.error('Original Redis error:', error instanceof Error ? error.message : error);
        redisClient = null;
        return null;
    }
};

export const getRedis = (): Redis | null => {
    return redisClient;
};

export const closeRedis = async (): Promise<void> => {
    if (redisClient) {
        await redisClient.quit();
        redisClient = null;
    }
};

// Helper functions for common Redis operations

/**
 * Set a key-value pair with optional expiry
 */
export const setCache = async (
    key: string,
    value: string | object,
    expirySeconds?: number
): Promise<void> => {
    const redis = getRedis();
    if (!redis) return;
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);

    if (expirySeconds) {
        await redis.setex(key, expirySeconds, stringValue);
    } else {
        await redis.set(key, stringValue);
    }
};

/**
 * Get a value by key
 */
export const getCache = async <T = string>(key: string): Promise<T | null> => {
    const redis = getRedis();
    if (!redis) return null;
    const value = await redis.get(key);

    if (!value) return null;

    try {
        return JSON.parse(value) as T;
    } catch {
        return value as T;
    }
};

/**
 * Delete a key
 */
export const deleteCache = async (key: string): Promise<void> => {
    const redis = getRedis();
    if (!redis) return;
    await redis.del(key);
};

/**
 * Check if key exists
 */
export const cacheExists = async (key: string): Promise<boolean> => {
    const redis = getRedis();
    if (!redis) return false;
    const exists = await redis.exists(key);
    return exists === 1;
};

/**
 * Increment a counter
 */
export const incrementCounter = async (
    key: string,
    expirySeconds?: number
): Promise<number> => {
    const redis = getRedis();
    if (!redis) return 0;
    const value = await redis.incr(key);

    if (expirySeconds && value === 1) {
        await redis.expire(key, expirySeconds);
    }

    return value;
};
