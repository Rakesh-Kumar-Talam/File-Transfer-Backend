import Redis from 'ioredis';
export declare const initRedis: () => Promise<Redis | null>;
export declare const getRedis: () => Redis | null;
export declare const closeRedis: () => Promise<void>;
/**
 * Set a key-value pair with optional expiry
 */
export declare const setCache: (key: string, value: string | object, expirySeconds?: number) => Promise<void>;
/**
 * Get a value by key
 */
export declare const getCache: <T = string>(key: string) => Promise<T | null>;
/**
 * Delete a key
 */
export declare const deleteCache: (key: string) => Promise<void>;
/**
 * Check if key exists
 */
export declare const cacheExists: (key: string) => Promise<boolean>;
/**
 * Increment a counter
 */
export declare const incrementCounter: (key: string, expirySeconds?: number) => Promise<number>;
//# sourceMappingURL=redis.d.ts.map