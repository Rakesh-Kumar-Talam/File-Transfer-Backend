"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.incrementCounter = exports.cacheExists = exports.deleteCache = exports.getCache = exports.setCache = exports.closeRedis = exports.getRedis = exports.initRedis = void 0;
const ioredis_1 = __importDefault(require("ioredis"));
let redisClient = null;
const initRedis = async () => {
    try {
        redisClient = new ioredis_1.default({
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
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Redis connection timeout')), 5000));
        await Promise.race([pingPromise, timeoutPromise]);
        return redisClient;
    }
    catch (error) {
        console.warn('⚠️ Redis could not be initialized. Some features like rate limiting will fall back to in-memory/open state.');
        console.error('Original Redis error:', error instanceof Error ? error.message : error);
        redisClient = null;
        return null;
    }
};
exports.initRedis = initRedis;
const getRedis = () => {
    return redisClient;
};
exports.getRedis = getRedis;
const closeRedis = async () => {
    if (redisClient) {
        await redisClient.quit();
        redisClient = null;
    }
};
exports.closeRedis = closeRedis;
// Helper functions for common Redis operations
/**
 * Set a key-value pair with optional expiry
 */
const setCache = async (key, value, expirySeconds) => {
    const redis = (0, exports.getRedis)();
    if (!redis)
        return;
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
    if (expirySeconds) {
        await redis.setex(key, expirySeconds, stringValue);
    }
    else {
        await redis.set(key, stringValue);
    }
};
exports.setCache = setCache;
/**
 * Get a value by key
 */
const getCache = async (key) => {
    const redis = (0, exports.getRedis)();
    if (!redis)
        return null;
    const value = await redis.get(key);
    if (!value)
        return null;
    try {
        return JSON.parse(value);
    }
    catch {
        return value;
    }
};
exports.getCache = getCache;
/**
 * Delete a key
 */
const deleteCache = async (key) => {
    const redis = (0, exports.getRedis)();
    if (!redis)
        return;
    await redis.del(key);
};
exports.deleteCache = deleteCache;
/**
 * Check if key exists
 */
const cacheExists = async (key) => {
    const redis = (0, exports.getRedis)();
    if (!redis)
        return false;
    const exists = await redis.exists(key);
    return exists === 1;
};
exports.cacheExists = cacheExists;
/**
 * Increment a counter
 */
const incrementCounter = async (key, expirySeconds) => {
    const redis = (0, exports.getRedis)();
    if (!redis)
        return 0;
    const value = await redis.incr(key);
    if (expirySeconds && value === 1) {
        await redis.expire(key, expirySeconds);
    }
    return value;
};
exports.incrementCounter = incrementCounter;
//# sourceMappingURL=redis.js.map