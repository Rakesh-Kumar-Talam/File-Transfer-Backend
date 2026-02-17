import crypto from 'crypto';
import { ethers } from 'ethers';

/**
 * Hash email using SHA-256 for privacy
 */
export const hashEmail = (email: string): string => {
    return crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
};

/**
 * Generate a random nonce for wallet authentication
 */
export const generateNonce = (): string => {
    return crypto.randomBytes(32).toString('hex');
};

/**
 * Verify wallet signature
 */
export const verifyWalletSignature = (
    message: string,
    signature: string,
    expectedAddress: string
): boolean => {
    try {
        const recoveredAddress = ethers.verifyMessage(message, signature);
        return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
    } catch (error) {
        console.error('Signature verification error:', error);
        return false;
    }
};

/**
 * Generate policy hash from access control parameters
 */
export const generatePolicyHash = (
    ipfsCID: string,
    expiryTimestamp: number,
    maxAccess: number,
    receivers: string[]
): string => {
    const data = JSON.stringify({
        ipfsCID,
        expiryTimestamp,
        maxAccess,
        receivers: receivers.sort(), // Sort for consistency
    });

    return crypto.createHash('sha256').update(data).digest('hex');
};

/**
 * Encrypt data using AES-256-GCM
 */
export const encryptData = (
    plaintext: string,
    key: Buffer
): { ciphertext: string; iv: string; authTag: string } => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
        ciphertext,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
    };
};

/**
 * Decrypt data using AES-256-GCM
 */
export const decryptData = (
    ciphertext: string,
    key: Buffer,
    iv: string,
    authTag: string
): string => {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(iv, 'hex')
    );

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');

    return plaintext;
};

/**
 * Derive key using HKDF
 */
export const deriveKey = (
    masterKey: Buffer,
    salt: Buffer,
    info: string,
    length: number = 32
): Buffer => {
    return Buffer.from(crypto.hkdfSync('sha256', masterKey, salt, info, length));
};

/**
 * Generate a secure random key
 */
export const generateKey = (length: number = 32): Buffer => {
    return crypto.randomBytes(length);
};

/**
 * Hash password using bcrypt-compatible method
 */
export const hashPassword = async (password: string): Promise<string> => {
    const bcrypt = require('bcryptjs');
    const salt = await bcrypt.genSalt(12);
    return bcrypt.hash(password, salt);
};

/**
 * Verify password against hash
 */
export const verifyPassword = async (
    password: string,
    hash: string
): Promise<boolean> => {
    const bcrypt = require('bcryptjs');
    return bcrypt.compare(password, hash);
};

/**
 * Generate TOTP secret for 2FA
 */
export const generateTOTPSecret = (): string => {
    return crypto.randomBytes(20).toString('hex');
};

/**
 * Verify TOTP token
 */
export const verifyTOTP = (token: string, secret: string): boolean => {
    // Simple TOTP implementation (in production, use a library like 'otplib')
    const window = 30; // 30-second window
    const currentTime = Math.floor(Date.now() / 1000 / window);

    for (let i = -1; i <= 1; i++) {
        const time = currentTime + i;
        const expectedToken = generateTOTPToken(secret, time);
        if (token === expectedToken) {
            return true;
        }
    }

    return false;
};

/**
 * Generate TOTP token
 */
const generateTOTPToken = (secret: string, time: number): string => {
    const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'hex'));
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigInt64BE(BigInt(time));

    const hash = hmac.update(timeBuffer).digest();
    const offset = hash[hash.length - 1] & 0xf;
    const binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    const otp = binary % 1000000;
    return otp.toString().padStart(6, '0');
};

/**
 * Generate a secure file ID
 */
export const generateFileId = (
    sender: string,
    ipfsCID: string,
    timestamp: number
): string => {
    const data = `${sender}:${ipfsCID}:${timestamp}:${crypto.randomBytes(16).toString('hex')}`;
    return crypto.createHash('sha256').update(data).digest('hex');
};

/**
 * Sanitize input to prevent injection attacks
 */
export const sanitizeInput = (input: string): string => {
    return input
        .replace(/[<>]/g, '') // Remove HTML tags
        .replace(/['"]/g, '') // Remove quotes
        .trim();
};
