"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeInput = exports.generateFileId = exports.verifyTOTP = exports.generateTOTPSecret = exports.verifyPassword = exports.hashPassword = exports.generateKey = exports.deriveKey = exports.decryptData = exports.encryptData = exports.generatePolicyHash = exports.verifyWalletSignature = exports.generateNonce = exports.hashEmail = void 0;
const crypto_1 = __importDefault(require("crypto"));
const ethers_1 = require("ethers");
/**
 * Hash email using SHA-256 for privacy
 */
const hashEmail = (email) => {
    return crypto_1.default.createHash('sha256').update(email.toLowerCase()).digest('hex');
};
exports.hashEmail = hashEmail;
/**
 * Generate a random nonce for wallet authentication
 */
const generateNonce = () => {
    return crypto_1.default.randomBytes(32).toString('hex');
};
exports.generateNonce = generateNonce;
/**
 * Verify wallet signature
 */
const verifyWalletSignature = (message, signature, expectedAddress) => {
    try {
        const recoveredAddress = ethers_1.ethers.verifyMessage(message, signature);
        return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
    }
    catch (error) {
        console.error('Signature verification error:', error);
        return false;
    }
};
exports.verifyWalletSignature = verifyWalletSignature;
/**
 * Generate policy hash from access control parameters
 */
const generatePolicyHash = (ipfsCID, expiryTimestamp, maxAccess, receivers) => {
    const data = JSON.stringify({
        ipfsCID,
        expiryTimestamp,
        maxAccess,
        receivers: receivers.sort(), // Sort for consistency
    });
    return crypto_1.default.createHash('sha256').update(data).digest('hex');
};
exports.generatePolicyHash = generatePolicyHash;
/**
 * Encrypt data using AES-256-GCM
 */
const encryptData = (plaintext, key) => {
    const iv = crypto_1.default.randomBytes(12);
    const cipher = crypto_1.default.createCipheriv('aes-256-gcm', key, iv);
    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
        ciphertext,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
    };
};
exports.encryptData = encryptData;
/**
 * Decrypt data using AES-256-GCM
 */
const decryptData = (ciphertext, key, iv, authTag) => {
    const decipher = crypto_1.default.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
    return plaintext;
};
exports.decryptData = decryptData;
/**
 * Derive key using HKDF
 */
const deriveKey = (masterKey, salt, info, length = 32) => {
    return Buffer.from(crypto_1.default.hkdfSync('sha256', masterKey, salt, info, length));
};
exports.deriveKey = deriveKey;
/**
 * Generate a secure random key
 */
const generateKey = (length = 32) => {
    return crypto_1.default.randomBytes(length);
};
exports.generateKey = generateKey;
/**
 * Hash password using bcrypt-compatible method
 */
const hashPassword = async (password) => {
    const bcrypt = require('bcryptjs');
    const salt = await bcrypt.genSalt(12);
    return bcrypt.hash(password, salt);
};
exports.hashPassword = hashPassword;
/**
 * Verify password against hash
 */
const verifyPassword = async (password, hash) => {
    const bcrypt = require('bcryptjs');
    return bcrypt.compare(password, hash);
};
exports.verifyPassword = verifyPassword;
/**
 * Generate TOTP secret for 2FA
 */
const generateTOTPSecret = () => {
    return crypto_1.default.randomBytes(20).toString('hex');
};
exports.generateTOTPSecret = generateTOTPSecret;
/**
 * Verify TOTP token
 */
const verifyTOTP = (token, secret) => {
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
exports.verifyTOTP = verifyTOTP;
/**
 * Generate TOTP token
 */
const generateTOTPToken = (secret, time) => {
    const hmac = crypto_1.default.createHmac('sha1', Buffer.from(secret, 'hex'));
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigInt64BE(BigInt(time));
    const hash = hmac.update(timeBuffer).digest();
    const offset = hash[hash.length - 1] & 0xf;
    const binary = ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    const otp = binary % 1000000;
    return otp.toString().padStart(6, '0');
};
/**
 * Generate a secure file ID
 */
const generateFileId = (sender, ipfsCID, timestamp) => {
    const data = `${sender}:${ipfsCID}:${timestamp}:${crypto_1.default.randomBytes(16).toString('hex')}`;
    return crypto_1.default.createHash('sha256').update(data).digest('hex');
};
exports.generateFileId = generateFileId;
/**
 * Sanitize input to prevent injection attacks
 */
const sanitizeInput = (input) => {
    return input
        .replace(/[<>]/g, '') // Remove HTML tags
        .replace(/['"]/g, '') // Remove quotes
        .trim();
};
exports.sanitizeInput = sanitizeInput;
//# sourceMappingURL=crypto.js.map