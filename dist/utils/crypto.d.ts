/**
 * Hash email using SHA-256 for privacy
 */
export declare const hashEmail: (email: string) => string;
/**
 * Generate a random nonce for wallet authentication
 */
export declare const generateNonce: () => string;
/**
 * Verify wallet signature
 */
export declare const verifyWalletSignature: (message: string, signature: string, expectedAddress: string) => boolean;
/**
 * Generate policy hash from access control parameters
 */
export declare const generatePolicyHash: (ipfsCID: string, expiryTimestamp: number, maxAccess: number, receivers: string[]) => string;
/**
 * Encrypt data using AES-256-GCM
 */
export declare const encryptData: (plaintext: string, key: Buffer) => {
    ciphertext: string;
    iv: string;
    authTag: string;
};
/**
 * Decrypt data using AES-256-GCM
 */
export declare const decryptData: (ciphertext: string, key: Buffer, iv: string, authTag: string) => string;
/**
 * Derive key using HKDF
 */
export declare const deriveKey: (masterKey: Buffer, salt: Buffer, info: string, length?: number) => Buffer;
/**
 * Generate a secure random key
 */
export declare const generateKey: (length?: number) => Buffer;
/**
 * Hash password using bcrypt-compatible method
 */
export declare const hashPassword: (password: string) => Promise<string>;
/**
 * Verify password against hash
 */
export declare const verifyPassword: (password: string, hash: string) => Promise<boolean>;
/**
 * Generate TOTP secret for 2FA
 */
export declare const generateTOTPSecret: () => string;
/**
 * Verify TOTP token
 */
export declare const verifyTOTP: (token: string, secret: string) => boolean;
/**
 * Generate a secure file ID
 */
export declare const generateFileId: (sender: string, ipfsCID: string, timestamp: number) => string;
/**
 * Sanitize input to prevent injection attacks
 */
export declare const sanitizeInput: (input: string) => string;
//# sourceMappingURL=crypto.d.ts.map