/**
 * Upload a buffer to Pinata using a readable stream
 */
export declare const uploadToPinata: (fileBuffer: Buffer, fileName: string, metadata?: Record<string, any>) => Promise<string>;
/**
 * Test Pinata connection
 */
export declare const testPinataConnection: () => Promise<boolean>;
//# sourceMappingURL=pinata.d.ts.map