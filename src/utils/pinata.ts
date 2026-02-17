import pinataSDK from '@pinata/sdk';
import { AppError } from '../middleware/errorHandler';

let pinataClient: any = null;

const getPinataClient = () => {
    if (pinataClient) return pinataClient;

    const jwt = process.env.PINATA_JWT;
    const apiKey = process.env.PINATA_API_KEY;
    const secretKey = process.env.PINATA_SECRET_API_KEY;

    if (jwt) {
        pinataClient = new pinataSDK({ pinataJWTKey: jwt });
    } else if (apiKey && secretKey) {
        pinataClient = new pinataSDK({
            pinataApiKey: apiKey,
            pinataSecretApiKey: secretKey
        });
    } else {
        throw new AppError('Pinata credentials not found in environment', 500);
    }

    return pinataClient;
};

/**
 * Upload a buffer to Pinata using a readable stream
 */
export const uploadToPinata = async (
    fileBuffer: Buffer,
    fileName: string,
    metadata?: Record<string, any>
): Promise<string> => {
    try {
        const { Readable } = require('stream');
        const stream = Readable.from(fileBuffer);

        // Pinata SDK requires the stream to have a path property for certain types
        (stream as any).path = fileName;

        const options = {
            pinataMetadata: {
                name: fileName,
                keyvalues: metadata as Record<string, string | number>
            } as any, // Bypass strict PinataMetadata type if needed, but we provide correct structure
            pinataOptions: {
                cidVersion: 1 as 0 | 1
            }
        };

        console.log(`📡 Pinning to IPFS: ${fileName}...`);
        const pinata = getPinataClient();
        const result = await pinata.pinFileToIPFS(stream, options);
        console.log(`✅ Pinned to IPFS! CID: ${result.IpfsHash}`);
        return result.IpfsHash;
    } catch (error: any) {
        console.error('❌ Pinata upload error:', error);
        throw new AppError(`IPFS Upload failed: ${error.message}`, 500);
    }
};

/**
 * Test Pinata connection
 */
export const testPinataConnection = async (): Promise<boolean> => {
    try {
        const pinata = getPinataClient();
        const result = await pinata.testAuthentication();
        return result.authenticated;
    } catch (error) {
        console.error('Pinata authentication failed:', error);
        return false;
    }
};
