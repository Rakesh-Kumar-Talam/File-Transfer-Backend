"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.testPinataConnection = exports.uploadToPinata = void 0;
const sdk_1 = __importDefault(require("@pinata/sdk"));
const errorHandler_1 = require("../middleware/errorHandler");
let pinataClient = null;
const getPinataClient = () => {
    if (pinataClient)
        return pinataClient;
    const jwt = process.env.PINATA_JWT;
    const apiKey = process.env.PINATA_API_KEY;
    const secretKey = process.env.PINATA_SECRET_API_KEY;
    if (jwt) {
        pinataClient = new sdk_1.default({ pinataJWTKey: jwt });
    }
    else if (apiKey && secretKey) {
        pinataClient = new sdk_1.default({
            pinataApiKey: apiKey,
            pinataSecretApiKey: secretKey
        });
    }
    else {
        throw new errorHandler_1.AppError('Pinata credentials not found in environment', 500);
    }
    return pinataClient;
};
/**
 * Upload a buffer to Pinata using a readable stream
 */
const uploadToPinata = async (fileBuffer, fileName, metadata) => {
    try {
        const { Readable } = require('stream');
        const stream = Readable.from(fileBuffer);
        // Pinata SDK requires the stream to have a path property for certain types
        stream.path = fileName;
        const options = {
            pinataMetadata: {
                name: fileName,
                keyvalues: metadata
            }, // Bypass strict PinataMetadata type if needed, but we provide correct structure
            pinataOptions: {
                cidVersion: 1
            }
        };
        console.log(`📡 Pinning to IPFS: ${fileName}...`);
        const pinata = getPinataClient();
        const result = await pinata.pinFileToIPFS(stream, options);
        console.log(`✅ Pinned to IPFS! CID: ${result.IpfsHash}`);
        return result.IpfsHash;
    }
    catch (error) {
        console.error('❌ Pinata upload error:', error);
        throw new errorHandler_1.AppError(`IPFS Upload failed: ${error.message}`, 500);
    }
};
exports.uploadToPinata = uploadToPinata;
/**
 * Test Pinata connection
 */
const testPinataConnection = async () => {
    try {
        const pinata = getPinataClient();
        const result = await pinata.testAuthentication();
        return result.authenticated;
    }
    catch (error) {
        console.error('Pinata authentication failed:', error);
        return false;
    }
};
exports.testPinataConnection = testPinataConnection;
//# sourceMappingURL=pinata.js.map