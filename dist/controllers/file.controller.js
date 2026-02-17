"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.proxyIPFS = exports.revokeFile = exports.requestDownloadToken = exports.getMyFiles = exports.registerFileUpload = void 0;
const axios_1 = __importDefault(require("axios"));
const database_1 = require("../config/database");
const errorHandler_1 = require("../middleware/errorHandler");
const auth_1 = require("../middleware/auth");
const uuid_1 = require("uuid");
const ethers_1 = require("ethers");
const crypto_1 = require("../utils/crypto");
const pinata_1 = require("../utils/pinata");
const auditLogger_1 = require("../utils/auditLogger");
/**
 * Helper to ensure we only pass valid 20-byte addresses to the contract
 */
const toValidAddress = (str) => {
    if (!str || typeof str !== 'string')
        return null;
    const clean = str.trim();
    if (!clean)
        return null;
    // 1. If it's a valid Ethereum address, checksum it
    if (ethers_1.ethers.isAddress(clean))
        return ethers_1.ethers.getAddress(clean);
    // 2. If it's an email address, hash it first
    // 2. If it's an email address, hash it first
    // Cast to string because ethers.isAddress type guard narrows the type incorrectly in the else branch
    let hex = clean;
    if (hex.includes('@') && hex.includes('.')) {
        hex = (0, crypto_1.hashEmail)(hex);
    }
    // 3. If it looks like a hex string (e.g. emailHash), derive a valid address from it
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (/^[0-9a-fA-F]{40,64}$/.test(cleanHex)) {
        return ethers_1.ethers.getAddress('0x' + cleanHex.substring(0, 40));
    }
    return null;
};
/**
 * Register file upload metadata
 */
exports.registerFileUpload = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    let { name, size, type, ipfsCID, policy, wrappedKey, ivs } = req.body;
    const user = req.user;
    // Parse stringified JSON from FormData
    if (typeof policy === 'string') {
        try {
            policy = JSON.parse(policy);
        }
        catch (e) {
            throw new errorHandler_1.AppError('Invalid policy format', 400);
        }
    }
    if (typeof ivs === 'string') {
        try {
            ivs = JSON.parse(ivs);
        }
        catch (e) {
            // Optional: fallback to empty array
            ivs = [];
        }
    }
    if (!user || (user.role !== 'sender' && user.role !== 'user')) {
        throw new errorHandler_1.AppError('Only senders can upload files', 403);
    }
    // Actual IPFS upload if file is provided
    if (req.file) {
        console.log(`📦 Uploading ${req.file.originalname} to Pinata...`);
        ipfsCID = await (0, pinata_1.uploadToPinata)(req.file.buffer, req.file.originalname || name, {
            sender: user.userId,
            size: req.file.size
        });
        name = req.file.originalname || name;
        size = req.file.size || size;
        type = req.file.mimetype || type;
    }
    if (!ipfsCID || !policy || !wrappedKey) {
        throw new errorHandler_1.AppError('Missing file metadata, policy, or encryption data', 400);
    }
    let { expiryDays, maxAccess, receivers } = policy;
    // Validate and set defaults for policy values
    expiryDays = parseInt(String(expiryDays));
    if (isNaN(expiryDays) || expiryDays < 1)
        expiryDays = 7;
    maxAccess = parseInt(String(maxAccess));
    if (isNaN(maxAccess) || maxAccess < 0)
        maxAccess = 5;
    console.log(`[DEBUG] Registering File - Policy: Expiry=${expiryDays}d, MaxAccess=${maxAccess}`);
    const receiverAddresses = Array.isArray(receivers)
        ? receivers
        : (typeof receivers === 'string' ? receivers.split(',').map((r) => r.trim()) : []);
    console.log('📧 Parsed Receiver Inputs:', receiverAddresses);
    console.log(`🚀 Starting registration for file: ${name} (${ipfsCID})`);
    // 1. Blockchain Transaction
    const rpcUrl = process.env.POLYGON_RPC_URL;
    const privateKey = process.env.PRIVATE_KEY;
    const contractAddress = process.env.VITE_CONTRACT_ADDRESS;
    if (!rpcUrl || !privateKey || !contractAddress) {
        console.error('❌ Missing blockchain config:', { rpcUrl: !!rpcUrl, privateKey: !!privateKey, contractAddress: !!contractAddress });
        throw new errorHandler_1.AppError('Blockchain configuration missing on server', 500);
    }
    const provider = new ethers_1.ethers.JsonRpcProvider(rpcUrl);
    const wallet = new ethers_1.ethers.Wallet(privateKey, provider);
    // ABI for registerFile
    const abi = [
        "function registerFile(string _ipfsCID, bytes32 _policyHash, uint256 _expiryTimestamp, uint256 _maxAccess, address[] _receivers) external returns (bytes32)"
    ];
    const contract = new ethers_1.ethers.Contract(contractAddress, abi, wallet);
    // expiryTimestamp is calculated in seconds for the blockchain (Solidity uses seconds)
    // But for MongoDB and JS comparisons, we need milliseconds.
    const expiryTimestampSeconds = Math.floor(Date.now() / 1000) + (expiryDays * 24 * 60 * 60);
    const senderRaw = user.walletAddress || user.emailHash || '';
    const senderAddress = toValidAddress(senderRaw);
    if (!senderAddress) {
        throw new errorHandler_1.AppError('Invalid sender identity for blockchain transaction', 400);
    }
    const normalizedReceivers = [
        ...new Set([
            senderAddress,
            ...receiverAddresses
                .map((r) => {
                const valid = toValidAddress(r);
                console.log(`🔍 Validating receiver "${r}" -> ${valid}`);
                return valid;
            })
                .filter((r) => r !== null)
        ])
    ];
    console.log(`👥 Normalized Unique Receivers: ${normalizedReceivers.join(', ')}`);
    // Use seconds for blockchain
    const policyHash = '0x' + (0, crypto_1.generatePolicyHash)(ipfsCID, expiryTimestampSeconds, maxAccess, normalizedReceivers);
    console.log(`⛓️  Registering on-chain at address: ${contractAddress} ...`);
    console.log(`👥 Normalized Receivers: ${normalizedReceivers.join(', ')}`);
    let txHash;
    try {
        const tx = await contract.registerFile(ipfsCID, policyHash, BigInt(expiryTimestampSeconds), BigInt(maxAccess), normalizedReceivers, { gasLimit: 1000000 });
        console.log(`⏳ On-chain registration pending: ${tx.hash}`);
        const receipt = await tx.wait();
        txHash = receipt.hash;
        console.log('✅ On-chain registration success:', txHash);
    }
    catch (err) {
        console.error('❌ Blockchain transaction failed:', err);
        // Handle insufficient funds gracefully to keep app functional
        if (err.code === 'INSUFFICIENT_FUNDS' || (err.message && err.message.includes('insufficient funds'))) {
            console.warn('⚠️ WARNING: Wallet has no MATIC. Using a placeholder TX hash to maintain app state.');
            txHash = `faucet-pending-${(0, uuid_1.v4)().substring(0, 8)}`;
        }
        else {
            throw new errorHandler_1.AppError(`Blockchain transaction failed: ${err.message}`, 500);
        }
    }
    // 2. Database Update
    const db = (0, database_1.getDatabase)();
    const fileRecord = {
        fileId: (0, uuid_1.v4)(),
        onChainId: txHash,
        name,
        size,
        type,
        ipfsCID,
        ivs: ivs || [], // Store initialization vectors for decryption
        sender: user.userId,
        senderAddress: senderAddress,
        policy: {
            // STORE IN MILLISECONDS FOR MONGODB
            expiryTimestamp: expiryTimestampSeconds * 1000,
            maxAccess: maxAccess,
            usedAccess: 0,
        },
        wrappedKeys: normalizedReceivers.map(addr => ({
            receiverAddress: addr,
            key: wrappedKey // Using the same key for all receivers as current frontend only supports single wrapping
        })),
        status: 'active',
        createdAt: new Date(),
    };
    try {
        await db.collection('files').insertOne(fileRecord);
        console.log(`File ${fileRecord.fileId} registered in MongoDB`);
    }
    catch (dbErr) {
        console.error('Database write failed after blockchain success! CRITICAL STATE DRIFT:', dbErr);
        // In production, we would queue a background job to retry or sync from chain
        throw new errorHandler_1.AppError('File registered on blockchain but failed to update database. Please contact support.', 500);
    }
    const isPlaceholder = txHash.startsWith('faucet-pending-');
    await (0, auditLogger_1.logEvent)({
        actorId: user.userId,
        actorRole: user.role,
        actorType: user.loginMethod === 'wallet' ? 'wallet' : 'email',
        actionType: 'FILE_UPLOAD',
        targetType: 'file',
        targetId: fileRecord.fileId,
        metadata: {
            name,
            size,
            type,
            ipfsCID,
            maxAccess,
            txHash,
            receivers: normalizedReceivers
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        status: 'success'
    });
    res.status(201).json({
        success: true,
        file: fileRecord,
        txHash: txHash,
        message: isPlaceholder
            ? 'File uploaded to IPFS, but on-chain registration is pending faucet funding.'
            : 'File registered successfully on-chain and IPFS',
        warning: isPlaceholder ? 'Your wallet has 0 MATIC. On-chain access control will be active once you fund your wallet.' : null
    });
});
/**
 * Get files for current user
 */
exports.getMyFiles = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const user = req.user;
    if (!user)
        throw new errorHandler_1.AppError('Unauthorized', 401);
    const db = (0, database_1.getDatabase)();
    const userId = user.userId;
    // Normalize user's address/identity for querying (ensure same format as stored in wrappedKeys)
    const senderRaw = user.walletAddress || user.emailHash || '';
    const userVirtualAddress = toValidAddress(senderRaw);
    // Find files where user is sender OR authorized receiver
    const files = await db.collection('files').find({
        $or: [
            { sender: userId },
            { 'wrappedKeys.receiverAddress': userVirtualAddress }
        ]
    }).sort({ createdAt: -1 }).toArray();
    res.json({
        success: true,
        files: files.map(f => ({
            fileId: f.fileId,
            name: f.name,
            size: f.size,
            status: f.status,
            type: f.sender === userId ? 'sent' : 'received',
            expiry: new Date(f.policy.expiryTimestamp).toLocaleDateString(),
            downloads: `${f.policy.usedAccess}/${f.policy.maxAccess}`,
            cid: f.ipfsCID,
            // wrappedKey and ivs REMOVED for security. 
            // Only metadata is returned. Keys are fetched via /access endpoint.
        }))
    });
});
/**
 * Request download access token
 */
exports.requestDownloadToken = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { fileId } = req.params;
    const user = req.user;
    if (!user)
        throw new errorHandler_1.AppError('Unauthorized', 401);
    const db = (0, database_1.getDatabase)();
    const file = await db.collection('files').findOne({ fileId });
    if (!file)
        throw new errorHandler_1.AppError('File not found', 404);
    console.log(`[DEBUG] File ${fileId} Expiry Check: Now=${Date.now()}, Expiry=${file.policy.expiryTimestamp}`);
    // 1. Verify Status
    if (file.status !== 'active')
        throw new errorHandler_1.AppError('File has been revoked', 403);
    // 2. Verify Expiry
    let expiry = file.policy.expiryTimestamp;
    // Fix: If timestamp looks like seconds (e.g. < 1 trillion), convert to milliseconds
    // This handles legacy files uploaded before the fix
    if (expiry < 1000000000000) {
        console.log(`[FIX] Auto-converting expiry from seconds to ms: ${expiry} -> ${expiry * 1000}`);
        expiry = expiry * 1000;
    }
    console.log(`[DEBUG] Expiry Check: Now=${Date.now()}, Expiry=${expiry}`);
    if (Date.now() > expiry) {
        throw new errorHandler_1.AppError(`File access has expired (Now: ${new Date().toISOString()}, Exp: ${new Date(expiry).toISOString()})`, 403);
    }
    // 3. Verify Access Count
    if (file.policy.usedAccess >= file.policy.maxAccess) {
        throw new errorHandler_1.AppError('Maximum downloads reached', 403);
    }
    // 4. Verify Authorization (Check if receiver has a wrapped key)
    const address = user.walletAddress || user.emailHash;
    if (!address)
        throw new errorHandler_1.AppError('User identity not found', 400);
    // Normalize for comparison (checksum/case-insensitive) just in case
    const normalizedAddress = toValidAddress(address);
    const accessInfo = file.wrappedKeys.find((k) => {
        // Compare normalized addresses if possible, or direct string match
        const kAddress = toValidAddress(k.receiverAddress) || k.receiverAddress;
        return kAddress === normalizedAddress || k.receiverAddress === address;
    });
    if (!accessInfo) {
        console.error(`[AUTH FAILURE] User: ${address} (Normalized: ${normalizedAddress})`);
        console.error(`[AUTH FAILURE] File Receivers:`, file.wrappedKeys.map((k) => k.receiverAddress));
        throw new errorHandler_1.AppError('You are not authorized to access this file', 403);
    }
    // 5. Generate short-lived token
    const downloadToken = (0, auth_1.generateDownloadToken)(fileId, address);
    // 6. Update usage count (In production, this might be triggered after successful download)
    await db.collection('files').updateOne({ fileId }, { $inc: { 'policy.usedAccess': 1 } });
    // Log access event to centralized audit log
    await (0, auditLogger_1.logEvent)({
        actorId: user.userId,
        actorRole: user.role,
        actorType: user.loginMethod === 'wallet' ? 'wallet' : 'email',
        actionType: 'FILE_ACCESS_REQUEST',
        targetType: 'file',
        targetId: fileId,
        metadata: {
            receiverAddress: address,
            fileName: file.name,
            senderId: file.sender
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        status: 'success'
    });
    res.json({
        success: true,
        downloadToken,
        ipfsCID: file.ipfsCID,
        wrappedKey: accessInfo.key,
        ivs: file.ivs || []
    });
});
/**
 * Revoke file access
 */
exports.revokeFile = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { fileId } = req.params;
    const user = req.user;
    if (!user || (user.role !== 'sender' && user.role !== 'user')) {
        throw new errorHandler_1.AppError('Only senders can revoke files', 403);
    }
    const db = (0, database_1.getDatabase)();
    const result = await db.collection('files').updateOne({ fileId, sender: user.userId }, { $set: { status: 'revoked', revokedAt: new Date() } });
    if (result.matchedCount === 0) {
        throw new errorHandler_1.AppError('File not found or unauthorized', 404);
    }
    await (0, auditLogger_1.logEvent)({
        actorId: user.userId,
        actorRole: user.role,
        actorType: user.loginMethod === 'wallet' ? 'wallet' : 'email',
        actionType: 'FILE_REVOKE',
        targetType: 'file',
        targetId: fileId,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        status: 'success'
    });
    res.json({ success: true, message: 'File access revoked successfully' });
});
/**
 * Proxy IPFS content to avoid CORS issues in the browser
 */
exports.proxyIPFS = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { cid } = req.params;
    if (!cid)
        throw new errorHandler_1.AppError('CID is required', 400);
    const gateways = [
        `https://gateway.pinata.cloud/ipfs/${cid}`,
        `https://ipfs.io/ipfs/${cid}`,
        `https://cloudflare-ipfs.com/ipfs/${cid}`,
        `https://dweb.link/ipfs/${cid}`,
        `https://gateway.ipfs.io/ipfs/${cid}`
    ];
    console.log(`📡 Proxying IPFS request for CID: ${cid}`);
    for (const url of gateways) {
        try {
            console.log(`Trying gateway: ${url}`);
            const response = await (0, axios_1.default)({
                method: 'get',
                url: url,
                responseType: 'stream',
                timeout: 15000 // 15s timeout
            });
            // Forward important headers
            const contentType = response.headers['content-type'];
            if (contentType)
                res.setHeader('Content-Type', contentType);
            const contentLength = response.headers['content-length'];
            if (contentLength)
                res.setHeader('Content-Length', contentLength);
            // Set a header to indicate which gateway served it (for debugging)
            res.setHeader('X-IPFS-Gateway', new URL(url).hostname);
            // Stream the response body
            response.data.pipe(res);
            // Handle stream errors
            response.data.on('error', (err) => {
                console.error('❌ Stream Error:', err);
                if (!res.headersSent)
                    res.status(502).end();
            });
            return; // Exit on success
        }
        catch (err) {
            console.error(`⚠️  Gateway failed (${new URL(url).hostname}):`, err.message);
        }
    }
    res.status(502).json({
        success: false,
        message: 'Could not retrieve file from any IPFS gateway. The file may still be propagating or gateways are congested.'
    });
});
//# sourceMappingURL=file.controller.js.map