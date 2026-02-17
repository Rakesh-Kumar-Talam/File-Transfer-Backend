"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.googleLogin = exports.verifyWallet = exports.getNonce = void 0;
const database_1 = require("../config/database");
const crypto_1 = require("../utils/crypto");
const auth_1 = require("../middleware/auth");
const errorHandler_1 = require("../middleware/errorHandler");
const uuid_1 = require("uuid");
const auditLogger_1 = require("../utils/auditLogger");
/**
 * Get nonce for wallet login
 */
exports.getNonce = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { walletAddress } = req.body;
    if (!walletAddress)
        throw new errorHandler_1.AppError('Wallet address is required', 400);
    const nonce = (0, crypto_1.generateNonce)();
    const db = (0, database_1.getDatabase)();
    // Store or update nonce for this address
    await db.collection('nonces').updateOne({ walletAddress: walletAddress.toLowerCase() }, { $set: { nonce, createdAt: new Date() } }, { upsert: true });
    res.json({ success: true, nonce });
});
/**
 * Verify signature and login via wallet
 */
exports.verifyWallet = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { walletAddress, signature, role: requestedRole } = req.body;
    if (!walletAddress || !signature || !requestedRole) {
        throw new errorHandler_1.AppError('Missing required fields', 400);
    }
    const db = (0, database_1.getDatabase)();
    const nonceDoc = await db.collection('nonces').findOne({
        walletAddress: walletAddress.toLowerCase()
    });
    if (!nonceDoc)
        throw new errorHandler_1.AppError('Nonce not found. Get nonce first.', 404);
    const message = `Sign this message to authenticate with SecureTransfer: ${nonceDoc.nonce}`;
    console.log(`🔐 Verifying wallet: ${walletAddress}`);
    console.log(`📝 Expected message: "${message}"`);
    console.log(`✍️ Signature provided: ${signature.substring(0, 20)}...`);
    const isValid = (0, crypto_1.verifyWalletSignature)(message, signature, walletAddress);
    if (!isValid) {
        // Recover address manually for debug log
        const { ethers } = require('ethers');
        try {
            const recovered = ethers.verifyMessage(message, signature);
            console.error(`❌ Signature Mismatch! Recovered: ${recovered}, Expected: ${walletAddress}`);
        }
        catch (e) {
            console.error('❌ Signature Malformed:', e);
        }
        throw new errorHandler_1.AppError('Invalid signature', 401);
    }
    // Clean up nonce
    await db.collection('nonces').deleteOne({ walletAddress: walletAddress.toLowerCase() });
    // Find or create user - UNIQUE BY ADDRESS AND ROLE to prevent context collapse
    const dbUser = await db.collection('users').findOne({
        walletAddress: walletAddress.toLowerCase(),
        role: requestedRole
    });
    if (dbUser && dbUser.status === 'frozen') {
        await (0, auditLogger_1.logEvent)({
            actorId: dbUser.userId,
            actorRole: dbUser.role,
            actorType: 'wallet',
            actionType: 'LOGIN_FAILURE',
            targetType: 'auth',
            metadata: { reason: 'Account frozen', walletAddress },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'failure'
        });
        throw new errorHandler_1.AppError('Your account has been frozen. Please contact administration.', 403);
    }
    let userId;
    let userRole;
    if (!dbUser) {
        userId = (0, uuid_1.v4)();
        userRole = requestedRole;
        const newUser = {
            userId,
            walletAddress: walletAddress.toLowerCase(),
            role: userRole,
            loginMethod: 'wallet',
            status: 'active',
            createdAt: new Date(),
            lastLoginAt: new Date(),
        };
        await db.collection('users').insertOne(newUser);
    }
    else {
        userId = dbUser.userId;
        userRole = dbUser.role;
        await db.collection('users').updateOne({ _id: dbUser._id }, { $set: { lastLoginAt: new Date() } });
    }
    await (0, auditLogger_1.logEvent)({
        actorId: userId,
        actorRole: userRole,
        actorType: 'wallet',
        actionType: 'LOGIN_SUCCESS',
        targetType: 'auth',
        metadata: { walletAddress, loginMethod: 'wallet' },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        status: 'success'
    });
    const tokenPayload = {
        userId: userId,
        walletAddress: walletAddress.toLowerCase(),
        role: userRole,
        loginMethod: 'wallet',
    };
    const accessToken = (0, auth_1.generateAccessToken)(tokenPayload);
    const refreshToken = (0, auth_1.generateRefreshToken)(tokenPayload);
    res.json({
        success: true,
        user: tokenPayload,
        accessToken,
        refreshToken
    });
});
/**
 * Mock Google OAuth handler
 */
exports.googleLogin = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { email, role: requestedRole } = req.body;
    if (!email || !requestedRole)
        throw new errorHandler_1.AppError('Email and role are required', 400);
    const emailHash = (0, crypto_1.hashEmail)(email);
    const db = (0, database_1.getDatabase)();
    // Find or create user - UNIQUE BY EMAIL AND ROLE
    const dbUser = await db.collection('users').findOne({
        emailHash,
        role: requestedRole
    });
    if (dbUser && dbUser.status === 'frozen') {
        await (0, auditLogger_1.logEvent)({
            actorId: dbUser.userId,
            actorRole: dbUser.role,
            actorType: 'email',
            actionType: 'LOGIN_FAILURE',
            targetType: 'auth',
            metadata: { reason: 'Account frozen', emailHash },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'failure'
        });
        throw new errorHandler_1.AppError('Your account has been frozen. Please contact administration.', 403);
    }
    let userId;
    let userRole;
    if (!dbUser) {
        userId = (0, uuid_1.v4)();
        userRole = requestedRole;
        const newUser = {
            userId,
            emailHash,
            role: userRole,
            loginMethod: 'email',
            status: 'active',
            createdAt: new Date(),
            lastLoginAt: new Date(),
        };
        await db.collection('users').insertOne(newUser);
    }
    else {
        userId = dbUser.userId;
        userRole = dbUser.role;
        await db.collection('users').updateOne({ _id: dbUser._id }, { $set: { lastLoginAt: new Date() } });
    }
    await (0, auditLogger_1.logEvent)({
        actorId: userId,
        actorRole: userRole,
        actorType: 'email',
        actionType: 'LOGIN_SUCCESS',
        targetType: 'auth',
        metadata: { emailHash, loginMethod: 'email' },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        status: 'success'
    });
    const tokenPayload = {
        userId,
        emailHash,
        role: userRole,
        loginMethod: 'email',
    };
    const accessToken = (0, auth_1.generateAccessToken)(tokenPayload);
    res.json({
        success: true,
        user: tokenPayload,
        accessToken
    });
});
//# sourceMappingURL=auth.controller.js.map