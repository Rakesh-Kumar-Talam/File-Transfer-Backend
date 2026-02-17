import { Request, Response } from 'express';
import { getDatabase } from '../config/database';
import {
    generateNonce,
    verifyWalletSignature,
    hashEmail
} from '../utils/crypto';
import {
    generateAccessToken,
    generateRefreshToken,
    JWTPayload
} from '../middleware/auth';
import { AppError, asyncHandler } from '../middleware/errorHandler';
import { v4 as uuidv4 } from 'uuid';
import { logEvent } from '../utils/auditLogger';

/**
 * Get nonce for wallet login
 */
export const getNonce = asyncHandler(async (req: Request, res: Response) => {
    const { walletAddress } = req.body;
    if (!walletAddress) throw new AppError('Wallet address is required', 400);

    const nonce = generateNonce();
    const db = getDatabase();

    // Store or update nonce for this address
    await db.collection('nonces').updateOne(
        { walletAddress: walletAddress.toLowerCase() },
        { $set: { nonce, createdAt: new Date() } },
        { upsert: true }
    );

    res.json({ success: true, nonce });
});

/**
 * Verify signature and login via wallet
 */
export const verifyWallet = asyncHandler(async (req: Request, res: Response) => {
    const { walletAddress, signature, role: requestedRole } = req.body;
    if (!walletAddress || !signature || !requestedRole) {
        throw new AppError('Missing required fields', 400);
    }

    const db = getDatabase();
    const nonceDoc = await db.collection('nonces').findOne({
        walletAddress: walletAddress.toLowerCase()
    });

    if (!nonceDoc) throw new AppError('Nonce not found. Get nonce first.', 404);

    const message = `Sign this message to authenticate with SecureTransfer: ${nonceDoc.nonce}`;
    console.log(`🔐 Verifying wallet: ${walletAddress}`);
    console.log(`📝 Expected message: "${message}"`);
    console.log(`✍️ Signature provided: ${signature.substring(0, 20)}...`);

    const isValid = verifyWalletSignature(message, signature, walletAddress);

    if (!isValid) {
        // Recover address manually for debug log
        const { ethers } = require('ethers');
        try {
            const recovered = ethers.verifyMessage(message, signature);
            console.error(`❌ Signature Mismatch! Recovered: ${recovered}, Expected: ${walletAddress}`);
        } catch (e) {
            console.error('❌ Signature Malformed:', e);
        }
        throw new AppError('Invalid signature', 401);
    }

    // Clean up nonce
    await db.collection('nonces').deleteOne({ walletAddress: walletAddress.toLowerCase() });

    // Find or create user - UNIQUE BY ADDRESS AND ROLE to prevent context collapse
    const dbUser = await db.collection('users').findOne({
        walletAddress: walletAddress.toLowerCase(),
        role: requestedRole
    });

    if (dbUser && dbUser.status === 'frozen') {
        await logEvent({
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
        throw new AppError('Your account has been frozen. Please contact administration.', 403);
    }

    let userId: string;
    let userRole: 'sender' | 'receiver' | 'admin' | 'user';

    if (!dbUser) {
        userId = uuidv4();
        userRole = requestedRole as any;

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
    } else {
        userId = dbUser.userId;
        userRole = dbUser.role;
        await db.collection('users').updateOne(
            { _id: dbUser._id },
            { $set: { lastLoginAt: new Date() } }
        );
    }

    await logEvent({
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

    const tokenPayload: JWTPayload = {
        userId: userId,
        walletAddress: walletAddress.toLowerCase(),
        role: userRole,
        loginMethod: 'wallet',
    };

    const accessToken = generateAccessToken(tokenPayload);
    const refreshToken = generateRefreshToken(tokenPayload);

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
export const googleLogin = asyncHandler(async (req: Request, res: Response) => {
    const { email, role: requestedRole } = req.body;
    if (!email || !requestedRole) throw new AppError('Email and role are required', 400);

    const emailHash = hashEmail(email);
    const db = getDatabase();

    // Find or create user - UNIQUE BY EMAIL AND ROLE
    const dbUser = await db.collection('users').findOne({
        emailHash,
        role: requestedRole
    });

    if (dbUser && dbUser.status === 'frozen') {
        await logEvent({
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
        throw new AppError('Your account has been frozen. Please contact administration.', 403);
    }

    let userId: string;
    let userRole: 'sender' | 'receiver' | 'admin' | 'user';

    if (!dbUser) {
        userId = uuidv4();
        userRole = requestedRole as any;
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
    } else {
        userId = dbUser.userId;
        userRole = dbUser.role;
        await db.collection('users').updateOne(
            { _id: dbUser._id },
            { $set: { lastLoginAt: new Date() } }
        );
    }

    await logEvent({
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

    const tokenPayload: JWTPayload = {
        userId,
        emailHash,
        role: userRole,
        loginMethod: 'email',
    };

    const accessToken = generateAccessToken(tokenPayload);

    res.json({
        success: true,
        user: tokenPayload,
        accessToken
    });
});
