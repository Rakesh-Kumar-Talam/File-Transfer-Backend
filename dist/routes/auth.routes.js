"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const authController = __importStar(require("../controllers/auth.controller"));
const auth_1 = require("../middleware/auth");
const passport_1 = __importDefault(require("passport"));
const auth_2 = require("../middleware/auth");
const router = (0, express_1.Router)();
// Apply strict rate limiting to all auth routes
// router.use(strictRateLimiter);
/**
 * @route   POST /api/auth/wallet/nonce
 * @desc    Get nonce for wallet authentication
 * @access  Public
 */
router.post('/wallet/nonce', authController.getNonce);
/**
 * @route   POST /api/auth/wallet/verify
 * @desc    Verify wallet signature and issue JWT
 * @access  Public
 */
router.post('/wallet/verify', authController.verifyWallet);
/**
 * @route   GET /api/auth/google
 * @desc    Google OAuth login
 * @access  Public
 */
router.get('/google', (req, res, next) => {
    const { role } = req.query;
    const state = role ? Buffer.from(JSON.stringify({ role })).toString('base64') : undefined;
    passport_1.default.authenticate('google', {
        scope: ['profile', 'email'],
        state
    })(req, res, next);
});
/**
 * @route   GET /api/auth/google/callback
 * @desc    Google OAuth callback
 * @access  Public
 */
router.get('/google/callback', passport_1.default.authenticate('google', { session: false }), async (req, res) => {
    try {
        const user = req.user;
        let role = 'receiver'; // Default
        if (req.query.state) {
            try {
                const stateObj = JSON.parse(Buffer.from(req.query.state, 'base64').toString());
                role = stateObj.role || 'receiver';
            }
            catch (e) { }
        }
        // Update user role if changed
        const { getDatabase } = await Promise.resolve().then(() => __importStar(require('../config/database')));
        const db = getDatabase();
        await db.collection('users').updateOne({ userId: user.userId }, { $set: { role } });
        // Generate tokens
        const tokenPayload = {
            userId: user.userId,
            emailHash: user.emailHash,
            role: role,
            loginMethod: 'email'
        };
        const accessToken = (0, auth_2.generateAccessToken)(tokenPayload);
        // Redirect back to frontend with token
        const frontendUrl = process.env.CORS_ORIGIN || 'http://localhost:5173';
        res.redirect(`${frontendUrl}/login?token=${accessToken}&user=${encodeURIComponent(JSON.stringify(tokenPayload))}`);
    }
    catch (error) {
        console.error('OAuth callback error:', error);
        res.redirect(`${process.env.CORS_ORIGIN || 'http://localhost:5173'}/login?error=auth_failed`);
    }
});
/**
 * @route   POST /api/auth/logout
 * @desc    Logout and blacklist token
 * @access  Private
 */
router.post('/logout', auth_1.authenticate, (req, res) => {
    // Logic for blacklisting token is handled in middleware but can be explicitly called here
    res.json({ success: true, message: 'Logged out successfully' });
});
exports.default = router;
//# sourceMappingURL=auth.routes.js.map