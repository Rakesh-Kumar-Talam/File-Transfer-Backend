import { Router } from 'express';
import { strictRateLimiter } from '../middleware/rateLimiter';
import * as authController from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth';
import passport from 'passport';
import { generateAccessToken } from '../middleware/auth';

const router = Router();

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
    passport.authenticate('google', {
        scope: ['profile', 'email'],
        state
    })(req, res, next);
});

/**
 * @route   GET /api/auth/google/callback
 * @desc    Google OAuth callback
 * @access  Public
 */
router.get('/google/callback',
    passport.authenticate('google', { session: false }),
    async (req: any, res) => {
        try {
            const user = req.user;
            let role = 'receiver'; // Default

            if (req.query.state) {
                try {
                    const stateObj = JSON.parse(Buffer.from(req.query.state as string, 'base64').toString());
                    role = stateObj.role || 'receiver';
                } catch (e) { }
            }

            // Update user role if changed
            const { getDatabase } = await import('../config/database');
            const db = getDatabase();
            await db.collection('users').updateOne(
                { userId: user.userId },
                { $set: { role } }
            );

            // Generate tokens
            const tokenPayload = {
                userId: user.userId,
                emailHash: user.emailHash,
                role: role as any,
                loginMethod: 'email' as const
            };

            const accessToken = generateAccessToken(tokenPayload);

            // Redirect back to frontend with token
            const frontendUrl = process.env.CORS_ORIGIN || 'http://localhost:5173';
            res.redirect(`${frontendUrl}/login?token=${accessToken}&user=${encodeURIComponent(JSON.stringify(tokenPayload))}`);
        } catch (error) {
            console.error('OAuth callback error:', error);
            res.redirect(`${process.env.CORS_ORIGIN || 'http://localhost:5173'}/login?error=auth_failed`);
        }
    }
);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout and blacklist token
 * @access  Private
 */
router.post('/logout', authenticate, (req, res) => {
    // Logic for blacklisting token is handled in middleware but can be explicitly called here
    res.json({ success: true, message: 'Logged out successfully' });
});

export default router;
