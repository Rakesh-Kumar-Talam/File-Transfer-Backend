import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { getDatabase } from './database';
import { hashEmail } from '../utils/crypto';
import { v4 as uuidv4 } from 'uuid';

export const initPassport = () => {
    passport.use(
        new GoogleStrategy(
            {
                clientID: process.env.GOOGLE_CLIENT_ID!,
                clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
                callbackURL: process.env.GOOGLE_CALLBACK_URL!,
                passReqToCallback: true,
            },
            async (req: any, accessToken, refreshToken, profile, done) => {
                try {
                    const email = profile.emails?.[0].value;
                    if (!email) {
                        return done(new Error('No email found in Google profile'));
                    }

                    const emailHash = hashEmail(email);
                    const db = getDatabase();

                    // Attempt to parse role from state parameter
                    let role = 'receiver'; // Default
                    if (req.query && req.query.state) {
                        try {
                            const stateJson = Buffer.from(req.query.state as string, 'base64').toString();
                            const state = JSON.parse(stateJson);
                            if (state.role && ['sender', 'receiver', 'admin'].includes(state.role)) {
                                role = state.role;
                            }
                        } catch (e) {
                            console.warn('Failed to parse OAuth state:', e);
                        }
                    }

                    // Find existing user (emailHash is unique per role usually, but here we just find by emailHash)
                    // Note: If we want one user to have multiple roles, we need to change findOne logic. 
                    // For now, assuming 1 email = 1 identity regardless of role, or we update role?
                    // The schema suggests (emailHash, role) unique.
                    // If I login as 'sender' but exist as 'receiver', what happens?
                    // Let's find by emailHash AND role if we want distinct profiles, OR just find by emailHash.
                    // Current logic finds by emailHash only.
                    let user = await db.collection('users').findOne({ emailHash });

                    if (!user) {
                        const userId = uuidv4();
                        user = {
                            userId,
                            emailHash,
                            role: role,
                            loginMethod: 'email',
                            createdAt: new Date(),
                            lastLoginAt: new Date(),
                        } as any;
                        await db.collection('users').insertOne(user);
                    } else {
                        // User exists. Should we switch role if different?
                        // For now, keep existing role but verify if we want to allow switching.
                        // The auth controller handles role updates if needed, but here we just return the user.
                        await db.collection('users').updateOne(
                            { _id: user._id },
                            { $set: { lastLoginAt: new Date() } }
                        );
                    }

                    return done(null, user);
                } catch (error) {
                    return done(error as Error);
                }
            }
        )
    );

    passport.serializeUser((user: any, done) => {
        done(null, user.userId);
    });

    passport.deserializeUser(async (id: string, done) => {
        try {
            const db = getDatabase();
            const user = await db.collection('users').findOne({ userId: id });
            done(null, user);
        } catch (error) {
            done(error);
        }
    });
};
