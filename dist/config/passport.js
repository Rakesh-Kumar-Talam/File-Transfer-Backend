"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initPassport = void 0;
const passport_1 = __importDefault(require("passport"));
const passport_google_oauth20_1 = require("passport-google-oauth20");
const database_1 = require("./database");
const crypto_1 = require("../utils/crypto");
const uuid_1 = require("uuid");
const initPassport = () => {
    passport_1.default.use(new passport_google_oauth20_1.Strategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        passReqToCallback: true,
    }, async (req, accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails?.[0].value;
            if (!email) {
                return done(new Error('No email found in Google profile'));
            }
            const emailHash = (0, crypto_1.hashEmail)(email);
            const db = (0, database_1.getDatabase)();
            // Attempt to parse role from state parameter
            let role = 'receiver'; // Default
            if (req.query && req.query.state) {
                try {
                    const stateJson = Buffer.from(req.query.state, 'base64').toString();
                    const state = JSON.parse(stateJson);
                    if (state.role && ['sender', 'receiver', 'admin'].includes(state.role)) {
                        role = state.role;
                    }
                }
                catch (e) {
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
                const userId = (0, uuid_1.v4)();
                user = {
                    userId,
                    emailHash,
                    role: role,
                    loginMethod: 'email',
                    createdAt: new Date(),
                    lastLoginAt: new Date(),
                };
                await db.collection('users').insertOne(user);
            }
            else {
                // User exists. Should we switch role if different?
                // For now, keep existing role but verify if we want to allow switching.
                // The auth controller handles role updates if needed, but here we just return the user.
                await db.collection('users').updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date() } });
            }
            return done(null, user);
        }
        catch (error) {
            return done(error);
        }
    }));
    passport_1.default.serializeUser((user, done) => {
        done(null, user.userId);
    });
    passport_1.default.deserializeUser(async (id, done) => {
        try {
            const db = (0, database_1.getDatabase)();
            const user = await db.collection('users').findOne({ userId: id });
            done(null, user);
        }
        catch (error) {
            done(error);
        }
    });
};
exports.initPassport = initPassport;
//# sourceMappingURL=passport.js.map