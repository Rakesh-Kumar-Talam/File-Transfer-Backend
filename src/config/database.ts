import { MongoClient, Db } from 'mongodb';
import { setServers } from 'node:dns/promises';

// Fix for Node.js 22+ SRV resolution issues on Windows
try {
    setServers(['8.8.8.8', '8.8.4.4']);
} catch (e) {
    console.warn('Failed to set custom DNS servers, SRV resolution might fail.');
}

let db: Db | null = null;
let client: MongoClient | null = null;

export const connectDatabase = async (): Promise<Db> => {
    try {
        const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-file-transfer';

        // Atlas +srv handles TLS/SSL automatically. 
        // We only force it for standard mongodb:// in production.
        const options: any = {
            connectTimeoutMS: 30000,
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            heartbeatFrequencyMS: 10000,
            retryWrites: true
        };

        if (!uri.startsWith('mongodb+srv') && process.env.NODE_ENV === 'production') {
            options.tls = true;
        }

        client = new MongoClient(uri, options);
        console.log(`📡 Attempting to connect to: ${uri.replace(/:([^@]+)@/, ':****@')}`);
        await client.connect();

        db = client.db();
        console.log('✅ MongoDB connection successful');

        // Create indexes for performance
        await createIndexes();

        return db;
    } catch (error: any) {
        console.error('❌ Database connection error details:');
        console.error('Message:', error.message);
        if (error.reason) console.error('Reason:', JSON.stringify(error.reason, null, 2));
        throw error;
    }
};

export const getDatabase = (): Db => {
    if (!db) {
        throw new Error('Database not initialized. Call connectDatabase first.');
    }
    return db;
};

export const closeDatabase = async (): Promise<void> => {
    if (client) {
        await client.close();
        db = null;
        client = null;
    }
};

const createIndexes = async (): Promise<void> => {
    if (!db) return;

    try {
        // Users collection indexes - Support (address/email, role) uniqueness

        // 1. Drop old indexes if they exist to apply new partial filter
        try { await db.collection('users').dropIndex('walletAddress_1_role_1'); } catch (e) { /* ignore if not exists */ }
        try { await db.collection('users').dropIndex('emailHash_1_role_1'); } catch (e) { /* ignore if not exists */ }

        // 2. Create optimized indexes with partial filters (ignore nulls completely)
        await db.collection('users').createIndex(
            { walletAddress: 1, role: 1 },
            {
                unique: true,
                partialFilterExpression: { walletAddress: { $type: 'string' } }
            }
        );

        await db.collection('users').createIndex(
            { emailHash: 1, role: 1 },
            {
                unique: true,
                partialFilterExpression: { emailHash: { $type: 'string' } }
            }
        );

        await db.collection('users').createIndex({ userId: 1 }, { unique: true });

        // Files collection indexes
        await db.collection('files').createIndex({ fileId: 1 }, { unique: true });
        await db.collection('files').createIndex({ sender: 1 });
        await db.collection('files').createIndex({ 'wrappedKeys.receiverAddress': 1 }); // Fixed field name
        await db.collection('files').createIndex({ createdAt: -1 });
        await db.collection('files').createIndex({ 'policy.expiryTimestamp': 1 }); // Fixed nesting

        // Access logs collection indexes
        await db.collection('accessLogs').createIndex({ fileId: 1 });
        await db.collection('accessLogs').createIndex({ receiver: 1 });
        await db.collection('accessLogs').createIndex({ timestamp: -1 });

        // Sessions collection indexes
        await db.collection('sessions').createIndex({ sessionId: 1 }, { unique: true });
        await db.collection('sessions').createIndex({ userId: 1 });
        await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

        console.log('✅ Database indexes created');
    } catch (error) {
        console.error('Error creating indexes:', error);
    }
};
