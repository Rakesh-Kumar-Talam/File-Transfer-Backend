// Server initialization
import dotenv from 'dotenv';
dotenv.config();

import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { connectDatabase } from './config/database';
import { initRedis } from './config/redis';
import authRoutes from './routes/auth.routes';
import fileRoutes from './routes/file.routes';
import adminRoutes from './routes/admin.routes';
import { errorHandler } from './middleware/errorHandler';
import { rateLimiter } from './middleware/rateLimiter';
import passport from 'passport';
import { initPassport } from './config/passport';
import { initEventListener } from './utils/eventListener';

const app: Application = express();
const PORT = process.env.PORT || 5000;

// Enable trust proxy for Render load balancers
app.set('trust proxy', 1);

// Diagnostic route - Visit this URL in your browser to verify backend is up
app.get('/', (req: Request, res: Response) => {
    res.json({ message: "SecureTransfer API is alive", version: "1.0.0" });
});

// Request logger
app.use((req: Request, res: Response, next: NextFunction) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// CORS configuration
const allowedOrigins = [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    process.env.CORS_ORIGIN
].filter(Boolean) as string[];

app.use(cors({
    origin: (origin, callback) => {
        console.log(`[CORS DEBUG] Incoming origin: ${origin}`);
        callback(null, true); // Allow all during debug
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Initialize Passport
initPassport();
app.use(passport.initialize());

// Rate limiting
// app.use(rateLimiter);

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/admin', adminRoutes);

// 404 handler
app.use((req: Request, res: Response) => {
    res.status(404).json({
        success: false,
        message: 'Route not found',
    });
});

// Error handling middleware (must be last)
app.use(errorHandler);

// Initialize database and start server
const startServer = async () => {
    try {
        // Connect to database
        await connectDatabase();
        console.log('✅ Database connected');

        // Initialize Redis
        const redisStatus = await initRedis();
        if (redisStatus) {
            console.log('✅ Redis connected');
        } else {
            console.log('⚠️ Server starting without Redis (rate limiting may be restricted)');
        }

        // Initialize Blockchain Listener
        initEventListener();

        // Start server
        app.listen(Number(PORT), '0.0.0.0', () => {
            console.log(`🚀 Server running on port ${PORT} (0.0.0.0)`);
            console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔗 CORS enabled for: ${process.env.CORS_ORIGIN}`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing HTTP server');
    process.exit(0);
});

// Unhandled rejections and exceptions
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

// Start the server
startServer();

export default app;
