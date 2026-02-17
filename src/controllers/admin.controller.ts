import { Request, Response } from 'express';
import { getDatabase } from '../config/database';
import { AppError, asyncHandler } from '../middleware/errorHandler';
import { generateDownloadToken } from '../middleware/auth';
import { logEvent } from '../utils/auditLogger';

/**
 * Get system-wide dashboard stats for admin
 */
export const getAdminStats = asyncHandler(async (req: Request, res: Response) => {
    const db = getDatabase();

    const totalUsers = await db.collection('users').countDocuments({ role: 'user' });
    const totalAdmins = await db.collection('users').countDocuments({ role: 'admin' });
    const totalFiles = await db.collection('files').countDocuments();

    // Get total downloads from aggregation of usedAccess
    const downloadStats = await db.collection('files').aggregate([
        { $group: { _id: null, total: { $sum: "$policy.usedAccess" } } }
    ]).toArray();

    const activeFiles = await db.collection('files').countDocuments({ status: 'active' });
    const revokedFiles = await db.collection('files').countDocuments({ status: 'revoked' });

    // Last 24h failed logins
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const failedLogins = await db.collection('audit_logs').countDocuments({
        actionType: 'LOGIN_FAILURE',
        createdAt: { $gt: last24h }
    });

    res.json({
        success: true,
        stats: {
            totalUsers,
            totalAdmins,
            totalFiles,
            totalDownloads: downloadStats[0]?.total || 0,
            activeFiles,
            revokedFiles,
            failedLogins24h: failedLogins
        }
    });
});

/**
 * Get audit logs across the system
 */
export const getAuditLogs = asyncHandler(async (req: Request, res: Response) => {
    const { type, limit = 50, skip = 0 } = req.query;
    const db = getDatabase();

    const query: any = {};
    if (type) query.targetType = type;

    const logs = await db.collection('audit_logs')
        .find(query)
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .skip(Number(skip))
        .toArray();

    const total = await db.collection('audit_logs').countDocuments(query);

    res.json({ success: true, logs, total });
});

/**
 * Get all users
 */
export const getUsers = asyncHandler(async (req: Request, res: Response) => {
    const db = getDatabase();
    const users = await db.collection('users')
        .find()
        .sort({ createdAt: -1 })
        .toArray();

    res.json({ success: true, users });
});

/**
 * Toggle user freeze status
 */
export const toggleUserFreeze = asyncHandler(async (req: Request, res: Response) => {
    const { userId } = req.params;
    const { freeze } = req.body; // boolean
    const db = getDatabase();
    const admin = req.user!;

    const user = await db.collection('users').findOne({ userId });
    if (!user) throw new AppError('User not found', 404);

    const status = freeze ? 'frozen' : 'active';

    await db.collection('users').updateOne(
        { userId },
        { $set: { status, updatedAt: new Date() } }
    );

    await logEvent({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: freeze ? 'USER_FREEZE' : 'USER_UNFREEZE',
        targetType: 'user',
        targetId: userId as string,
        metadata: { previousStatus: user.status, newStatus: status },
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || '',
        status: 'success'
    });

    res.json({ success: true, message: `User account has been ${freeze ? 'frozen' : 'activated'}` });
});

/**
 * Get all files
 */
export const getFiles = asyncHandler(async (req: Request, res: Response) => {
    const db = getDatabase();
    const files = await db.collection('files')
        .find()
        .sort({ createdAt: -1 })
        .toArray();

    res.json({ success: true, files });
});

/**
 * Update file policy (Admin)
 */
export const updateFilePolicy = asyncHandler(async (req: Request, res: Response) => {
    const { fileId } = req.params;
    const { maxAccess, expiryDays } = req.body;
    const db = getDatabase();
    const admin = req.user!;

    const file = await db.collection('files').findOne({ fileId });
    if (!file) throw new AppError('File not found', 404);

    const update: any = {};
    if (maxAccess !== undefined) update['policy.maxAccess'] = Number(maxAccess);
    if (expiryDays !== undefined) {
        update['policy.expiryTimestamp'] = Date.now() + (Number(expiryDays) * 24 * 60 * 60 * 1000);
    }

    await db.collection('files').updateOne({ fileId }, { $set: update });

    await logEvent({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: 'FILE_POLICY_UPDATE',
        targetType: 'file',
        targetId: fileId as string,
        metadata: { oldPolicy: file.policy, updates: update },
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || '',
        status: 'success'
    });

    res.json({ success: true, message: 'File policy updated successfully' });
});

/**
 * Emergency revoke a file (System Admin)
 */
export const emergencyRevoke = asyncHandler(async (req: Request, res: Response) => {
    const { fileId } = req.params;
    const db = getDatabase();
    const admin = req.user!;

    const file = await db.collection('files').findOne({ fileId });
    if (!file) throw new AppError('File not found', 404);

    await db.collection('files').updateOne(
        { fileId },
        { $set: { status: 'revoked', revokedAt: new Date(), revokedBy: 'ADMIN' } }
    );

    await logEvent({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: 'FILE_EMERGENCY_REVOKE',
        targetType: 'file',
        targetId: fileId as string,
        metadata: { previousStatus: file.status },
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || '',
        status: 'success'
    });

    res.json({ success: true, message: 'File has been emergency revoked' });
});

/**
 * Superuser: Generate download token for auditing any file
 */
export const getAdminDownloadToken = asyncHandler(async (req: Request, res: Response) => {
    const { fileId } = req.params;
    const db = getDatabase();
    const admin = req.user!;

    const file = await db.collection('files').findOne({ fileId });
    if (!file) throw new AppError('File not found', 404);

    // Generate a superuser token (linked to admin identity)
    const downloadToken = generateDownloadToken(fileId as string, `ADMIN-${admin.userId}`);

    await logEvent({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: 'ADMIN_AUDIT_DOWNLOAD',
        targetType: 'file',
        targetId: fileId as string,
        metadata: { fileName: file.name },
        ipAddress: req.ip,
        userAgent: (req.headers['user-agent'] as string) || '',
        status: 'success'
    });

    res.json({
        success: true,
        downloadToken,
        ipfsCID: file.ipfsCID,
        wrappedKeys: file.wrappedKeys, // Give all wrapped keys so admin can see who it was for
        ivs: file.ivs
    });
});

export const freezeUser = toggleUserFreeze; // For backward compatibility with existing route if needed
