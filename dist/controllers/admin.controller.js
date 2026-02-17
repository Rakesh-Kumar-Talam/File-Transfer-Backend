"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.freezeUser = exports.getAdminDownloadToken = exports.emergencyRevoke = exports.updateFilePolicy = exports.getFiles = exports.toggleUserFreeze = exports.getUsers = exports.getAuditLogs = exports.getAdminStats = void 0;
const database_1 = require("../config/database");
const errorHandler_1 = require("../middleware/errorHandler");
const auth_1 = require("../middleware/auth");
const auditLogger_1 = require("../utils/auditLogger");
/**
 * Get system-wide dashboard stats for admin
 */
exports.getAdminStats = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const db = (0, database_1.getDatabase)();
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
exports.getAuditLogs = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { type, limit = 50, skip = 0 } = req.query;
    const db = (0, database_1.getDatabase)();
    const query = {};
    if (type)
        query.targetType = type;
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
exports.getUsers = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const db = (0, database_1.getDatabase)();
    const users = await db.collection('users')
        .find()
        .sort({ createdAt: -1 })
        .toArray();
    res.json({ success: true, users });
});
/**
 * Toggle user freeze status
 */
exports.toggleUserFreeze = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { userId } = req.params;
    const { freeze } = req.body; // boolean
    const db = (0, database_1.getDatabase)();
    const admin = req.user;
    const user = await db.collection('users').findOne({ userId });
    if (!user)
        throw new errorHandler_1.AppError('User not found', 404);
    const status = freeze ? 'frozen' : 'active';
    await db.collection('users').updateOne({ userId }, { $set: { status, updatedAt: new Date() } });
    await (0, auditLogger_1.logEvent)({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: freeze ? 'USER_FREEZE' : 'USER_UNFREEZE',
        targetType: 'user',
        targetId: userId,
        metadata: { previousStatus: user.status, newStatus: status },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        status: 'success'
    });
    res.json({ success: true, message: `User account has been ${freeze ? 'frozen' : 'activated'}` });
});
/**
 * Get all files
 */
exports.getFiles = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const db = (0, database_1.getDatabase)();
    const files = await db.collection('files')
        .find()
        .sort({ createdAt: -1 })
        .toArray();
    res.json({ success: true, files });
});
/**
 * Update file policy (Admin)
 */
exports.updateFilePolicy = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { fileId } = req.params;
    const { maxAccess, expiryDays } = req.body;
    const db = (0, database_1.getDatabase)();
    const admin = req.user;
    const file = await db.collection('files').findOne({ fileId });
    if (!file)
        throw new errorHandler_1.AppError('File not found', 404);
    const update = {};
    if (maxAccess !== undefined)
        update['policy.maxAccess'] = Number(maxAccess);
    if (expiryDays !== undefined) {
        update['policy.expiryTimestamp'] = Date.now() + (Number(expiryDays) * 24 * 60 * 60 * 1000);
    }
    await db.collection('files').updateOne({ fileId }, { $set: update });
    await (0, auditLogger_1.logEvent)({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: 'FILE_POLICY_UPDATE',
        targetType: 'file',
        targetId: fileId,
        metadata: { oldPolicy: file.policy, updates: update },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        status: 'success'
    });
    res.json({ success: true, message: 'File policy updated successfully' });
});
/**
 * Emergency revoke a file (System Admin)
 */
exports.emergencyRevoke = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { fileId } = req.params;
    const db = (0, database_1.getDatabase)();
    const admin = req.user;
    const file = await db.collection('files').findOne({ fileId });
    if (!file)
        throw new errorHandler_1.AppError('File not found', 404);
    await db.collection('files').updateOne({ fileId }, { $set: { status: 'revoked', revokedAt: new Date(), revokedBy: 'ADMIN' } });
    await (0, auditLogger_1.logEvent)({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: 'FILE_EMERGENCY_REVOKE',
        targetType: 'file',
        targetId: fileId,
        metadata: { previousStatus: file.status },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        status: 'success'
    });
    res.json({ success: true, message: 'File has been emergency revoked' });
});
/**
 * Superuser: Generate download token for auditing any file
 */
exports.getAdminDownloadToken = (0, errorHandler_1.asyncHandler)(async (req, res) => {
    const { fileId } = req.params;
    const db = (0, database_1.getDatabase)();
    const admin = req.user;
    const file = await db.collection('files').findOne({ fileId });
    if (!file)
        throw new errorHandler_1.AppError('File not found', 404);
    // Generate a superuser token (linked to admin identity)
    const downloadToken = (0, auth_1.generateDownloadToken)(fileId, `ADMIN-${admin.userId}`);
    await (0, auditLogger_1.logEvent)({
        actorId: admin.userId,
        actorRole: 'admin',
        actorType: 'admin',
        actionType: 'ADMIN_AUDIT_DOWNLOAD',
        targetType: 'file',
        targetId: fileId,
        metadata: { fileName: file.name },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
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
exports.freezeUser = exports.toggleUserFreeze; // For backward compatibility with existing route if needed
//# sourceMappingURL=admin.controller.js.map