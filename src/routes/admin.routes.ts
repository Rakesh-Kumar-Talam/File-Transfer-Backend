import { Router } from 'express';
import { authenticate, adminOnly } from '../middleware/auth';
import * as adminController from '../controllers/admin.controller';

const router = Router();

// All admin routes require admin authentication
router.use(authenticate);
router.use(adminOnly);

/**
 * @route   GET /api/admin/dashboard
 */
router.get('/dashboard', adminController.getAdminStats);

/**
 * @route   GET /api/admin/audit-logs
 * @desc    Get system audit logs (with optional type filtering)
 */
router.get('/audit-logs', adminController.getAuditLogs);

/**
 * @route   GET /api/admin/users
 */
router.get('/users', adminController.getUsers);

/**
 * @route   PATCH /api/admin/users/:userId/toggle-freeze
 */
router.patch('/users/:userId/toggle-freeze', adminController.toggleUserFreeze);

/**
 * @route   GET /api/admin/files
 */
router.get('/files', adminController.getFiles);

/**
 * @route   PATCH /api/admin/files/:fileId/policy
 */
router.patch('/files/:fileId/policy', adminController.updateFilePolicy);

/**
 * @route   POST /api/admin/files/:fileId/revoke
 */
router.post('/files/:fileId/revoke', adminController.emergencyRevoke);

/**
 * @route   GET /api/admin/files/:fileId/audit-access
 * @desc    Get access token for auditing encrypted blobs (Admins only)
 */
router.get('/files/:fileId/audit-access', adminController.getAdminDownloadToken);

export default router;
