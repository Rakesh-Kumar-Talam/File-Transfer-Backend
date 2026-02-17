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
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const adminController = __importStar(require("../controllers/admin.controller"));
const router = (0, express_1.Router)();
// All admin routes require admin authentication
router.use(auth_1.authenticate);
router.use(auth_1.adminOnly);
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
exports.default = router;
//# sourceMappingURL=admin.routes.js.map