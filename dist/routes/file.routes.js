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
const auth_1 = require("../middleware/auth");
const fileController = __importStar(require("../controllers/file.controller"));
const multer_1 = __importDefault(require("multer"));
const router = (0, express_1.Router)();
const upload = (0, multer_1.default)({ storage: multer_1.default.memoryStorage() });
// All file routes require authentication
router.use(auth_1.authenticate);
/**
 * @route   POST /api/files/register (Alias for /upload)
 * @desc    Register file upload with metadata
 * @access  Private (Sender only)
 */
router.post('/register', (0, auth_1.authorize)('sender', 'user'), upload.single('file'), fileController.registerFileUpload);
router.post('/upload', (0, auth_1.authorize)('sender', 'user'), upload.single('file'), fileController.registerFileUpload);
/**
 * @route   GET /api/files/my-files
 * @desc    Get user's files (sent or received)
 * @access  Private
 */
router.get('/my-files', fileController.getMyFiles);
router.get('/', fileController.getMyFiles);
/**
 * @route   POST /api/files/:fileId/access
 * @desc    Request download access token
 * @access  Private
 */
router.post('/:fileId/access', fileController.requestDownloadToken);
/**
 * @route   POST /api/files/:fileId/revoke
 * @desc    Revoke file access
 * @access  Private (Sender only)
 */
router.post('/:fileId/revoke', (0, auth_1.authorize)('sender', 'user'), fileController.revokeFile);
/**
 * @route   GET /api/files/ipfs/:cid
 * @desc    Proxy IPFS content to avoid CORS
 * @access  Private
 */
router.get('/ipfs/:cid', fileController.proxyIPFS);
exports.default = router;
//# sourceMappingURL=file.routes.js.map