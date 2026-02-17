import { Router } from 'express';
import { authenticate, authorize } from '../middleware/auth';
import * as fileController from '../controllers/file.controller';
import multer from 'multer';

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

// All file routes require authentication
router.use(authenticate);

/**
 * @route   POST /api/files/register (Alias for /upload)
 * @desc    Register file upload with metadata
 * @access  Private (Sender only)
 */
router.post('/register', authorize('sender', 'user'), upload.single('file'), fileController.registerFileUpload);
router.post('/upload', authorize('sender', 'user'), upload.single('file'), fileController.registerFileUpload);

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
router.post('/:fileId/revoke', authorize('sender', 'user'), fileController.revokeFile);

/**
 * @route   GET /api/files/ipfs/:cid
 * @desc    Proxy IPFS content to avoid CORS
 * @access  Private
 */
router.get('/ipfs/:cid', fileController.proxyIPFS);

export default router;
