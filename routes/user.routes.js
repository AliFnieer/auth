import express from 'express'
import { UserController } from '../controllers/user.controller.js'
import { authenticate } from '../middleware/auth.middleware.js'
import { validateUpdateProfile } from '../middleware/validation.middleware.js'

const router = express.Router()

// All routes require authentication
router.use(authenticate)

// User profile routes
router.get('/profile', UserController.getProfile)
router.put('/profile', validateUpdateProfile, UserController.updateProfile)

// Security routes
router.put('/change-password', UserController.changePassword)
router.get('/login-history', UserController.getLoginHistory)
router.get('/audit-logs', UserController.getAuditLogs)

// Account management
router.post('/deactivate', UserController.deactivateAccount)

export default router