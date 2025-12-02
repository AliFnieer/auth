import express from 'express'
import { AuthController } from '../controllers/auth.controller.js'
import { 
  validateRegister, 
  validateLogin, 
  validatePasswordReset 
} from '../middleware/validation.middleware.js'
import { authenticate } from '../middleware/auth.middleware.js'
import rateLimit from 'express-rate-limit'

const router = express.Router()

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // more restrictive for auth endpoints
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
})

// Public routes
router.post('/register', authLimiter, validateRegister, AuthController.register)
router.post('/login', authLimiter, validateLogin, AuthController.login)
router.post('/refresh-token', authLimiter, AuthController.refreshToken)
router.post('/verify-email/:token', AuthController.verifyEmail)
router.post('/forgot-password', authLimiter, AuthController.requestPasswordReset)
router.post('/reset-password', authLimiter, validatePasswordReset, AuthController.resetPassword)

// Protected routes
router.post('/logout', authenticate, AuthController.logout)

export default router