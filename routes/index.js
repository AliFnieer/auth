import express from 'express'
import authRoutes from './auth.routes.js'
import userRoutes from './user.routes.js'

const router = express.Router()

// API routes
router.use('/auth', authRoutes)
router.use('/users', userRoutes)

// API health check
router.get('/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Auth API is running', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  })
})

export default router