import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import csrf from 'csrf'
import cookieParser from 'cookie-parser'
import routes from './routes/index.js'
import prisma from './lib/prisma.js'
import { errorHandler, notFound } from './middleware/error.middleware.js'

const app = express()
const tokens = new csrf()

// Load environment variables
dotenv.config()

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}))

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}))

// Body parsing middleware
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))
app.use(cookieParser())

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
})
app.use(generalLimiter)

app.use((req, res, next) => {
  if (!req.cookies._csrfSecret) {
    const secret = tokens.secretSync()
    res.cookie('_csrfSecret', secret, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production'
    })
  }
  next()
})

app.get('/api/csrf-token', (req, res) => {
  const secret = req.cookies._csrfSecret
  const token = tokens.create(secret)
  res.json({ csrfToken: token })
})


app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const secret = req.cookies._csrfSecret
    const token = req.body._csrf || req.headers['x-csrf-token']
    try {
      if (!token || !tokens.verify(secret, token)) {
        return res.status(403).json({ success: false, message: 'Invalid CSRF token' })
      }
    } catch (err) {
      console.error('CSRF verification error:', err)
      return res.status(403).json({ success: false, message: 'Invalid CSRF token' })
    }
  }
  next()
})

// Routes
app.use('/api', routes)

// Error handling
app.use(notFound)
app.use(errorHandler)

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log(`🚀 Auth system server running on port ${PORT}`)
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`)
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Configured' : 'Not configured'}`)

  prisma.$connect()
    .then(() => console.log('✅ Database connected successfully'))
    .catch((e) => console.error('❌ Database connection error:', e))
})