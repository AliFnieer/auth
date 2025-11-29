import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import helmet from 'helmet' // Import helmet
import rateLimit from 'express-rate-limit'
import routes from './routes/index.js'
import prisma from './lib/prisma.js' // Import prisma client
import { errorHandler, notFound } from './middleware/error.middleware.js'

const app = express()

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

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
})
app.use(generalLimiter)

// Routes
app.use('/api', routes)

// Error handling
app.use(notFound)
app.use(errorHandler)

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log(`🚀 Auth system server running on port ${PORT}`)
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`)
  // Check if DATABASE_URL is set, but don't log the URL itself for security
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Configured' : 'Not configured'}`) 

  // Connect to Prisma
  prisma.$connect()
    .then(() => console.log('✅ Database connected successfully'))
    .catch((e) => console.error('❌ Database connection error:', e))
})