export const errorHandler = (error, req, res, next) => {
  console.error('Error:', error)

  // Prisma errors
  if (error.code === 'P2002') {
    return res.status(409).json({
      success: false,
      message: 'A record with this already exists',
      field: error.meta?.target?.[0]
    })
  }

  if (error.code === 'P2025') {
    return res.status(404).json({
      success: false,
      message: 'Record not found'
    })
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    })
  }

  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired'
    })
  }

  // Default error
  const statusCode = error.statusCode || 500
  const message = error.message || 'Internal server error'

  res.status(statusCode).json({
    success: false,
    message,
    error: process.env.NODE_ENV === 'development' ? {
      stack: error.stack,
      details: error
    } : undefined
  })
}

export const notFound = (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  })
}