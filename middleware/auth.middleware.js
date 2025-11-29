import jwt from 'jsonwebtoken'
import { UserModel } from '../models/user.model.js'

export const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '')
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Access denied. No token provided.' 
      })
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const user = await UserModel.findById(decoded.userId)
    
    if (!user || !user.isActive) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token or user not found.' 
      })
    }

    req.user = user
    next()
  } catch (error) {
    res.status(401).json({ 
      success: false, 
      message: 'Invalid token.' 
    })
  }
}

export const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied. Insufficient permissions.' 
      })
    }
    next()
  }
}

export const optionalAuth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '')
    
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET)
      const user = await UserModel.findById(decoded.userId)
      
      if (user && user.isActive) {
        req.user = user
      }
    }
    
    next()
  } catch (error) {
    next()
  }
}