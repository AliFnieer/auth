import jwt from 'jsonwebtoken'
import { UserModel } from '../models/user.model.js'
import { TokenModel } from '../models/token.model.js'
import { AuditLogModel } from '../models/audit.model.js'

export class AuthController {
  static generateAccessToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { 
      expiresIn: process.env.JWT_EXPIRES_IN || '15m' 
    })
  }

  static async register(req, res) {
    try {
      const { email, password, firstName, lastName, phone } = req.body

      // Check if user exists
      const existingUser = await UserModel.findByEmail(email)
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User already exists with this email.'
        })
      }

      // Create user
      const user = await UserModel.create({
        email,
        password,
        firstName,
        lastName,
        phone
      })

      // Generate verification token
      const verificationToken = await TokenModel.createVerificationToken(user.id)

      // TODO: Send verification email
      // await EmailService.sendVerificationEmail(user.email, verificationToken.token)

      // Create audit log
      await AuditLogModel.create({
        userId: user.id,
        action: 'REGISTER',
        description: 'User registered successfully',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.status(201).json({
        success: true,
        message: 'User registered successfully. Please check your email for verification.',
        data: { user }
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error creating user',
        error: error.message
      })
    }
  }

  static async login(req, res) {
    try {
      const { email, password } = req.body

      // Find user
      const user = await UserModel.findByEmail(email)
      if (!user || !user.isActive) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        })
      }

      // Verify password
      const isPasswordValid = await UserModel.verifyPassword(password, user.password)
      if (!isPasswordValid) {
        // Log failed login attempt
        await AuditLogModel.create({
          userId: user.id,
          action: 'LOGIN',
          description: 'Failed login attempt - invalid password',
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          success: false
        })

        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        })
      }

      // Check if email is verified
      if (!user.isVerified) {
        return res.status(403).json({
          success: false,
          message: 'Please verify your email before logging in.'
        })
      }

      // Generate tokens
      const accessToken = this.generateAccessToken(user.id)
      const refreshToken = await TokenModel.createRefreshToken(
        user.id, 
        req.get('User-Agent'), 
        req.ip
      )

      // Update last login
      await UserModel.update(user.id, { lastLoginAt: new Date() })

      // Create audit log
      await AuditLogModel.create({
        userId: user.id,
        action: 'LOGIN',
        description: 'User logged in successfully',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            isVerified: user.isVerified
          },
          tokens: {
            accessToken,
            refreshToken: refreshToken.token,
            expiresIn: process.env.JWT_EXPIRES_IN || '15m'
          }
        }
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error during login',
        error: error.message
      })
    }
  }

  static async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          message: 'Refresh token is required'
        })
      }

      const tokenData = await TokenModel.findRefreshToken(refreshToken)
      if (!tokenData) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired refresh token'
        })
      }

      const accessToken = this.generateAccessToken(tokenData.userId)

      res.json({
        success: true,
        data: {
          accessToken,
          refreshToken: tokenData.token
        }
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error refreshing token',
        error: error.message
      })
    }
  }

  static async logout(req, res) {
    try {
      const { refreshToken } = req.body
      const userId = req.user.id

      if (refreshToken) {
        await TokenModel.revokeRefreshToken(refreshToken)
      }

      // Create audit log
      await AuditLogModel.create({
        userId,
        action: 'LOGOUT',
        description: 'User logged out successfully',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.json({
        success: true,
        message: 'Logged out successfully'
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error during logout',
        error: error.message
      })
    }
  }

  static async verifyEmail(req, res) {
    try {
      const { token } = req.params

      const verificationToken = await TokenModel.findVerificationToken(token)
      if (!verificationToken) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired verification token'
        })
      }

      // Verify user
      await UserModel.update(verificationToken.userId, { isVerified: true })
      
      // Delete verification token
      await TokenModel.deleteVerificationToken(token)

      // Create audit log
      await AuditLogModel.create({
        userId: verificationToken.userId,
        action: 'EMAIL_VERIFICATION',
        description: 'Email verified successfully',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.json({
        success: true,
        message: 'Email verified successfully'
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error verifying email',
        error: error.message
      })
    }
  }

  static async requestPasswordReset(req, res) {
    try {
      const { email } = req.body

      const user = await UserModel.findByEmail(email)
      if (!user) {
        // Don't reveal if user exists or not
        return res.json({
          success: true,
          message: 'If the email exists, a password reset link has been sent.'
        })
      }

      const resetToken = await TokenModel.createPasswordResetToken(user.id)

      // TODO: Send password reset email
      // await EmailService.sendPasswordResetEmail(user.email, resetToken.token)

      // Create audit log
      await AuditLogModel.create({
        userId: user.id,
        action: 'PASSWORD_RESET_REQUEST',
        description: 'Password reset requested',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.json({
        success: true,
        message: 'If the email exists, a password reset link has been sent.'
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error requesting password reset',
        error: error.message
      })
    }
  }

  static async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body

      const resetToken = await TokenModel.findPasswordResetToken(token)
      if (!resetToken) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token'
        })
      }

      // Update password
      const hashedPassword = await bcrypt.hash(newPassword, 12)
      await UserModel.update(resetToken.userId, { password: hashedPassword })

      // Mark token as used
      await TokenModel.markPasswordResetTokenUsed(token)

      // Revoke all refresh tokens
      await TokenModel.revokeAllUserTokens(resetToken.userId)

      // Create audit log
      await AuditLogModel.create({
        userId: resetToken.userId,
        action: 'PASSWORD_RESET',
        description: 'Password reset successfully',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.json({
        success: true,
        message: 'Password reset successfully'
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error resetting password',
        error: error.message
      })
    }
  }
}