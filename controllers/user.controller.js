import { UserModel } from '../models/user.model.js'
import { AuditLogModel } from '../models/audit.model.js'
import { TokenModel } from '../models/token.model.js'
import bcrypt from 'bcryptjs'

export class UserController {
  static async getProfile(req, res) {
    try {
      const user = await UserModel.findById(req.user.id)
      
      res.json({
        success: true,
        data: { user }
      })
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching user profile',
        error: error.message
      })
    }
  }

  static async updateProfile(req, res) {
    try {
      const { firstName, lastName, phone } = req.body
      const userId = req.user.id

      const updatedUser = await UserModel.update(userId, {
        firstName,
        lastName,
        phone
      })

      // Create audit log
      await AuditLogModel.create({
        userId,
        action: 'PROFILE_UPDATE',
        description: 'User profile updated successfully',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { updatedFields: { firstName, lastName, phone } }
      })

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: { user: updatedUser }
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error updating profile',
        error: error.message
      })
    }
  }

  static async changePassword(req, res) {
    try {
      const { currentPassword, newPassword } = req.body
      const userId = req.user.id

      // Get user with password
      const user = await UserModel.findByEmail(req.user.email)
      
      // Verify current password
      const isCurrentPasswordValid = await UserModel.verifyPassword(currentPassword, user.password)
      if (!isCurrentPasswordValid) {
        return res.status(400).json({
          success: false,
          message: 'Current password is incorrect'
        })
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 12)

      // Update password
      await UserModel.update(userId, { password: hashedPassword })

      // Revoke all refresh tokens (force logout from all devices)
      await TokenModel.revokeAllUserTokens(userId)

      // Create audit log
      await AuditLogModel.create({
        userId,
        action: 'PASSWORD_CHANGE',
        description: 'Password changed successfully',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.json({
        success: true,
        message: 'Password changed successfully. Please login again.'
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error changing password',
        error: error.message
      })
    }
  }

  static async getLoginHistory(req, res) {
    try {
      const { page = 1, limit = 10 } = req.query
      const userId = req.user.id

      const loginHistory = await AuditLogModel.getLoginHistory(
        userId, 
        parseInt(page), 
        parseInt(limit)
      )

      res.json({
        success: true,
        data: { loginHistory }
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching login history',
        error: error.message
      })
    }
  }

  static async getAuditLogs(req, res) {
    try {
      const { page = 1, limit = 10 } = req.query
      const userId = req.user.id

      const auditLogs = await AuditLogModel.findByUserId(
        userId, 
        parseInt(page), 
        parseInt(limit)
      )

      res.json({
        success: true,
        data: { auditLogs }
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching audit logs',
        error: error.message
      })
    }
  }

  static async deactivateAccount(req, res) {
    try {
      const userId = req.user.id

      await UserModel.update(userId, { isActive: false })

      // Revoke all tokens
      await TokenModel.revokeAllUserTokens(userId)

      // Create audit log
      await AuditLogModel.create({
        userId,
        action: 'ACCOUNT_DEACTIVATION',
        description: 'Account deactivated by user',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      })

      res.json({
        success: true,
        message: 'Account deactivated successfully'
      })

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error deactivating account',
        error: error.message
      })
    }
  }
}