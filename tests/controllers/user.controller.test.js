import { jest } from '@jest/globals'

// Mock dependencies before importing controller
await jest.unstable_mockModule('../../models/user.model.js', () => ({ UserModel: {
  findById: jest.fn(),
  update: jest.fn(),
  findByEmail: jest.fn(),
  verifyPassword: jest.fn()
}}))

await jest.unstable_mockModule('../../models/audit.model.js', () => ({ AuditLogModel: {
  create: jest.fn(),
  getLoginHistory: jest.fn()
}}))

await jest.unstable_mockModule('../../models/token.model.js', () => ({ TokenModel: {
  revokeAllUserTokens: jest.fn()
}}))

await jest.unstable_mockModule('bcryptjs', () => {
  const hash = jest.fn()
  const compare = jest.fn()
  return { default: { hash, compare }, hash, compare }
})

// Import modules after mocks
const { UserController } = await import('../../controllers/user.controller.js')
const { UserModel } = await import('../../models/user.model.js')
const { AuditLogModel } = await import('../../models/audit.model.js')
const { TokenModel } = await import('../../models/token.model.js')
const bcrypt = await import('bcryptjs')

describe('UserController', () => {
  let mockReq, mockRes

  beforeEach(() => {
    jest.clearAllMocks()
    
    mockReq = {
      user: {},
      body: {},
      query: {},
      ip: '127.0.0.1',
      get: jest.fn()
    }
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    }
    
    mockReq.get.mockReturnValue('TestAgent/1.0')
  })

  describe('getProfile', () => {
    it('should return user profile', async () => {
      const userId = 'user-123'
      const user = {
        id: userId,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe'
      }

      mockReq.user = { id: userId }
      UserModel.findById.mockResolvedValue(user)

      await UserController.getProfile(mockReq, mockRes)

      expect(UserModel.findById).toHaveBeenCalledWith(userId)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data: { user }
      })
    })

    it('should handle errors', async () => {
      const error = new Error('Database error')
      mockReq.user = { id: 'user-123' }
      
      UserModel.findById.mockRejectedValue(error)

      await UserController.getProfile(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(500)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Error fetching user profile',
        error: error.message
      })
    })
  })

  describe('updateProfile', () => {
    it('should update profile successfully', async () => {
      const userId = 'user-123'
      const updateData = {
        firstName: 'John',
        lastName: 'Doe',
        phone: '1234567890'
      }

      const updatedUser = {
        id: userId,
        email: 'test@example.com',
        ...updateData
      }

      mockReq.user = { id: userId }
      mockReq.body = updateData

      UserModel.update.mockResolvedValue(updatedUser)
      AuditLogModel.create.mockResolvedValue()

      await UserController.updateProfile(mockReq, mockRes)

      expect(UserModel.update).toHaveBeenCalledWith(userId, updateData)
      expect(AuditLogModel.create).toHaveBeenCalledWith({
        userId,
        action: 'PROFILE_UPDATE',
        description: 'User profile updated successfully',
        ipAddress: mockReq.ip,
        userAgent: mockReq.get('User-Agent'),
        metadata: { updatedFields: updateData }
      })
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: 'Profile updated successfully',
        data: { user: updatedUser }
      })
    })
  })

  describe('changePassword', () => {
    it('should change password successfully', async () => {
      const userId = 'user-123'
      const email = 'test@example.com'
      const passwordData = {
        currentPassword: 'old_password',
        newPassword: 'new_password'
      }

      const user = {
        id: userId,
        email,
        password: 'hashed_old_password'
      }

      const hashedNewPassword = 'hashed_new_password'

      mockReq.user = { id: userId, email }
      mockReq.body = passwordData

      UserModel.findByEmail.mockResolvedValue(user)
      UserModel.verifyPassword.mockResolvedValue(true)
      bcrypt.hash.mockResolvedValue(hashedNewPassword)
      UserModel.update.mockResolvedValue()
      TokenModel.revokeAllUserTokens.mockResolvedValue()
      AuditLogModel.create.mockResolvedValue()

      await UserController.changePassword(mockReq, mockRes)

      expect(UserModel.findByEmail).toHaveBeenCalledWith(email)
      expect(UserModel.verifyPassword).toHaveBeenCalledWith(
        passwordData.currentPassword,
        user.password
      )
      expect(bcrypt.hash).toHaveBeenCalledWith(passwordData.newPassword, 12)
      expect(UserModel.update).toHaveBeenCalledWith(userId, { password: hashedNewPassword })
      expect(TokenModel.revokeAllUserTokens).toHaveBeenCalledWith(userId)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: 'Password changed successfully. Please login again.'
      })
    })

    it('should reject incorrect current password', async () => {
      const userId = 'user-123'
      const email = 'test@example.com'
      const passwordData = {
        currentPassword: 'wrong_password',
        newPassword: 'new_password'
      }

      const user = {
        id: userId,
        email,
        password: 'hashed_password'
      }

      mockReq.user = { id: userId, email }
      mockReq.body = passwordData

      UserModel.findByEmail.mockResolvedValue(user)
      UserModel.verifyPassword.mockResolvedValue(false)

      await UserController.changePassword(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Current password is incorrect'
      })
    })
  })

  describe('getLoginHistory', () => {
    it('should return paginated login history', async () => {
      const userId = 'user-123'
      const page = 1
      const limit = 10
      const loginHistory = [
        { id: 'log-1', loginAt: new Date(), success: true },
        { id: 'log-2', loginAt: new Date(), success: true }
      ]

      mockReq.user = { id: userId }
      mockReq.query = { page, limit }
      AuditLogModel.getLoginHistory.mockResolvedValue(loginHistory)

      await UserController.getLoginHistory(mockReq, mockRes)

      expect(AuditLogModel.getLoginHistory).toHaveBeenCalledWith(
        userId,
        parseInt(page),
        parseInt(limit)
      )
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data: { loginHistory }
      })
    })
  })

  describe('deactivateAccount', () => {
    it('should deactivate account successfully', async () => {
      const userId = 'user-123'

      mockReq.user = { id: userId }

      UserModel.update.mockResolvedValue()
      TokenModel.revokeAllUserTokens.mockResolvedValue()
      AuditLogModel.create.mockResolvedValue()

      await UserController.deactivateAccount(mockReq, mockRes)

      expect(UserModel.update).toHaveBeenCalledWith(userId, { isActive: false })
      expect(TokenModel.revokeAllUserTokens).toHaveBeenCalledWith(userId)
      expect(AuditLogModel.create).toHaveBeenCalledWith({
        userId,
        action: 'ACCOUNT_DEACTIVATION',
        description: 'Account deactivated by user',
        ipAddress: mockReq.ip,
        userAgent: mockReq.get('User-Agent')
      })
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: 'Account deactivated successfully'
      })
    })
  })
})