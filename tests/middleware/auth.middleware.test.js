import { jest } from '@jest/globals'

// Mock dependencies before importing middleware
await jest.unstable_mockModule('../../models/user.model.js', () => ({ UserModel: {
  findById: jest.fn()
}}))

await jest.unstable_mockModule('jsonwebtoken', () => {
  const verify = jest.fn()
  const sign = jest.fn()
  return { default: { verify, sign }, verify, sign }
})

// Import after mocks
const { authenticate, authorize, optionalAuth } = await import('../../middleware/auth.middleware.js')
const { UserModel } = await import('../../models/user.model.js')
const jwt = await import('jsonwebtoken')

describe('Auth Middleware', () => {
  let mockReq, mockRes, mockNext

  beforeEach(() => {
    jest.clearAllMocks()
    
    mockReq = {
      header: jest.fn()
    }
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    }
    
    mockNext = jest.fn()
  })

  describe('authenticate', () => {
    it('should authenticate valid token', async () => {
      const token = 'valid_token'
      const userId = 'user-123'
      const user = {
        id: userId,
        email: 'test@example.com',
        isActive: true
      }

      mockReq.header.mockImplementation((header) => {
        if (header === 'Authorization') return `Bearer ${token}`
        return null
      })

      jwt.verify.mockReturnValue({ userId })
      UserModel.findById.mockResolvedValue(user)

      await authenticate(mockReq, mockRes, mockNext)

      expect(jwt.verify).toHaveBeenCalledWith(token, process.env.JWT_SECRET)
      expect(UserModel.findById).toHaveBeenCalledWith(userId)
      expect(mockReq.user).toEqual(user)
      expect(mockNext).toHaveBeenCalled()
    })

    it('should return 401 if no token provided', async () => {
      mockReq.header.mockReturnValue(null)

      await authenticate(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Access denied. No token provided.'
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should return 401 for invalid token', async () => {
      const token = 'invalid_token'
      
      mockReq.header.mockReturnValue(`Bearer ${token}`)
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token')
      })

      await authenticate(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid token.'
      })
    })

    it('should return 401 for inactive user', async () => {
      const token = 'valid_token'
      const userId = 'user-123'
      const user = {
        id: userId,
        email: 'test@example.com',
        isActive: false
      }

      mockReq.header.mockReturnValue(`Bearer ${token}`)
      jwt.verify.mockReturnValue({ userId })
      UserModel.findById.mockResolvedValue(user)

      await authenticate(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid token or user not found.'
      })
    })
  })

  describe('authorize', () => {
    it('should allow access for authorized role', () => {
      const roles = ['ADMIN', 'MODERATOR']
      const middleware = authorize(...roles)
      
      mockReq.user = { role: 'ADMIN' }

      middleware(mockReq, mockRes, mockNext)

      expect(mockNext).toHaveBeenCalled()
    })

    it('should deny access for unauthorized role', () => {
      const roles = ['ADMIN']
      const middleware = authorize(...roles)
      
      mockReq.user = { role: 'USER' }

      middleware(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(403)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Access denied. Insufficient permissions.'
      })
      expect(mockNext).not.toHaveBeenCalled()
    })
  })

  describe('optionalAuth', () => {
    it('should set user if valid token provided', async () => {
      const token = 'valid_token'
      const userId = 'user-123'
      const user = {
        id: userId,
        email: 'test@example.com',
        isActive: true
      }

      mockReq.header.mockReturnValue(`Bearer ${token}`)
      jwt.verify.mockReturnValue({ userId })
      UserModel.findById.mockResolvedValue(user)

      await optionalAuth(mockReq, mockRes, mockNext)

      expect(mockReq.user).toEqual(user)
      expect(mockNext).toHaveBeenCalled()
    })

    it('should continue without user if no token', async () => {
      mockReq.header.mockReturnValue(null)

      await optionalAuth(mockReq, mockRes, mockNext)

      expect(mockReq.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalled()
    })

    it('should continue without user on token error', async () => {
      const token = 'invalid_token'
      
      mockReq.header.mockReturnValue(`Bearer ${token}`)
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token')
      })

      await optionalAuth(mockReq, mockRes, mockNext)

      expect(mockReq.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalled()
    })
  })
})