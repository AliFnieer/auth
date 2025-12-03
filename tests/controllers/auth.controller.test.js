import { jest } from '@jest/globals'

// Mock dependencies before importing controller
await jest.unstable_mockModule('../../models/user.model.js', () => {
  return {
    UserModel: {
      findByEmail: jest.fn(),
      create: jest.fn(),
      verifyPassword: jest.fn(),
      update: jest.fn()
    }
  }
})

await jest.unstable_mockModule('../../models/token.model.js', () => {
  return {
    TokenModel: {
      createVerificationToken: jest.fn(),
      createRefreshToken: jest.fn(),
      findRefreshTokenByToken: jest.fn(),
      revokeRefreshToken: jest.fn(),
      revokeAllUserTokens: jest.fn()
    }
  }
})

await jest.unstable_mockModule('../../models/audit.model.js', () => {
  return { AuditLogModel: { create: jest.fn() } }
})

await jest.unstable_mockModule('../../utils/emailService.js', () => {
  return { EmailService: { sendVerificationEmail: jest.fn(), sendPasswordResetEmail: jest.fn() } }
})

await jest.unstable_mockModule('jsonwebtoken', () => {
  const sign = jest.fn()
  const verify = jest.fn()
  return { default: { sign, verify }, sign, verify }
})

await jest.unstable_mockModule('bcryptjs', () => {
  const hash = jest.fn()
  const compare = jest.fn()
  return { default: { hash, compare }, hash, compare }
})

// Import modules after mocks
const { AuthController } = await import('../../controllers/auth.controller.js')
const { UserModel } = await import('../../models/user.model.js')
const { TokenModel } = await import('../../models/token.model.js')
const { AuditLogModel } = await import('../../models/audit.model.js')
const { EmailService } = await import('../../utils/emailService.js')
const jwt = await import('jsonwebtoken')
const bcrypt = await import('bcryptjs')

describe('AuthController', () => {
  let mockReq, mockRes, mockNext

  beforeEach(() => {
    jest.clearAllMocks()
    
    mockReq = {
      body: {},
      params: {},
      cookies: {},
      get: jest.fn(),
      ip: '127.0.0.1'
    }
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      cookie: jest.fn(),
      clearCookie: jest.fn()
    }
    
    mockNext = jest.fn()
    
    // Default mocks
    mockReq.get.mockReturnValue('TestAgent/1.0')
  })

  describe('generateAccessToken', () => {
    it('should generate access token with correct payload', () => {
      const userId = 'user-123'
      const token = 'jwt_token_123'
      
      jwt.sign.mockReturnValue(token)
      process.env.JWT_SECRET = 'test_secret'
      process.env.JWT_EXPIRES_IN = '15m'

      const result = AuthController.generateAccessToken(userId)

      expect(jwt.sign).toHaveBeenCalledWith(
        {
          userId,
          type: 'access'
        },
        'test_secret',
        {
          expiresIn: '15m',
          issuer: 'auth',
          subject: userId
        }
      )
      expect(result).toBe(token)
    })
  })

  describe('register', () => {
    it('should register new user successfully', async () => {
      const userData = {
        email: 'new@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
        phone: '1234567890'
      }

      mockReq.body = userData

      const createdUser = {
        id: 'user-123',
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        role: 'USER',
        isVerified: false,
        createdAt: new Date()
      }

      const verificationToken = {
        token: 'verification_token_123'
      }

      UserModel.findByEmail.mockResolvedValue(null)
      UserModel.create.mockResolvedValue(createdUser)
      TokenModel.createVerificationToken.mockResolvedValue(verificationToken)
      EmailService.sendVerificationEmail.mockResolvedValue()
      AuditLogModel.create.mockResolvedValue()

      await AuthController.register(mockReq, mockRes)

      expect(UserModel.findByEmail).toHaveBeenCalledWith(userData.email)
      expect(UserModel.create).toHaveBeenCalledWith(userData)
      expect(TokenModel.createVerificationToken).toHaveBeenCalledWith(createdUser.id)
      expect(EmailService.sendVerificationEmail).toHaveBeenCalledWith(
        userData.email,
        verificationToken.token
      )
      expect(AuditLogModel.create).toHaveBeenCalledWith({
        userId: createdUser.id,
        action: 'REGISTER',
        description: 'User registered successfully',
        ipAddress: mockReq.ip,
        userAgent: mockReq.get('User-Agent')
      })
      expect(mockRes.status).toHaveBeenCalledWith(201)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: 'User registered successfully. Please check your email for verification.',
        data: { user: createdUser }
      })
    })

    it('should return error if user already exists', async () => {
      const userData = {
        email: 'existing@example.com',
        password: 'password123'
      }

      mockReq.body = userData

      const existingUser = {
        id: 'existing-user',
        email: userData.email
      }

      UserModel.findByEmail.mockResolvedValue(existingUser)

      await AuthController.register(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'User already exists with this email.'
      })
    })

    it('should handle email sending failure gracefully', async () => {
      const userData = {
        email: 'new@example.com',
        password: 'password123'
      }

      mockReq.body = userData

      const createdUser = {
        id: 'user-123',
        email: userData.email
      }

      const verificationToken = {
        token: 'verification_token_123'
      }

      UserModel.findByEmail.mockResolvedValue(null)
      UserModel.create.mockResolvedValue(createdUser)
      TokenModel.createVerificationToken.mockResolvedValue(verificationToken)
      EmailService.sendVerificationEmail.mockRejectedValue(new Error('SMTP Error'))
      AuditLogModel.create.mockResolvedValue()

      await AuthController.register(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(201)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: 'User registered successfully. Please check your email for verification.',
        data: { user: createdUser }
      })
    })
  })

  describe('login', () => {
    it('should login successfully with valid credentials', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'password123'
      }

      mockReq.body = credentials

      const user = {
        id: 'user-123',
        email: credentials.email,
        password: 'hashed_password',
        isActive: true,
        isVerified: true,
        firstName: 'John',
        lastName: 'Doe',
        role: 'USER'
      }

      const accessToken = 'access_token_123'
      const refreshToken = {
        token: 'refresh_token_123'
      }

      UserModel.findByEmail.mockResolvedValue(user)
      UserModel.verifyPassword.mockResolvedValue(true)
      UserModel.update.mockResolvedValue()
      TokenModel.createRefreshToken.mockResolvedValue(refreshToken)
      AuditLogModel.create.mockResolvedValue()

      // Mock generateAccessToken
      const originalGenerateAccessToken = AuthController.generateAccessToken
      AuthController.generateAccessToken = jest.fn().mockReturnValue(accessToken)

      await AuthController.login(mockReq, mockRes)

      expect(UserModel.findByEmail).toHaveBeenCalledWith(credentials.email)
      expect(UserModel.verifyPassword).toHaveBeenCalledWith(credentials.password, user.password)
      expect(UserModel.update).toHaveBeenCalledWith(user.id, { lastLoginAt: expect.any(Date) })
      expect(TokenModel.createRefreshToken).toHaveBeenCalledWith(
        user.id,
        mockReq.get('User-Agent'),
        mockReq.ip
      )
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        refreshToken.token,
        expect.objectContaining({
          httpOnly: true,
          secure: false, // NODE_ENV is not production
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000,
          path: '/api'
        })
      )
      expect(mockRes.json).toHaveBeenCalledWith({
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
            expiresIn: '15m'
          }
        }
      })

      // Restore original function
      AuthController.generateAccessToken = originalGenerateAccessToken
    })

    it('should return error for invalid credentials', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'wrong_password'
      }

      mockReq.body = credentials

      const user = {
        id: 'user-123',
        email: credentials.email,
        password: 'hashed_password',
        isActive: true
      }

      UserModel.findByEmail.mockResolvedValue(user)
      UserModel.verifyPassword.mockResolvedValue(false)
      AuditLogModel.create.mockResolvedValue()

      await AuthController.login(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid credentials'
      })
      expect(AuditLogModel.create).toHaveBeenCalledWith({
        userId: user.id,
        action: 'LOGIN',
        description: 'Failed login attempt - invalid password',
        ipAddress: mockReq.ip,
        userAgent: mockReq.get('User-Agent'),
        success: false
      })
    })

    it('should return error for unverified email', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'password123'
      }

      mockReq.body = credentials

      const user = {
        id: 'user-123',
        email: credentials.email,
        password: 'hashed_password',
        isActive: true,
        isVerified: false
      }

      UserModel.findByEmail.mockResolvedValue(user)
      UserModel.verifyPassword.mockResolvedValue(true)

      await AuthController.login(mockReq, mockRes)

      expect(mockRes.status).toHaveBeenCalledWith(403)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Please verify your email before logging in.'
      })
    })
  })

  describe('refreshToken', () => {
    it('should refresh token successfully', async () => {
      const refreshToken = 'valid_refresh_token'
      mockReq.cookies.refreshToken = refreshToken

      const tokenRecord = {
        token: refreshToken,
        userId: 'user-123',
        expiresAt: new Date(Date.now() + 10000),
        isRevoked: false,
        user: {
          id: 'user-123',
          email: 'test@example.com'
        }
      }

      const newRefreshToken = {
        token: 'new_refresh_token_123'
      }

      const accessToken = 'new_access_token_123'

      TokenModel.findRefreshTokenByToken.mockResolvedValue(tokenRecord)
      TokenModel.createRefreshToken.mockResolvedValue(newRefreshToken)
      TokenModel.revokeRefreshToken.mockResolvedValue()

      // Mock generateAccessToken
      const originalGenerateAccessToken = AuthController.generateAccessToken
      AuthController.generateAccessToken = jest.fn().mockReturnValue(accessToken)

      await AuthController.refreshToken(mockReq, mockRes)

      expect(TokenModel.findRefreshTokenByToken).toHaveBeenCalledWith(refreshToken)
      expect(TokenModel.createRefreshToken).toHaveBeenCalledWith(
        tokenRecord.userId,
        mockReq.get('User-Agent'),
        mockReq.ip
      )
      expect(TokenModel.revokeRefreshToken).toHaveBeenCalledWith(refreshToken)
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        newRefreshToken.token,
        expect.any(Object)
      )
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data: {
          accessToken
        }
      })

      // Restore original function
      AuthController.generateAccessToken = originalGenerateAccessToken
    })

    it('should detect token reuse and revoke all sessions', async () => {
      const reusedToken = 'reused_token'
      mockReq.cookies.refreshToken = reusedToken

      const tokenRecord = {
        token: reusedToken,
        userId: 'user-123',
        expiresAt: new Date(Date.now() + 10000),
        isRevoked: true
      }

      TokenModel.findRefreshTokenByToken.mockResolvedValue(tokenRecord)
      TokenModel.revokeAllUserTokens.mockResolvedValue()

      await AuthController.refreshToken(mockReq, mockRes)

      expect(TokenModel.revokeAllUserTokens).toHaveBeenCalledWith(tokenRecord.userId)
      expect(mockRes.clearCookie).toHaveBeenCalledWith('refreshToken')
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Refresh token reuse detected. All sessions revoked.'
      })
    })
  })

  describe('logout', () => {
    it('should logout successfully', async () => {
      const refreshToken = 'refresh_token_123'
      mockReq.cookies.refreshToken = refreshToken
      mockReq.user = { id: 'user-123' }

      TokenModel.revokeRefreshToken.mockResolvedValue()
      AuditLogModel.create.mockResolvedValue()

      await AuthController.logout(mockReq, mockRes)

      expect(TokenModel.revokeRefreshToken).toHaveBeenCalledWith(refreshToken)
      expect(mockRes.clearCookie).toHaveBeenCalledWith('refreshToken', { path: '/api' })
      expect(AuditLogModel.create).toHaveBeenCalledWith({
        userId: mockReq.user.id,
        action: 'LOGOUT',
        description: 'User logged out successfully',
        ipAddress: mockReq.ip,
        userAgent: mockReq.get('User-Agent')
      })
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: 'Logged out successfully'
      })
    })
  })
})