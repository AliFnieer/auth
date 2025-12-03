import { jest } from '@jest/globals'

// Mock dependencies before importing the module under test
await jest.unstable_mockModule('../../lib/prisma.js', () => {
  const refreshToken = { create: jest.fn(), findFirst: jest.fn(), updateMany: jest.fn() }
  const verificationToken = { create: jest.fn(), findFirst: jest.fn() }
  const passwordResetToken = { create: jest.fn(), findFirst: jest.fn() }
  return { default: { refreshToken, verificationToken, passwordResetToken } }
})

await jest.unstable_mockModule('crypto', () => {
  const randomBytes = jest.fn()
  return { default: { randomBytes }, randomBytes }
})

// Import modules after mocks
const { TokenModel } = await import('../../models/token.model.js')
const prisma = (await import('../../lib/prisma.js')).default
const crypto = await import('crypto')

describe('TokenModel', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  describe('generateToken', () => {
    it('should generate a random token', () => {
      const mockToken = 'random_token_123'
      crypto.randomBytes.mockReturnValue({ toString: () => mockToken })

      const result = TokenModel.generateToken()

      expect(crypto.randomBytes).toHaveBeenCalledWith(32)
      expect(result).toBe(mockToken)
    })
  })

  describe('createRefreshToken', () => {
    it('should create a refresh token', async () => {
      const userId = 'user-123'
      const userAgent = 'TestAgent/1.0'
      const ipAddress = '127.0.0.1'
      const token = 'refresh_token_123'
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)

      crypto.randomBytes.mockReturnValue({ toString: () => token })

      const createdToken = {
        id: 'token-123',
        token,
        userId,
        expiresAt,
        userAgent,
        ipAddress,
        createdAt: new Date(),
        isRevoked: false
      }

      prisma.refreshToken.create.mockResolvedValue(createdToken)

      const result = await TokenModel.createRefreshToken(userId, userAgent, ipAddress)

      expect(crypto.randomBytes).toHaveBeenCalledWith(32)
      expect(prisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          token,
          userId,
          expiresAt,
          userAgent,
          ipAddress
        }
      })
      expect(result).toEqual(createdToken)
    })
  })

  describe('findRefreshToken', () => {
    it('should find valid refresh token', async () => {
      const token = 'valid_token'
      const tokenRecord = {
        id: 'token-123',
        token,
        userId: 'user-123',
        expiresAt: new Date(Date.now() + 10000),
        isRevoked: false,
        user: {
          id: 'user-123',
          email: 'test@example.com'
        }
      }

      prisma.refreshToken.findFirst.mockResolvedValue(tokenRecord)

      const result = await TokenModel.findRefreshToken(token)

      expect(prisma.refreshToken.findFirst).toHaveBeenCalledWith({
        where: {
          token,
          isRevoked: false,
          expiresAt: { gt: expect.any(Date) }
        },
        include: { user: true }
      })
      expect(result).toEqual(tokenRecord)
    })

    it('should return null for expired token', async () => {
      const token = 'expired_token'

      prisma.refreshToken.findFirst.mockResolvedValue(null)

      const result = await TokenModel.findRefreshToken(token)

      expect(result).toBeNull()
    })
  })

  describe('revokeRefreshToken', () => {
    it('should revoke a refresh token', async () => {
      const token = 'token_to_revoke'

      prisma.refreshToken.updateMany.mockResolvedValue({ count: 1 })

      await TokenModel.revokeRefreshToken(token)

      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { token },
        data: { isRevoked: true }
      })
    })
  })

  describe('revokeAllUserTokens', () => {
    it('should revoke all user tokens', async () => {
      const userId = 'user-123'

      prisma.refreshToken.updateMany.mockResolvedValue({ count: 3 })

      await TokenModel.revokeAllUserTokens(userId)

      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          userId,
          isRevoked: false
        },
        data: { isRevoked: true }
      })
    })
  })

  describe('createVerificationToken', () => {
    it('should create a verification token', async () => {
      const userId = 'user-123'
      const token = 'verification_token_123'
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000)

      crypto.randomBytes.mockReturnValue({ toString: () => token })

      const createdToken = {
        id: 'token-123',
        token,
        userId,
        expiresAt,
        createdAt: new Date()
      }

      prisma.verificationToken.create.mockResolvedValue(createdToken)

      const result = await TokenModel.createVerificationToken(userId)

      expect(prisma.verificationToken.create).toHaveBeenCalledWith({
        data: {
          token,
          userId,
          expiresAt
        }
      })
      expect(result).toEqual(createdToken)
    })
  })

  describe('findVerificationToken', () => {
    it('should find valid verification token', async () => {
      const token = 'valid_verification_token'
      const tokenRecord = {
        id: 'token-123',
        token,
        userId: 'user-123',
        expiresAt: new Date(Date.now() + 10000),
        user: {
          id: 'user-123',
          email: 'test@example.com'
        }
      }

      prisma.verificationToken.findFirst.mockResolvedValue(tokenRecord)

      const result = await TokenModel.findVerificationToken(token)

      expect(prisma.verificationToken.findFirst).toHaveBeenCalledWith({
        where: {
          token,
          expiresAt: { gt: expect.any(Date) }
        },
        include: { user: true }
      })
      expect(result).toEqual(tokenRecord)
    })
  })

  describe('createPasswordResetToken', () => {
    it('should create a password reset token', async () => {
      const userId = 'user-123'
      const token = 'reset_token_123'
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000)

      crypto.randomBytes.mockReturnValue({ toString: () => token })

      const createdToken = {
        id: 'token-123',
        token,
        userId,
        expiresAt,
        createdAt: new Date(),
        usedAt: null
      }

      prisma.passwordResetToken.create.mockResolvedValue(createdToken)

      const result = await TokenModel.createPasswordResetToken(userId)

      expect(prisma.passwordResetToken.create).toHaveBeenCalledWith({
        data: {
          token,
          userId,
          expiresAt
        }
      })
      expect(result).toEqual(createdToken)
    })
  })

  describe('findPasswordResetToken', () => {
    it('should find valid, unused password reset token', async () => {
      const token = 'valid_reset_token'
      const tokenRecord = {
        id: 'token-123',
        token,
        userId: 'user-123',
        expiresAt: new Date(Date.now() + 10000),
        usedAt: null,
        user: {
          id: 'user-123',
          email: 'test@example.com'
        }
      }

      prisma.passwordResetToken.findFirst.mockResolvedValue(tokenRecord)

      const result = await TokenModel.findPasswordResetToken(token)

      expect(prisma.passwordResetToken.findFirst).toHaveBeenCalledWith({
        where: {
          token,
          expiresAt: { gt: expect.any(Date) },
          usedAt: null
        },
        include: { user: true }
      })
      expect(result).toEqual(tokenRecord)
    })
  })
})