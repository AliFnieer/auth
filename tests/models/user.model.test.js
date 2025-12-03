import { jest } from '@jest/globals'

// Mock dependencies before importing the module under test
await jest.unstable_mockModule('../../lib/prisma.js', () => {
  const user = {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn()
  }
  return { default: { user } }
})

await jest.unstable_mockModule('../../utils/validation.js', () => {
  return { sanitizeInput: jest.fn() }
})

await jest.unstable_mockModule('bcryptjs', () => {
  const hash = jest.fn()
  const compare = jest.fn()
  return { default: { hash, compare }, hash, compare }
})

// Import modules after mocks
const { UserModel } = await import('../../models/user.model.js')
const prisma = (await import('../../lib/prisma.js')).default
const bcrypt = await import('bcryptjs')
const { sanitizeInput } = await import('../../utils/validation.js')

describe('UserModel', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('create', () => {
    it('should create a user with hashed password and sanitized fields', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: '<script>alert("xss")</script>John',
        lastName: 'Doe',
        phone: '1234567890'
      }

      const sanitizedData = {
        email: 'test@example.com',
        firstName: '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;John',
        lastName: 'Doe',
        phone: '1234567890'
      }

      const hashedPassword = 'hashed_password_123'
      const createdUser = {
        id: 'user-123',
        email: sanitizedData.email,
        firstName: sanitizedData.firstName,
        lastName: sanitizedData.lastName,
        role: 'USER',
        isVerified: false,
        createdAt: new Date()
      }

      // Mock sanitizeInput
      sanitizeInput
        .mockReturnValueOnce(sanitizedData.email)
        .mockReturnValueOnce(sanitizedData.firstName)
        .mockReturnValueOnce(sanitizedData.lastName)
        .mockReturnValueOnce(sanitizedData.phone)

      // Mock bcrypt.hash
      bcrypt.hash.mockResolvedValue(hashedPassword)

      // Mock prisma.user.create
      prisma.user.create.mockResolvedValue(createdUser)

      const result = await UserModel.create(userData)

      expect(sanitizeInput).toHaveBeenCalledTimes(4)
      expect(bcrypt.hash).toHaveBeenCalledWith(userData.password, 12)
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: {
          email: sanitizedData.email,
          firstName: sanitizedData.firstName,
          lastName: sanitizedData.lastName,
          phone: sanitizedData.phone,
          password: hashedPassword
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isVerified: true,
          createdAt: true
        }
      })
      expect(result).toEqual(createdUser)
    })

    it('should handle missing optional fields', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123'
      }

      const createdUser = {
        id: 'user-123',
        email: userData.email,
        firstName: null,
        lastName: null,
        role: 'USER',
        isVerified: false,
        createdAt: new Date()
      }

      sanitizeInput.mockReturnValue(userData.email)
      bcrypt.hash.mockResolvedValue('hashed_password')
      prisma.user.create.mockResolvedValue(createdUser)

      const result = await UserModel.create(userData)

      expect(result).toEqual(createdUser)
    })
  })

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      const email = 'test@example.com'
      const user = {
        id: 'user-123',
        email,
        firstName: 'John',
        lastName: 'Doe'
      }

      prisma.user.findUnique.mockResolvedValue(user)

      const result = await UserModel.findByEmail(email)

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email }
      })
      expect(result).toEqual(user)
    })

    it('should return null if user not found', async () => {
      const email = 'nonexistent@example.com'

      prisma.user.findUnique.mockResolvedValue(null)

      const result = await UserModel.findByEmail(email)

      expect(result).toBeNull()
    })
  })

  describe('findById', () => {
    it('should find user by id with selected fields', async () => {
      const id = 'user-123'
      const user = {
        id,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        role: 'USER',
        isVerified: true,
        isActive: true,
        createdAt: new Date(),
        lastLoginAt: new Date()
      }

      prisma.user.findUnique.mockResolvedValue(user)

      const result = await UserModel.findById(id)

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isVerified: true,
          isActive: true,
          createdAt: true,
          lastLoginAt: true
        }
      })
      expect(result).toEqual(user)
    })
  })

  describe('update', () => {
    it('should update user with sanitized data', async () => {
      const id = 'user-123'
      const updateData = {
        firstName: '<script>alert("xss")</script>John',
        lastName: 'Doe',
        phone: '1234567890'
      }

      const sanitizedData = {
        firstName: '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;John',
        lastName: 'Doe',
        phone: '1234567890'
      }

      const updatedUser = {
        id,
        email: 'test@example.com',
        firstName: sanitizedData.firstName,
        lastName: sanitizedData.lastName,
        role: 'USER',
        isVerified: true,
        updatedAt: new Date()
      }

      sanitizeInput
        .mockReturnValueOnce(sanitizedData.firstName)
        .mockReturnValueOnce(sanitizedData.lastName)
        .mockReturnValueOnce(sanitizedData.phone)

      prisma.user.update.mockResolvedValue(updatedUser)

      const result = await UserModel.update(id, updateData)

      expect(sanitizeInput).toHaveBeenCalledTimes(3)
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id },
        data: sanitizedData,
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isVerified: true,
          updatedAt: true
        }
      })
      expect(result).toEqual(updatedUser)
    })

    it('should update only provided fields', async () => {
      const id = 'user-123'
      const updateData = { firstName: 'John' }

      sanitizeInput.mockReturnValue(updateData.firstName)

      await UserModel.update(id, updateData)

      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id },
        data: { firstName: updateData.firstName },
        select: expect.any(Object)
      })
    })
  })

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const plainPassword = 'password123'
      const hashedPassword = 'hashed_password'

      bcrypt.compare.mockResolvedValue(true)

      const result = await UserModel.verifyPassword(plainPassword, hashedPassword)

      expect(bcrypt.compare).toHaveBeenCalledWith(plainPassword, hashedPassword)
      expect(result).toBe(true)
    })

    it('should reject incorrect password', async () => {
      const plainPassword = 'wrong_password'
      const hashedPassword = 'hashed_password'

      bcrypt.compare.mockResolvedValue(false)

      const result = await UserModel.verifyPassword(plainPassword, hashedPassword)

      expect(result).toBe(false)
    })
  })
})