import { jest } from '@jest/globals'

// Mock dependencies before importing middleware
await jest.unstable_mockModule('validator', () => {
  const isEmail = jest.fn()
  const isMobilePhone = jest.fn()
  const trim = jest.fn()
  const escape = jest.fn()
  return { default: { isEmail, isMobilePhone, trim, escape }, isEmail, isMobilePhone, trim, escape }
})

await jest.unstable_mockModule('../../utils/validation.js', () => ({ sanitizeInput: jest.fn() }))

// Import after mocks
const { validateRegister, validateLogin, validateUpdateProfile } = await import('../../middleware/validation.middleware.js')
const validator = await import('validator')
const { sanitizeInput } = await import('../../utils/validation.js')

describe('Validation Middleware', () => {
  let mockReq, mockRes, mockNext

  beforeEach(() => {
    jest.clearAllMocks()
    
    mockReq = {
      body: {}
    }
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    }
    
    mockNext = jest.fn()
  })

  describe('validateRegister', () => {
    it('should pass validation for valid data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      }

      mockReq.body = validData

      sanitizeInput.mockImplementation(input => input)
      validator.isEmail.mockReturnValue(true)

      validateRegister(mockReq, mockRes, mockNext)

      expect(sanitizeInput).toHaveBeenCalledTimes(3)
      expect(validator.isEmail).toHaveBeenCalledWith(validData.email)
      expect(mockNext).toHaveBeenCalled()
    })

    it('should return error for invalid email', () => {
      const invalidData = {
        email: 'invalid-email',
        password: 'password123'
      }

      mockReq.body = invalidData

      sanitizeInput.mockImplementation(input => input)
      validator.isEmail.mockReturnValue(false)

      validateRegister(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Please provide a valid email address'
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should return error for short password', () => {
      const invalidData = {
        email: 'test@example.com',
        password: '123'
      }

      mockReq.body = invalidData

      sanitizeInput.mockImplementation(input => input)
      validator.isEmail.mockReturnValue(true)

      validateRegister(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Password must be at least 6 characters long'
      })
    })

    it('should return error for long first name', () => {
      const longName = 'A'.repeat(51)
      const invalidData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: longName
      }

      mockReq.body = invalidData

      sanitizeInput.mockImplementation(input => input)
      validator.isEmail.mockReturnValue(true)

      validateRegister(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'First name must be less than 50 characters'
      })
    })
  })

  describe('validateLogin', () => {
    it('should pass validation for valid login data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'password123'
      }

      mockReq.body = validData

      sanitizeInput.mockImplementation(input => input)
      validator.isEmail.mockReturnValue(true)

      validateLogin(mockReq, mockRes, mockNext)

      expect(sanitizeInput).toHaveBeenCalledWith(validData.email)
      expect(mockNext).toHaveBeenCalled()
    })

    it('should return error for missing credentials', () => {
      const invalidData = {
        email: '',
        password: ''
      }

      mockReq.body = invalidData

      validateLogin(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Email and password are required'
      })
    })
  })

  describe('validateUpdateProfile', () => {
    it('should pass validation for valid profile data', () => {
      const validData = {
        firstName: 'John',
        lastName: 'Doe',
        phone: '+1234567890'
      }

      mockReq.body = validData

      sanitizeInput.mockImplementation(input => input)
      validator.isMobilePhone.mockReturnValue(true)

      validateUpdateProfile(mockReq, mockRes, mockNext)

      expect(sanitizeInput).toHaveBeenCalledTimes(3)
      expect(validator.isMobilePhone).toHaveBeenCalledWith(validData.phone)
      expect(mockNext).toHaveBeenCalled()
    })

    it('should return error for invalid phone number', () => {
      const invalidData = {
        phone: 'invalid-phone'
      }

      mockReq.body = invalidData

      sanitizeInput.mockImplementation(input => input)
      validator.isMobilePhone.mockReturnValue(false)

      validateUpdateProfile(mockReq, mockRes, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(400)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Please provide a valid phone number'
      })
    })
  })
})