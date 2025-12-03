import { jest } from '@jest/globals'

// Mock validator before importing module under test
await jest.unstable_mockModule('validator', () => {
  const isEmail = jest.fn()
  const trim = jest.fn()
  const escape = jest.fn()
  const isMobilePhone = jest.fn()
  return { default: { isEmail, trim, escape, isMobilePhone }, isEmail, trim, escape, isMobilePhone }
})

const { isValidEmail, isValidPassword, sanitizeInput } = await import('../../utils/validation.js')
const validator = await import('validator')

describe('Validation Utils', () => {
  describe('isValidEmail', () => {
    it('should return true for valid email', () => {
      const validEmail = 'test@example.com'
      validator.isEmail.mockReturnValue(true)

      const result = isValidEmail(validEmail)

      expect(validator.isEmail).toHaveBeenCalledWith(validEmail)
      expect(result).toBe(true)
    })

    it('should return false for invalid email', () => {
      const invalidEmail = 'invalid-email'
      validator.isEmail.mockReturnValue(false)

      const result = isValidEmail(invalidEmail)

      expect(result).toBe(false)
    })
  })

  describe('isValidPassword', () => {
    it('should return true for valid password', () => {
      const validPassword = 'password123'

      const result = isValidPassword(validPassword)

      expect(result).toBe(true)
    })

    it('should return false for short password', () => {
      const shortPassword = '12345'

      const result = isValidPassword(shortPassword)

      expect(result).toBe(false)
    })

    it('should return false for empty password', () => {
      const emptyPassword = ''

      const result = isValidPassword(emptyPassword)

      expect(result).toBe(false)
    })
  })

  describe('sanitizeInput', () => {
    it('should sanitize string input', () => {
      const input = '  <script>alert("xss")</script>  '
      const trimmed = '<script>alert("xss")</script>'
      const escaped = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

      validator.trim.mockReturnValue(trimmed)
      validator.escape.mockReturnValue(escaped)

      const result = sanitizeInput(input)

      expect(validator.trim).toHaveBeenCalledWith(input)
      expect(validator.escape).toHaveBeenCalledWith(trimmed)
      expect(result).toBe(escaped)
    })

    it('should return non-string input as-is', () => {
      const input = 123

      const result = sanitizeInput(input)

      expect(result).toBe(input)
    })
  })
})