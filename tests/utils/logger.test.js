import { logger } from '../../utils/logger.js'

describe('Logger', () => {
  let originalConsole

  beforeAll(() => {
    originalConsole = { ...console }
  })

  beforeEach(() => {
    console.log = jest.fn()
    console.error = jest.fn()
    console.warn = jest.fn()
  })

  afterAll(() => {
    console.log = originalConsole.log
    console.error = originalConsole.error
    console.warn = originalConsole.warn
  })

  describe('info', () => {
    it('should log info message', () => {
      const message = 'Test info message'
      const meta = { userId: '123' }

      logger.info(message, meta)

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[INFO]'),
        expect.stringContaining(message),
        meta
      )
    })
  })

  describe('error', () => {
    it('should log error message', () => {
      const message = 'Test error message'
      const error = new Error('Test error')

      logger.error(message, error)

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[ERROR]'),
        expect.stringContaining(message),
        error
      )
    })
  })

  describe('warn', () => {
    it('should log warning message', () => {
      const message = 'Test warning message'
      const meta = { action: 'test' }

      logger.warn(message, meta)

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('[WARN]'),
        expect.stringContaining(message),
        meta
      )
    })
  })
})