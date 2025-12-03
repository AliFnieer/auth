import dotenv from 'dotenv'

// Provide jest globals in ESM test files
import { jest as _jest, describe as _describe, it as _it, expect as _expect, beforeEach as _beforeEach, afterEach as _afterEach } from '@jest/globals'
globalThis.jest = _jest
globalThis.describe = _describe
globalThis.it = _it
globalThis.expect = _expect
globalThis.beforeEach = _beforeEach
globalThis.afterEach = _afterEach

// Load test environment variables
dotenv.config({ path: '.env.test' })

// Replace console with wrappers that call the original console to reduce noise
const _originalConsole = { ...console }
global.console = {
  ..._originalConsole,
  log: (...args) => _originalConsole.log(...args),
  error: (...args) => _originalConsole.error(...args),
  warn: (...args) => _originalConsole.warn(...args),
  info: (...args) => _originalConsole.info(...args)
}

// Increase timeout for async operations if available
if (typeof jest !== 'undefined' && typeof jest.setTimeout === 'function') {
  jest.setTimeout(30000)
}