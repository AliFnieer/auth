import { jest } from '@jest/globals'

const isEmail = jest.fn()
const trim = jest.fn()
const escape = jest.fn()

export default { isEmail, trim, escape }
