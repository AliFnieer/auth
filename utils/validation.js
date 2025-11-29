import validator from 'validator'

export const isValidEmail = (email) => {
  return validator.isEmail(email)
}

export const isValidPassword = (password) => {
  return password && password.length >= 6
}

export const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return validator.escape(validator.trim(input))
  }
  return input
}