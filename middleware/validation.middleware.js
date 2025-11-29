import validator from 'validator'

export const validateRegister = (req, res, next) => {
  const { email, password, firstName, lastName } = req.body

  // Validate email
  if (!email || !validator.isEmail(email)) {
    return res.status(400).json({
      success: false,
      message: 'Please provide a valid email address'
    })
  }

  // Validate password
  if (!password || password.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'Password must be at least 6 characters long'
    })
  }

  // Validate name
  if (firstName && firstName.length > 50) {
    return res.status(400).json({
      success: false,
      message: 'First name must be less than 50 characters'
    })
  }

  if (lastName && lastName.length > 50) {
    return res.status(400).json({
      success: false,
      message: 'Last name must be less than 50 characters'
    })
  }

  next()
}

export const validateLogin = (req, res, next) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    })
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({
      success: false,
      message: 'Please provide a valid email address'
    })
  }

  next()
}

export const validatePasswordReset = (req, res, next) => {
  const { newPassword } = req.body

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'Password must be at least 6 characters long'
    })
  }

  next()
}

export const validateUpdateProfile = (req, res, next) => {
  const { firstName, lastName, phone } = req.body

  if (firstName && firstName.length > 50) {
    return res.status(400).json({
      success: false,
      message: 'First name must be less than 50 characters'
    })
  }

  if (lastName && lastName.length > 50) {
    return res.status(400).json({
      success: false,
      message: 'Last name must be less than 50 characters'
    })
  }

  if (phone && !validator.isMobilePhone(phone)) {
    return res.status(400).json({
      success: false,
      message: 'Please provide a valid phone number'
    })
  }

  next()
}