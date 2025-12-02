import nodemailer from 'nodemailer'
import { logger } from './logger.js'

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
})

const emailTemplates = {
  verificationEmail: (link, appName = process.env.APP_NAME || 'Our Platform') => `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify Your Email</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 30px;
          text-align: center;
          border-radius: 10px 10px 0 0;
        }
        .content {
          background: #f9f9f9;
          padding: 30px;
          border-radius: 0 0 10px 10px;
        }
        .button {
          display: inline-block;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          text-decoration: none;
          padding: 14px 28px;
          border-radius: 5px;
          font-weight: bold;
          margin: 20px 0;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          color: #666;
          font-size: 12px;
        }
        .code {
          background: #f4f4f4;
          padding: 10px;
          border-radius: 5px;
          font-family: monospace;
          word-break: break-all;
          margin: 20px 0;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Welcome to ${appName}! 👋</h1>
      </div>
      <div class="content">
        <h2>Verify Your Email Address</h2>
        <p>Thank you for signing up! To complete your registration and start using ${appName}, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center;">
          <a href="${link}" class="button">Verify Email Address</a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <div class="code">${link}</div>
        
        <p><strong>This verification link will expire in 24 hours.</strong></p>
        
        <p>If you didn't create an account with ${appName}, please ignore this email.</p>
        
        <p>Need help? <a href="mailto:${process.env.SUPPORT_EMAIL || 'support@example.com'}">Contact our support team</a></p>
      </div>
      <div class="footer">
        <p>© ${new Date().getFullYear()} ${appName}. All rights reserved.</p>
        <p>This email was sent to you as part of your ${appName} account registration.</p>
      </div>
    </body>
    </html>
  `,

  passwordResetEmail: (link, appName = process.env.APP_NAME || 'Our Platform') => `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
          color: white;
          padding: 30px;
          text-align: center;
          border-radius: 10px 10px 0 0;
        }
        .content {
          background: #f9f9f9;
          padding: 30px;
          border-radius: 0 0 10px 10px;
        }
        .button {
          display: inline-block;
          background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
          color: white;
          text-decoration: none;
          padding: 14px 28px;
          border-radius: 5px;
          font-weight: bold;
          margin: 20px 0;
        }
        .warning {
          background: #fff3cd;
          border: 1px solid #ffc107;
          color: #856404;
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          color: #666;
          font-size: 12px;
        }
        .code {
          background: #f4f4f4;
          padding: 10px;
          border-radius: 5px;
          font-family: monospace;
          word-break: break-all;
          margin: 20px 0;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Password Reset 🔒</h1>
      </div>
      <div class="content">
        <h2>Reset Your Password</h2>
        <p>We received a request to reset the password for your ${appName} account. Click the button below to create a new password:</p>
        
        <div style="text-align: center;">
          <a href="${link}" class="button">Reset Password</a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <div class="code">${link}</div>
        
        <div class="warning">
          <p><strong>⚠️ Important:</strong></p>
          <ul>
            <li>This link will expire in 1 hour</li>
            <li>If you didn't request this password reset, please ignore this email</li>
            <li>Your password will not change until you create a new one</li>
          </ul>
        </div>
        
        <p>For security reasons, this link can only be used once. If you need to reset your password again, please submit a new request.</p>
        
        <p>Need help? <a href="mailto:${process.env.SUPPORT_EMAIL || 'support@example.com'}">Contact our support team</a></p>
      </div>
      <div class="footer">
        <p>© ${new Date().getFullYear()} ${appName}. All rights reserved.</p>
        <p>This is an automated message, please do not reply to this email.</p>
      </div>
    </body>
    </html>
  `,

  welcomeEmail: (userName, appName = process.env.APP_NAME || 'Our Platform') => `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to ${appName}!</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
          color: white;
          padding: 40px;
          text-align: center;
          border-radius: 10px 10px 0 0;
        }
        .content {
          background: #f9f9f9;
          padding: 30px;
          border-radius: 0 0 10px 10px;
        }
        .features {
          margin: 30px 0;
        }
        .feature-item {
          background: white;
          padding: 15px;
          margin: 10px 0;
          border-radius: 5px;
          border-left: 4px solid #4facfe;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          color: #666;
          font-size: 12px;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🎉 Welcome to ${appName}, ${userName}!</h1>
      </div>
      <div class="content">
        <h2>Thank you for joining us!</h2>
        <p>We're excited to have you as part of our community. Your account is now fully activated and ready to use.</p>
        
        <div class="features">
          <h3>Getting Started:</h3>
          <div class="feature-item">
            <strong>📝 Complete your profile</strong>
            <p>Add a profile picture and update your information</p>
          </div>
          <div class="feature-item">
            <strong>🔍 Explore features</strong>
            <p>Take a tour of all the tools we offer</p>
          </div>
          <div class="feature-item">
            <strong>📚 Check out our guides</strong>
            <p>Visit our help center for tutorials</p>
          </div>
        </div>
        
        <h3>Need Assistance?</h3>
        <p>We're here to help! If you have any questions or need assistance:</p>
        <ul>
          <li>📖 Visit our <a href="${process.env.HELP_CENTER_URL || '#'}">Help Center</a></li>
          <li>📧 Email us at <a href="mailto:${process.env.SUPPORT_EMAIL || 'support@example.com'}">${process.env.SUPPORT_EMAIL || 'support@example.com'}</a></li>
          <li>💬 Join our <a href="${process.env.COMMUNITY_URL || '#'}">Community Forum</a></li>
        </ul>
        
        <p>Best regards,<br>The ${appName} Team</p>
      </div>
      <div class="footer">
        <p>© ${new Date().getFullYear()} ${appName}. All rights reserved.</p>
        <p>You're receiving this email because you recently created an account on ${appName}.</p>
        <p><a href="${process.env.UNSUBSCRIBE_URL || '#'}">Unsubscribe from welcome emails</a></p>
      </div>
    </body>
    </html>
  `
}

export const EmailService = {
  async sendVerificationEmail(to, token, userName = 'User') {
    const link = `${process.env.FRONTEND_URL}/verify-email/${token}`
    const mailOptions = {
      from: `"${process.env.APP_NAME || 'System'}" <${process.env.EMAIL_FROM}>`,
      to,
      subject: `Verify your email address - ${process.env.APP_NAME || ''}`,
      html: emailTemplates.verificationEmail(link, process.env.APP_NAME),
      text: `Welcome! Please verify your email by clicking this link: ${link}\n\nThis link will expire in 24 hours.\n\nIf you didn't create an account, please ignore this email.`
    }
    try {
      await transporter.sendMail(mailOptions)
      logger.info('Verification email sent', { to, type: 'verification' })
    } catch (err) {
      logger.error('Error sending verification email', { 
        error: err.message, 
        to,
        stack: err.stack 
      })
      throw new Error('Failed to send verification email')
    }
  },

  async sendPasswordResetEmail(to, token, userName = 'User') {
    const link = `${process.env.FRONTEND_URL}/reset-password/${token}`
    const mailOptions = {
      from: `"${process.env.APP_NAME || 'System'}" <${process.env.EMAIL_FROM}>`,
      to,
      subject: `Password Reset Request - ${process.env.APP_NAME || ''}`,
      html: emailTemplates.passwordResetEmail(link, process.env.APP_NAME),
      text: `To reset your password, click: ${link}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, please ignore this email.`
    }
    try {
      await transporter.sendMail(mailOptions)
      logger.info('Password reset email sent', { to, type: 'password_reset' })
    } catch (err) {
      logger.error('Error sending password reset email', { 
        error: err.message, 
        to,
        stack: err.stack 
      })
      throw new Error('Failed to send password reset email')
    }
  },

  async sendWelcomeEmail(to, userName) {
    const mailOptions = {
      from: `"${process.env.APP_NAME || 'Welcome Team'}" <${process.env.EMAIL_FROM}>`,
      to,
      subject: `Welcome to ${process.env.APP_NAME || 'our platform'}!`,
      html: emailTemplates.welcomeEmail(userName, process.env.APP_NAME),
      text: `Welcome ${userName} to ${process.env.APP_NAME || 'our platform'}!\n\nWe're excited to have you on board. Your account is now fully activated.\n\nStart exploring all the features we offer. If you need any assistance, please contact our support team.\n\nBest regards,\nThe ${process.env.APP_NAME || 'Platform'} Team`
    }
    try {
      await transporter.sendMail(mailOptions)
      logger.info('Welcome email sent', { to, type: 'welcome' })
    } catch (err) {
      logger.error('Error sending welcome email', { 
        error: err.message, 
        to,
        stack: err.stack 
      })
      // Note: Don't throw error for welcome email, as it's not critical
    }
  },

  async sendCustomEmail(to, subject, htmlContent, textContent) {
    const mailOptions = {
      from: `"${process.env.APP_NAME || 'System'}" <${process.env.EMAIL_FROM}>`,
      to,
      subject,
      html: htmlContent,
      text: textContent || htmlContent.replace(/<[^>]*>/g, '')
    }
    try {
      await transporter.sendMail(mailOptions)
      logger.info('Custom email sent', { to, subject })
      return true
    } catch (err) {
      logger.error('Error sending custom email', { 
        error: err.message, 
        to,
        subject,
        stack: err.stack 
      })
      throw new Error('Failed to send custom email')
    }
  }
}