import prisma from '../lib/prisma.js'
import * as crypto from 'crypto'

export class TokenModel {
  static generateToken() {
    return crypto.randomBytes(32).toString('hex')
  }

  static async createRefreshToken(userId, userAgent, ipAddress) {
    const token = this.generateToken()
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days

    return await prisma.refreshToken.create({
      data: {
        token,
        userId,
        expiresAt,
        userAgent,
        ipAddress
      }
    })
  }

  static async findRefreshToken(token) {
    return await prisma.refreshToken.findFirst({
      where: { 
        token,
        isRevoked: false,
        expiresAt: { gt: new Date() }
      },
      include: { user: true }
    })
  }

  // Find a refresh token record regardless of revoked/expired state
  static async findRefreshTokenByToken(token) {
    return await prisma.refreshToken.findUnique({
      where: { token },
      include: { user: true }
    })
  }

  static async revokeRefreshToken(token) {
    return await prisma.refreshToken.updateMany({
      where: { token },
      data: { isRevoked: true }
    })
  }

  static async revokeAllUserTokens(userId) {
    return await prisma.refreshToken.updateMany({
      where: { 
        userId,
        isRevoked: false 
      },
      data: { isRevoked: true }
    })
  }

  static async createVerificationToken(userId) {
    const token = this.generateToken()
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours

    return await prisma.verificationToken.create({
      data: {
        token,
        userId,
        expiresAt
      }
    })
  }

  static async findVerificationToken(token) {
    return await prisma.verificationToken.findFirst({
      where: { 
        token,
        expiresAt: { gt: new Date() }
      },
      include: { user: true }
    })
  }

  static async deleteVerificationToken(token) {
    return await prisma.verificationToken.delete({
      where: { token }
    })
  }

  static async createPasswordResetToken(userId) {
    const token = this.generateToken()
    const expiresAt = new Date(Date.now() + 1 * 60 * 60 * 1000) // 1 hour

    return await prisma.passwordResetToken.create({
      data: {
        token,
        userId,
        expiresAt
      }
    })
  }

  static async findPasswordResetToken(token) {
    return await prisma.passwordResetToken.findFirst({
      where: { 
        token,
        expiresAt: { gt: new Date() },
        usedAt: null
      },
      include: { user: true }
    })
  }

  static async markPasswordResetTokenUsed(token) {
    return await prisma.passwordResetToken.update({
      where: { token },
      data: { usedAt: new Date() }
    })
  }
}