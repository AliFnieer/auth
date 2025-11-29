import prisma from '../lib/prisma.js'
import bcrypt from 'bcryptjs'

export class UserModel {
  static async create(userData) {
    const hashedPassword = await bcrypt.hash(userData.password, 12)
    
    return await prisma.user.create({
      data: {
        ...userData,
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
  }

  static async findByEmail(email) {
    return await prisma.user.findUnique({
      where: { email }
    })
  }

  static async findById(id) {
    return await prisma.user.findUnique({
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
  }

  static async update(id, data) {
    return await prisma.user.update({
      where: { id },
      data,
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
  }

  static async verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword)
  }
}