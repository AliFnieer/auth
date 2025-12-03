import prisma from '../lib/prisma.js'
import * as bcrypt from 'bcryptjs'
import { sanitizeInput } from '../utils/validation.js'

export class UserModel {
  static async create(userData) {
    // sanitize fields except password
    const clean = {
      ...userData,
      email: userData.email ? sanitizeInput(userData.email) : userData.email,
      firstName: userData.firstName ? sanitizeInput(userData.firstName) : userData.firstName,
      lastName: userData.lastName ? sanitizeInput(userData.lastName) : userData.lastName,
      phone: userData.phone ? sanitizeInput(userData.phone) : userData.phone
    }

    const hashedPassword = await bcrypt.hash(clean.password, 12)
    
    return await prisma.user.create({
      data: {
        ...clean,
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
    // sanitize update fields and ensure sanitized values take precedence
    const clean = {
      ...data,
      ...(data.firstName ? { firstName: sanitizeInput(data.firstName) } : {}),
      ...(data.lastName ? { lastName: sanitizeInput(data.lastName) } : {}),
      ...(data.phone ? { phone: sanitizeInput(data.phone) } : {})
    }

    return await prisma.user.update({
      where: { id },
      data: clean,
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