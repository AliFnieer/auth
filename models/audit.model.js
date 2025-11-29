import prisma from '../lib/prisma.js'

export class AuditLogModel {
  static async create(auditData) {
    return await prisma.auditLog.create({
      data: auditData
    })
  }

  static async findByUserId(userId, page = 1, limit = 10) {
    const skip = (page - 1) * limit

    return await prisma.auditLog.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true
          }
        }
      }
    })
  }

  static async getLoginHistory(userId, page = 1, limit = 10) {
    const skip = (page - 1) * limit

    return await prisma.loginHistory.findMany({
      where: { userId },
      orderBy: { loginAt: 'desc' },
      skip,
      take: limit
    })
  }
}