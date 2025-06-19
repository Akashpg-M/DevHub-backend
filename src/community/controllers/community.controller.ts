import { Response, Request } from 'express';
import { PrismaClient, Prisma, CommunityRole } from '@prisma/client';
import { z } from 'zod';
import { AuthenticatedRequest } from '../../types/express';
import crypto from 'crypto';

// Validation schemas
const communityIdSchema = z.string().min(1);

const createCommunitySchema = z.object({
  name: z.string().min(3).max(50),
  description: z.string().min(10).max(500),
  isPrivate: z.boolean().optional(),
});

const updateCommunitySchema = z.object({
  name: z.string().min(3).max(50).optional(),
  description: z.string().min(10).max(500).optional(),
  isPrivate: z.boolean().optional(),
});

const updateMemberRoleSchema = z.object({
  userId: z.string(),
  role: z.string().transform(val => val.trim()).pipe(z.nativeEnum(CommunityRole)),
});


export class CommunityController {
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient();
    
    // Bind all methods to preserve 'this' context
    this.createCommunity = this.createCommunity.bind(this);
    this.getCommunities = this.getCommunities.bind(this);
    this.getCommunity = this.getCommunity.bind(this);
    this.updateCommunity = this.updateCommunity.bind(this);
    this.deleteCommunity = this.deleteCommunity.bind(this);
    this.joinCommunity = this.joinCommunity.bind(this);
    this.leaveCommunity = this.leaveCommunity.bind(this);
    this.updateMemberRole = this.updateMemberRole.bind(this);
    this.getCommunityMembers = this.getCommunityMembers.bind(this);
    this.generateInviteLink = this.generateInviteLink.bind(this);
    this.getUserCommunities = this.getUserCommunities.bind(this);
  }

  // Controller Methods
  async createCommunity(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const validatedData = createCommunitySchema.parse(req.body);
      const userId = req.user.id;

      const community = await this.prisma.$transaction(async (tx) => {
        return await tx.community.create({
          data: {
            name: validatedData.name,
            description: validatedData.description,
            isPrivate: validatedData.isPrivate ?? false,
            createdBy: userId,
            communityMembers: {
              create: {
                userId: userId,
                role: 'OWNER',
              },
            },
          },
          include: {
            communityMembers: {
              include: {
                user: {
                  select: {
                    id: true,
                    name: true,
                    email: true,
                    profilePicture: true,
                  },
                },
              },
            },
          },
        });
      });

      return res.status(201).json(community);
    } catch (error) {
      console.log('Error in createCommunity:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        return res.status(400).json({ error: 'Database error occurred' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getCommunities(req: Request & { query: any }, res: Response): Promise<Response> {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const search = req.query.search as string;
      const sortBy = (req.query.sortBy as 'name' | 'createdAt' | 'memberCount') || 'createdAt';
      const sortOrder = (req.query.sortOrder as 'asc' | 'desc') || 'desc';

      const skip = (page - 1) * limit;
      const where = search
        ? {
            OR: [
              { name: { contains: search, mode: Prisma.QueryMode.insensitive } },
              { description: { contains: search, mode: Prisma.QueryMode.insensitive } },
            ],
          }
        : {};

      const order = { [sortBy]: sortOrder };

      const [communities, total] = await Promise.all([
        this.prisma.community.findMany({
          where,
          skip,
          take: limit,
          orderBy: order,
          include: {
            _count: {
              select: { communityMembers: true },
            },
          },
        }),
        this.prisma.community.count({ where }),
      ]);

      return res.json({
        communities,
        total,
        page,
        totalPages: Math.ceil(total / limit),
      });
    } catch (error) {
      console.log('Error in getCommunities:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getCommunity(req: Request & { params: { communityId: string } }, res: Response): Promise<Response> {
    try {
      const id = communityIdSchema.parse(req.params.communityId);
      
      const community = await this.prisma.community.findUnique({
        where: { id },
        include: {
          communityMembers: {
            include: {
              user: {
                select: {
                  id: true,
                  name: true,
                  email: true,
                  profilePicture: true,
                },
              },
            },
          },
          _count: {
            select: { communityMembers: true },
          },
        },
      });

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      return res.json({
        ...community,
        memberCount: community._count.communityMembers,
      });
    } catch (error) {
      console.log('Error in getCommunity:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: 'Invalid community ID' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async updateCommunity(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      
      const id = communityIdSchema.parse(req.params.communityId);
      const updates = updateCommunitySchema.parse(req.body);
      const userId = req.user.id;

      const isAdmin = await this.isUserAdminOrOwner(id, userId);
      if (!isAdmin) {
        return res.status(403).json({ error: 'Only admins can update community details' });
      }

      const community = await this.prisma.community.update({
        where: { id },
        data: updates,
        include: {
          communityMembers: {
            include: {
              user: {
                select: {
                  id: true,
                  name: true,
                  email: true,
                  profilePicture: true,
                },
              },
            },
          },
        },
      });

      return res.json(community);
    } catch (error) {
      console.log('Error in updateCommunity:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        return res.status(400).json({ error: 'Database error occurred' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async deleteCommunity(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      
      const id = communityIdSchema.parse(req.params.communityId);
      const userId = req.user.id;

      const isAdmin = await this.isUserAdminOrOwner(id, userId);
      if (!isAdmin) {
        return res.status(403).json({ error: 'Only admins can delete the community' });
      }

      await this.prisma.$transaction([
        this.prisma.communityMember.deleteMany({ where: { communityId: id } }),
        this.prisma.communityInvite.deleteMany({ where: { communityId: id } }),
        this.prisma.community.delete({ where: { id } }),
      ]);

      return res.status(204).send();
    } catch (error) {
      console.log('Error in deleteCommunity:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: 'Invalid community ID' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async joinCommunity(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      
      const communityId = communityIdSchema.parse(req.params.communityId);
      const userId = req.user.id;

      const community = await this.prisma.community.findUnique({
        where: { id: communityId },
      });

      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      if (community.isPrivate) {
        return res.status(403).json({ error: 'Cannot join private community without invite' });
      }

      const membership = await this.prisma.communityMember.create({
        data: { communityId, userId, role: 'VIEWER' },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              profilePicture: true,
            },
          },
        },
      });

      return res.status(201).json(membership);
    } catch (error) {
      console.log('Error in joinCommunity:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: 'Invalid community ID' });
      }
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          return res.status(400).json({ error: 'Already a member of this community' });
        }
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async leaveCommunity(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      
      const communityId = communityIdSchema.parse(req.params.communityId);
      const userId = req.user.id;

      const community = await this.prisma.community.findUnique({ 
        where: { id: communityId } 
      });
      
      if (!community) {
        return res.status(404).json({ error: 'Community not found' });
      }

      const membership = await this.prisma.communityMember.findUnique({
        where: {
          communityId_userId: {
            userId,
            communityId,
          },
        },
      });

      if (!membership) {
        return res.status(400).json({ error: 'You are not a member of this community' });
      }

      // If the leaving member is the owner, delete the entire community
      if (membership.role === 'OWNER') {
        await this.prisma.$transaction([
          this.prisma.communityMember.deleteMany({ where: { communityId } }),
          this.prisma.communityInvite.deleteMany({ where: { communityId } }),
          this.prisma.community.delete({ where: { id: communityId } }),
        ]);
        return res.status(200).json({ message: 'Community deleted as owner left' });
      }

      // Check if user is the last admin
      if (membership.role === 'ADMIN') {
        const adminCount = await this.prisma.communityMember.count({
          where: { communityId, role: 'ADMIN' },
        });
        if (adminCount <= 1) {
          return res.status(400).json({ error: 'Cannot leave as the last admin' });
        }
      }

      // For other roles, just remove the member
      await this.prisma.communityMember.delete({
        where: {
          communityId_userId: {
            userId,
            communityId,
          },
        },
      });

      // Check if this was the last member and delete community if so
      const remaining = await this.prisma.communityMember.count({ 
        where: { communityId } 
      });
      
      if (remaining === 0) {
        await this.prisma.$transaction([
          this.prisma.communityInvite.deleteMany({ where: { communityId } }),
          this.prisma.community.delete({ where: { id: communityId } }),
        ]);
      }

      return res.status(200).json({ message: 'Left the community successfully' });
    } catch (error) {
      console.log('Error in leaveCommunity:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: 'Invalid community ID' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async updateMemberRole(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const communityId = communityIdSchema.parse(req.params.communityId);
      const { userId, role } = updateMemberRoleSchema.parse(req.body);
      const requesterId = req.user.id;

      const isAdmin = await this.isUserAdminOrOwner(communityId, requesterId);
      if (!isAdmin) {
        return res.status(403).json({ error: 'Only admins can change roles' });
      }

      const updatedMember = await this.prisma.$transaction(async (tx) => {
        const member = await tx.communityMember.findUnique({
          where: { communityId_userId: { communityId, userId } },
        });

        if (!member) {
          throw new Error('User is not a member of this community');
        }

        if (member.role === 'ADMIN' && role !== 'ADMIN') {
          const adminCount = await tx.communityMember.count({
            where: { communityId, role: 'ADMIN' },
          });
          if (adminCount <= 1) {
            throw new Error('Cannot demote the last admin');
          }
        }

        return await tx.communityMember.update({
          where: { communityId_userId: { communityId, userId } },
          data: { role },
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                profilePicture: true,
              },
            },
          },
        });
      });

      return res.status(200).json(updatedMember);
    } catch (error) {
      console.error('Error in updateMemberRole:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      return res.status(400).json({ error: error.message || 'Internal server error' });
    }
  }

  async getCommunityMembers(
    req: Request & { params: { communityId: string }, query: any }, 
    res: Response
  ): Promise<Response> {
    try {
      const id = communityIdSchema.parse(req.params.communityId);
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;

      const members = await this.prisma.communityMember.findMany({
        where: { communityId: id },
        include: {
          user: {
            select: { 
              id: true, 
              name: true, 
              email: true, 
              profilePicture: true 
            }
          }
        },
        skip: (page - 1) * limit,
        take: limit,
      });

      return res.json({ status: 'success', data: members });
    } catch (error) {
      console.error('Error in getCommunityMembers:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ status: 'error', error: { message: 'Invalid community ID' } });
      }
      return res.status(500).json({ status: 'error', error: { message: 'Internal server error' } });
    }
  }

  async generateInviteLink(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      
      const communityId = communityIdSchema.parse(req.params.communityId);
      const userId = req.user.id;

      const isAdmin = await this.isUserAdminOrOwner(communityId, userId);
      if (!isAdmin) {
        return res.status(403).json({ error: 'Only admins can generate invite links' });
      }

      const code = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await this.prisma.communityInvite.create({
        data: { code, communityId, userId, expiresAt },
      });

      const inviteLink = `${process.env.FRONTEND_URL}/join-community/${code}`;
      return res.json({ inviteLink });
    } catch (error) {
      console.error('Error in generateInviteLink:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: 'Invalid community ID' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getUserCommunities(req: AuthenticatedRequest, res: Response): Promise<Response> {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const search = req.query.search as string;
      const sortBy = (req.query.sortBy as 'name' | 'createdAt' | 'memberCount') || 'createdAt';
      const sortOrder = (req.query.sortOrder as 'asc' | 'desc') || 'desc';
      const userId = req.user.id;

      const skip = (page - 1) * limit;
      const where = {
        communityMembers: { some: { userId } },
        ...(search
          ? {
              OR: [
                { name: { contains: search, mode: Prisma.QueryMode.insensitive } },
                { description: { contains: search, mode: Prisma.QueryMode.insensitive } },
              ],
            }
          : {}),
      };

      const order = { [sortBy]: sortOrder };

      const [communities, total] = await Promise.all([
        this.prisma.community.findMany({
          where,
          skip,
          take: limit,
          orderBy: order,
          include: {
            _count: { select: { communityMembers: true } },
            communityMembers: { 
              where: { userId }, 
              select: { role: true } 
            },
          },
        }),
        this.prisma.community.count({ where }),
      ]);

      return res.json({
        communities,
        total,
        page,
        totalPages: Math.ceil(total / limit),
      });
    } catch (error) {
      console.error('Error in getUserCommunities:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  private async isUserAdminOrOwner(communityId: string, userId: string): Promise<boolean> {
    try {
      const member = await this.prisma.communityMember.findUnique({
        where: { communityId_userId: { communityId, userId } },
      });
      return member?.role === 'ADMIN' || member?.role === 'OWNER';
    } catch (error) {
      console.error('Error in isUserAdminOrOwner:', error);
      return false;
    }
  }
}

export default new CommunityController();
