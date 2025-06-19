import { Request, Response } from "express";
import { z } from "zod";
import { PrismaClient, Prisma } from '@prisma/client';
import { Permissions } from '../utils/communityManagement';
import { roleGuard } from '../utils/communityManagement';

const prisma = new PrismaClient();

// Validation schemas
const communityIdSchema = z.object({
  communityId: z.string().min(1),
});

const projectIdSchema = communityIdSchema.extend({
  projectId: z.string().min(1),
});

const createProjectSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  emoji: z.string().optional(),
});

const updateProjectSchema = createProjectSchema.partial();

// Helper function to check community membership
const checkCommunityMembership = async (userId: string, communityId: string) => {
  const member = await prisma.communityMember.findFirst({
    where: { communityId, userId },
  });
  if (!member) {
    throw new Error('You are not a member of this community');
  }
  return member;
};

export class ProjectController {
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient();

    // Bind all methods to preserve 'this' context
    this.createProject = this.createProject.bind(this);
    this.getProjectsInCommunity = this.getProjectsInCommunity.bind(this);
    this.getProjectByIdAndCommunityId = this.getProjectByIdAndCommunityId.bind(this);
    this.getProjectAnalytics = this.getProjectAnalytics.bind(this);
    this.joinProject = this.joinProject.bind(this);
    this.leaveProject = this.leaveProject.bind(this);
    this.getProjectMembers = this.getProjectMembers.bind(this);
    this.updateProject = this.updateProject.bind(this);
    this.deleteProject = this.deleteProject.bind(this);
  }

  // Project Methods
  async createProject(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId } = communityIdSchema.parse(req.params);
      const body = createProjectSchema.parse(req.body);
      const userId = (req as any).user.id;

      // Check permissions
      const member = await checkCommunityMembership(userId, communityId);
      roleGuard(member.role, [Permissions.CREATE_PROJECT]);

      const project = await this.prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        // Create the project
        const project = await tx.project.create({
          data: {
            name: body.name,
            description: body.description,
            emoji: body.emoji,
            communityId,
            createdById: userId,
          },
          include: {
            createdBy: {
              select: {
                id: true,
                name: true,
                profilePicture: true,
              },
            },
            members: {
              select: {
                id: true,
                user: {
                  select: {
                    id: true,
                    name: true,
                    profilePicture: true,
                  },
                },
              },
            },
          },
        });

        // Add creator as project member
        await tx.projectMember.create({
          data: {
            projectId: project.id,
            userId: userId,
          },
        });

        return project;
      });

      return res.status(201).json(project);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async getProjectsInCommunity(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId } = communityIdSchema.parse(req.params);
      const userId = (req as any).user.id;

      // Check community membership
      await checkCommunityMembership(userId, communityId);

      const pageSize = Number(req.query.pageSize) || 10;
      const pageNumber = Number(req.query.pageNumber) || 1;
      const skip = (pageNumber - 1) * pageSize;

      const [total, projects] = await Promise.all([
        this.prisma.project.count({
          where: { communityId },
        }),
        this.prisma.project.findMany({
          where: { communityId },
          skip,
          take: pageSize,
          include: {
            createdBy: {
              select: {
                id: true,
                name: true,
                profilePicture: true,
              },
            },
            members: {
              select: {
                id: true,
                user: {
                  select: {
                    id: true,
                    name: true,
                    profilePicture: true,
                  },
                },
              },
            },
          },
          orderBy: { createdAt: 'desc' },
        }),
      ]);

      return res.json({
        projects,
        total,
        pageNumber,
        totalPages: Math.ceil(total / pageSize),
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async getProjectByIdAndCommunityId(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId, projectId } = projectIdSchema.parse(req.params);
      const userId = (req as any).user.id;

      // Check community membership
      await checkCommunityMembership(userId, communityId);

      const project = await this.prisma.project.findFirst({
        where: { id: projectId, communityId },
        include: {
          createdBy: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          members: {
            select: {
              id: true,
              user: {
                select: {
                  id: true,
                  name: true,
                  profilePicture: true,
                },
              },
            },
          },
        },
      });

      if (!project) {
        throw new Error('Project not found');
      }

      return res.json(project);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async getProjectAnalytics(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId, projectId } = projectIdSchema.parse(req.params);
      const userId = (req as any).user.id;

      // Check community membership
      await checkCommunityMembership(userId, communityId);

      const project = await this.prisma.project.findFirst({
        where: { id: projectId, communityId },
        include: {
          members: {
            select: {
              id: true,
              user: {
                select: {
                  id: true,
                  name: true,
                  profilePicture: true,
                },
              },
            },
          },
        },
      });

      if (!project) {
        throw new Error('Project not found');
      }

      return res.json({
        totalMembers: project.members.length,
        members: project.members,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async joinProject(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId, projectId } = projectIdSchema.parse(req.params);
      const userId = (req as any).user.id;

      // Check community membership
      await checkCommunityMembership(userId, communityId);

      const result = await this.prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        // Check if project exists and belongs to the community
        const project = await tx.project.findFirst({
          where: { id: projectId, communityId },
        });

        if (!project) {
          throw new Error('Project not found');
        }

        // Check if user is already a member
        const existingMember = await tx.projectMember.findUnique({
          where: {
            projectId_userId: {
              projectId,
              userId,
            },
          },
        });

        if (existingMember) {
          throw new Error('User is already a member of this project');
        }

        // Add user to project
        const member = await tx.projectMember.create({
          data: {
            projectId,
            userId,
          },
          include: {
            user: {
              select: {
                id: true,
                name: true,
                profilePicture: true,
              },
            },
          },
        });

        return member;
      });

      return res.status(201).json(result);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async leaveProject(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId, projectId } = projectIdSchema.parse(req.params);
      const userId = (req as any).user.id;

      // Check community membership
      await checkCommunityMembership(userId, communityId);

      const result = await this.prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        // Check if project exists and belongs to the community
        const project = await tx.project.findFirst({
          where: { id: projectId, communityId },
        });

        if (!project) {
          throw new Error('Project not found');
        }

        // Check if user is a member
        const member = await tx.projectMember.findUnique({
          where: {
            projectId_userId: {
              projectId,
              userId,
            },
          },
        });

        if (!member) {
          throw new Error('User is not a member of this project');
        }

        // Remove user from project
        await tx.projectMember.delete({
          where: {
            projectId_userId: {
              projectId,
              userId,
            },
          },
        });

        return { success: true, message: 'Successfully left the project' };
      });

      return res.json(result);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async getProjectMembers(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId, projectId } = projectIdSchema.parse(req.params);
      const userId = (req as any).user.id;
      const pageSize = Number(req.query.pageSize) || 10;
      const pageNumber = Number(req.query.pageNumber) || 1;
      const skip = (pageNumber - 1) * pageSize;

      // Check community membership
      await checkCommunityMembership(userId, communityId);

      // Check if project exists and belongs to the community
      const project = await this.prisma.project.findFirst({
        where: { id: projectId, communityId },
      });

      if (!project) {
        throw new Error('Project not found');
      }

      const [total, members] = await Promise.all([
        this.prisma.projectMember.count({
          where: { projectId },
        }),
        this.prisma.projectMember.findMany({
          where: { projectId },
          skip,
          take: pageSize,
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
        }),
      ]);

      return res.json({
        members: members.map((m) => ({
          id: m.user.id,
          name: m.user.name,
          email: m.user.email,
          profilePicture: m.user.profilePicture,
          joinedAt: m.joinedAt
        })),
        total,
        pageNumber,
        totalPages: Math.ceil(total / pageSize),
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async updateProject(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId, projectId } = projectIdSchema.parse(req.params);
      const userId = (req as any).user.id;
      const data = updateProjectSchema.parse(req.body);

      // Check permissions
      const member = await checkCommunityMembership(userId, communityId);
      roleGuard(member.role, [Permissions.EDIT_PROJECT]);

      // Check if project exists and belongs to the community
      const project = await this.prisma.project.findFirst({
        where: { id: projectId, communityId },
      });

      if (!project) {
        throw new Error('Project not found');
      }

      // Only project creator or community admin/owner can update
      if (project.createdById !== userId && member.role !== 'ADMIN' && member.role !== 'OWNER') {
        throw new Error('Only the project creator or community admin can update this project');
      }

      const updatedProject = await this.prisma.project.update({
        where: { id: projectId },
        data: {
          name: data.name,
          description: data.description,
          emoji: data.emoji,
        },
        include: {
          createdBy: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          members: {
            select: {
              id: true,
              user: {
                select: {
                  id: true,
                  name: true,
                  profilePicture: true,
                },
              },
            },
          },
        },
      });

      return res.json(updatedProject);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
  
  async deleteProject(req: Request, res: Response): Promise<Response> {
    try {
      const { communityId, projectId } = projectIdSchema.parse(req.params);
      const userId = (req as any).user.id;

      // Check permissions
      const member = await checkCommunityMembership(userId, communityId);
      roleGuard(member.role, [Permissions.DELETE_PROJECT]);

      // Check if project exists and belongs to the community
      const project = await this.prisma.project.findFirst({
        where: { id: projectId, communityId },
      });

      if (!project) {
        throw new Error('Project not found');
      }

      // Only project creator or community admin/owner can delete
      if (project.createdById !== userId && member.role !== 'ADMIN' && member.role !== 'OWNER') {
        throw new Error('Only the project creator or community admin can delete this project');
      }

      await this.prisma.$transaction([
        this.prisma.projectMember.deleteMany({
          where: { projectId },
        }),
        this.prisma.task.updateMany({
          where: { projectId },
          data: { projectId: null },
        }),
        this.prisma.project.delete({
          where: { id: projectId },
        }),
      ]);

      return res.status(204).send();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error.message === 'You are not a member of this community') {
        return res.status(403).json({ error: error.message });
      }
      if (error.message.includes('not found')) {
        return res.status(404).json({ error: error.message });
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  }
}

export default new ProjectController();
