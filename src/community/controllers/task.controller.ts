import { Response } from 'express';
import { AuthenticatedRequest } from '../..//types/express';
import { z } from 'zod';
import { PrismaClient, TaskPriority, TaskStatus, Prisma } from '@prisma/client';
import { roleGuard, NotFoundException, UnauthorizedException, Permissions } from '../utils/communityManagement';

// Custom error classes
class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

// Validation schemas
const taskIdSchema = z.string().min(1);
const communityIdSchema = z.string().min(1);

// Define the input schema with string dates
export const createTaskSchema = z.object({
  title: z.string().min(1, 'Title is required'),
  description: z.string().optional(),
  priority: z.nativeEnum(TaskPriority).optional(),
  status: z.nativeEnum(TaskStatus).optional(),
  assignedTo: z.string().uuid('Invalid user ID').optional().nullable(),
  dueDate: z.string().datetime('Invalid date format').optional(),
  projectId: z.string().uuid('Invalid project ID').optional().nullable()
});

export const updateTaskSchema = createTaskSchema.partial();

// Define the type for the parsed input
type CreateTaskInput = z.infer<typeof createTaskSchema>;

// Define the service input type
interface TaskServiceInput {
  title: string;
  description?: string;
  priority?: TaskPriority;
  status?: TaskStatus;
  assignedTo: string | null;
  projectId: string | null;
  dueDate?: Date;
}

export class TaskController {
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient();
  }

  // Helper function to convert input to service input
  private toTaskServiceInput(input: CreateTaskInput): TaskServiceInput {
    const result: TaskServiceInput = {
      title: input.title,
      description: input.description,
      priority: input.priority,
      status: input.status,
      assignedTo: input.assignedTo || null,
      projectId: input.projectId || null
    };
    
    if (input.dueDate) {
      result.dueDate = new Date(input.dueDate);
    }
    
    return result;
  }

  // Helper function to get member role in community
  private async getMemberRoleInWorkspace(userId: string, communityId: string) {
    const member = await this.prisma.communityMember.findFirst({
      where: { communityId, userId },
    });
    if (!member) {
      throw new NotFoundException('You are not a member of this community');
    }
    return member;
  }

  // Task Methods
  async assignTask(req: AuthenticatedRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const { taskId } = req.params;
      const { assignedTo } = req.body;
      const communityId = communityIdSchema.parse(req.params.communityId);

      // Verify task exists and belongs to the community
      const task = await this.prisma.task.findUnique({
        where: { id: taskId },
        include: { community: true }
      });

      if (!task) {
        throw new NotFoundError('Task not found');
      }

      if (task.communityId !== communityId) {
        throw new UnauthorizedException('Task does not belong to this community');
      }

      // Verify the user has permission to assign tasks
      const { role } = await this.getMemberRoleInWorkspace(userId, communityId);
      roleGuard(role, [Permissions.ASSIGN_TASK]);

      // If assigning to someone, verify they are a community member
      if (assignedTo) {
        const isAssignedUserMember = await this.prisma.communityMember.findFirst({
          where: { userId: assignedTo, communityId },
        });

        if (!isAssignedUserMember) {
          throw new NotFoundError('Assigned user is not a member of this community');
        }
      }

      // Update the task assignment
      const updatedTask = await this.prisma.task.update({
        where: { id: taskId },
        data: {
          assignedToId: assignedTo || null,
        },
        include: {
          assignedTo: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
        },
      });

      return res.status(200).json({
        success: true,
        message: 'Task assignment updated successfully',
        data: { task: updatedTask },
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          success: false,
          error: 'Validation error',
          details: error.errors 
        });
      }
      if (error instanceof NotFoundException || error instanceof NotFoundError) {
        return res.status(404).json({ 
          success: false,
          error: error.message 
        });
      }
      if (error instanceof UnauthorizedException) {
        return res.status(403).json({ 
          success: false,
          error: error.message 
        });
      }
      console.error('Error assigning task:', error);
      return res.status(500).json({ 
        success: false,
        error: 'Failed to assign task' 
      });
    }
  }

  async createTask(req: AuthenticatedRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      // Parse and validate the request body
      const parsedBody = createTaskSchema.parse(req.body);
      const communityId = communityIdSchema.parse(req.params.communityId);

      const { role } = await this.getMemberRoleInWorkspace(userId, communityId);
      roleGuard(role, [Permissions.CREATE_TASK]);

      // Convert to service input format
      const taskData = this.toTaskServiceInput(parsedBody);
      const { title, description, priority, status, assignedTo, dueDate, projectId } = taskData;

      // Verify community exists
      const community = await this.prisma.community.findUnique({
        where: { id: communityId },
      });

      if (!community) {
        throw new NotFoundError('Community not found');
      }

      // If projectId is provided, verify it belongs to the community
      if (projectId) {
        const project = await this.prisma.project.findFirst({
          where: { id: projectId, communityId },
        });

        if (!project) {
          throw new NotFoundError('Project not found or does not belong to this community');
        }
      }

      // If assigning to someone, verify they are a community member
      if (assignedTo) {
        const isAssignedUserMember = await this.prisma.communityMember.findFirst({
          where: { userId: assignedTo, communityId },
        });

        if (!isAssignedUserMember) {
          throw new NotFoundError('Assigned user is not a member of this community');
        }
      }

      const task = await this.prisma.task.create({
        data: {
          title,
          description,
          priority: priority || TaskPriority.MEDIUM,
          status: status || TaskStatus.TODO,
          assignedToId: assignedTo || null,
          createdById: userId,
          communityId,
          projectId: projectId || null,
          dueDate: dueDate,
        },
        include: {
          createdBy: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          assignedTo: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          project: projectId ? {
            select: {
              id: true,
              name: true,
              emoji: true,
            },
          } : undefined,
        },
      });

      return res.status(201).json({
        success: true,
        message: "Task created successfully",
        data: { task },
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          success: false,
          error: 'Validation error',
          details: error.errors 
        });
      }
      if (error instanceof NotFoundException || error instanceof NotFoundError) {
        return res.status(404).json({ 
          success: false,
          error: error.message 
        });
      }
      if (error instanceof UnauthorizedException) {
        return res.status(403).json({ 
          success: false,
          error: error.message 
        });
      }
      console.error('Error creating task:', error);
      return res.status(500).json({ 
        success: false,
        error: 'Failed to create task' 
      });
    }
  }

  async updateTask(req: AuthenticatedRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const rawBody = updateTaskSchema.parse(req.body);
      const taskId = taskIdSchema.parse(req.params.taskId);
      const communityId = communityIdSchema.parse(req.params.communityId);

      // const { role } = await this.getMemberRoleInWorkspace(userId, communityId);
      // roleGuard(role, [Permissions.EDIT_TASK]);

      const task = await this.prisma.task.findFirst({
        where: { id: taskId, communityId },
      });

      if (!task) {
        throw new NotFoundError("Task not found or does not belong to this community");
      }

      // If projectId is being updated, verify it belongs to the community
      if (rawBody.projectId) {
        const project = await this.prisma.project.findFirst({
          where: { id: rawBody.projectId, communityId },
        });

        if (!project) {
          throw new NotFoundError("Project not found or does not belong to this community");
        }
      }

      // If assigning to someone, verify they are a community member
      if (rawBody.assignedTo) {
        const isAssignedUserMember = await this.prisma.communityMember.findFirst({
          where: { userId: rawBody.assignedTo, communityId },
        });

        if (!isAssignedUserMember) {
          throw new NotFoundError("Assigned user is not a member of this community");
        }
      }

      const updatedTask = await this.prisma.task.update({
        where: { id: taskId },
        data: {
          title: rawBody.title,
          description: rawBody.description,
          priority: rawBody.priority,
          status: rawBody.status,
          assignedToId: rawBody.assignedTo,
          dueDate: rawBody.dueDate ? new Date(rawBody.dueDate) : undefined,
          projectId: rawBody.projectId,
        },
        include: {
          createdBy: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          assignedTo: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          project: rawBody.projectId ? {
            select: {
              id: true,
              name: true,
              emoji: true,
            },
          } : undefined,
        },
      });

      return res.status(200).json({
        message: "Task updated successfully",
        task: updatedTask,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error instanceof NotFoundError) {
        return res.status(404).json({ error: error.message });
      }
      if (error instanceof UnauthorizedException) {
        return res.status(403).json({ error: error.message });
      }
      console.error('Error updating task:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getAllTasks(req: AuthenticatedRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const communityId = communityIdSchema.parse(req.params.communityId);

      // Check community membership
      await this.getMemberRoleInWorkspace(userId, communityId);

      const filters = {
        projectId: req.query.projectId as string | undefined,
        status: req.query.status
          ? (req.query.status as string)?.split(",") as TaskStatus[]
          : undefined,
        priority: req.query.priority
          ? (req.query.priority as string)?.split(",") as TaskPriority[]
          : undefined,
        assignedTo: req.query.assignedTo
          ? (req.query.assignedTo as string)?.split(",")
          : undefined,
        keyword: req.query.keyword as string | undefined,
        dueDate: req.query.dueDate ? new Date(req.query.dueDate as string) : undefined,
      };

      const pagination = {
        pageSize: Number(req.query.pageSize) || 10,
        pageNumber: Number(req.query.pageNumber) || 1,
      };

      const where: Prisma.TaskWhereInput = {
        communityId,
        ...(filters.projectId && { projectId: filters.projectId }),
        ...(filters.status && { status: { in: filters.status } }),
        ...(filters.priority && { priority: { in: filters.priority } }),
        ...(filters.assignedTo && { assignedToId: { in: filters.assignedTo } }),
        ...(filters.keyword && {
          OR: [
            { title: { contains: filters.keyword, mode: 'insensitive' } },
            { description: { contains: filters.keyword, mode: 'insensitive' } },
          ],
        }),
        ...(filters.dueDate && {
          dueDate: {
            gte: new Date(filters.dueDate.setHours(0, 0, 0, 0)),
            lt: new Date(filters.dueDate.setHours(23, 59, 59, 999)),
          },
        }),
      };

      const [total, tasks] = await Promise.all([
        this.prisma.task.count({ where }),
        this.prisma.task.findMany({
          where,
          skip: (pagination.pageNumber - 1) * pagination.pageSize,
          take: pagination.pageSize,
          include: {
            createdBy: {
              select: {
                id: true,
                name: true,
                profilePicture: true,
              },
            },
            assignedTo: {
              select: {
                id: true,
                name: true,
                profilePicture: true,
              },
            },
            project: {
              select: {
                id: true,
                name: true,
                emoji: true,
              },
            },
          },
          orderBy: { createdAt: 'desc' },
        }),
      ]);

      return res.json({
        tasks,
        total,
        pageNumber: pagination.pageNumber,
        totalPages: Math.ceil(total / pagination.pageSize),
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error instanceof NotFoundException) {
        return res.status(404).json({ error: error.message });
      }
      if (error instanceof UnauthorizedException) {
        return res.status(403).json({ error: error.message });
      }
      console.error('Error getting tasks:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async getTaskById(req: AuthenticatedRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const taskId = taskIdSchema.parse(req.params.taskId);
      const communityId = communityIdSchema.parse(req.params.communityId);

      // Check community membership
      await this.getMemberRoleInWorkspace(userId, communityId);

      const task = await this.prisma.task.findFirst({
        where: { id: taskId, communityId },
        include: {
          createdBy: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          assignedTo: {
            select: {
              id: true,
              name: true,
              profilePicture: true,
            },
          },
          project: {
            select: {
              id: true,
              name: true,
              emoji: true,
            },
          },
        },
      });

      if (!task) {
        throw new NotFoundError('Task not found');
      }

      return res.json(task);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error instanceof NotFoundException || error instanceof NotFoundError) {
        return res.status(404).json({ error: error.message });
      }
      if (error instanceof UnauthorizedException) {
        return res.status(403).json({ error: error.message });
      }
      console.error('Error getting task:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async deleteTask(req: AuthenticatedRequest, res: Response) {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const taskId = taskIdSchema.parse(req.params.taskId);
      const communityId = communityIdSchema.parse(req.params.communityId);

      // Check permissions
      // const { role } = await this.getMemberRoleInWorkspace(userId, communityId);
      // roleGuard(role, [Permissions.DELETE_TASK]);

      // Check if task exists and belongs to the community
      const task = await this.prisma.task.findFirst({
        where: { id: taskId, communityId },
      });

      if (!task) {
        throw new NotFoundError('Task not found');
      }

      // Only task creator or community admin can delete
      // if (task.createdById !== userId && role !== 'ADMIN' && role !== 'OWNER') {
      //   throw new UnauthorizedException('Only the task creator or admin can delete this task');
      // }

      await this.prisma.task.delete({
        where: { id: taskId },
      });

      return res.status(204).send();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      if (error instanceof NotFoundException || error instanceof NotFoundError) {
        return res.status(404).json({ error: error.message });
      }
      if (error instanceof UnauthorizedException) {
        return res.status(403).json({ error: error.message });
      }
      console.error('Error deleting task:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  async updateTaskStatus(req: AuthenticatedRequest, res: Response) {
    try {
      const { taskId, communityId } = req.params;
      const { status } = req.body;
      // const userId = req.user?.id;
  
      // Validate input
      if (!Object.values(TaskStatus).includes(status)) {
        return res.status(400).json({ message: 'Invalid status value' });
      }
  
      // Get user's role and check permissions
      // const { role } = await this.getMemberRoleInWorkspace(userId, communityId);
      // roleGuard(role, [Permissions.UPDATE_TASK]);
  
      // Update the task status
      const updatedTask = await this.prisma.task.update({
        where: {
          id: taskId,
          project: {
            communityId: communityId
          }
        },
        data: {
          status: status
        }
      });
  
      return res.json(updatedTask);
    } catch (error) {
      console.error('Error updating task status:', error);
      if (error instanceof UnauthorizedException) {
        return res.status(403).json({ message: error.message });
      }
      return res.status(500).json({ message: 'Failed to update task status' });
    }
  }
}

export default new TaskController();
