import { Response, NextFunction, Request } from 'express';
import { CommunityRole, UserRole, AuthProvider } from '@prisma/client';
import { PrismaClient } from '@prisma/client';


//Represents an authenticated user in the system with extended properties
 
interface ExtendedUser {
  id: string;
  name: string;
  email: string;
  provider: AuthProvider;
  role?: UserRole;
  profilePicture?: string | null;
}

// Extended Express Request type with our custom user type

declare module 'express-serve-static-core' {
  interface Request {
    user?: ExtendedUser;
    communityMembership?: {
      role: CommunityRole;
      communityId: string;
    };
  }
}

const prisma = new PrismaClient();


// Error class for authorization-related errors
class AuthorizationError extends Error {
  statusCode: number;

  constructor(message: string, statusCode = 403) {
    super(message);
    this.name = 'AuthorizationError';
    this.statusCode = statusCode;
  }
}


// Validates if the provided community ID is in the correct format

function isValidCommunityId(communityId: unknown): communityId is string {
  return typeof communityId === 'string' && communityId.trim().length > 0;
}

/**
 * Middleware to authorize requests based on user roles and community membership
 * @param userRoles - Array of allowed user roles (global roles like ADMIN, MODERATOR)
 * @param communityRoles - Array of allowed community roles (like OWNER, MANAGER, etc.)
 * @returns Express middleware function
 */

export const authorizeRole = (
  userRoles: UserRole[] = [],
  communityRoles: CommunityRole[] = []
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Check if user is authenticated and has the required role
      if (!req.user) {
        throw new AuthorizationError('Authentication required', 401);
      }

      // Type guard to ensure user has the role property
      const userWithRole = req.user as ExtendedUser;

      // Check global user roles if specified
      if (userRoles.length > 0 && userWithRole.role && !userRoles.includes(userWithRole.role)) {
        throw new AuthorizationError('Insufficient global permissions');
      }

      // Check community-specific roles if specified
      if (communityRoles.length > 0) {
        const { communityId } = req.params;
        
        if (!isValidCommunityId(communityId)) {
          throw new AuthorizationError('Valid community ID is required', 400);
        }

        // Check if community exists
        const communityExists = await prisma.community.findUnique({
          where: { id: communityId },
          select: { id: true }
        });

        if (!communityExists) {
          throw new AuthorizationError('Community not found', 404);
        }

        // Check if user is a member with required role
        const membership = await prisma.communityMember.findFirst({
          where: { 
            userId: req.user.id,
            communityId: communityId,
            role: { in: communityRoles }
          },
          select: {
            role: true,
            communityId: true
          }
        });

        if (!membership) {
          throw new AuthorizationError('Insufficient community permissions');
        }

        req.communityMembership = membership;
      }
      
      return next();
    } catch (error) {
      if (error instanceof AuthorizationError) {
        return res.status(error.statusCode).json({ 
          success: false,
          error: error.message,
          code: error.statusCode
        });
      }

      console.error('Authorization error:', error);
      return res.status(500).json({ 
        success: false,
        error: 'An unexpected error occurred while checking permissions',
        code: 500
      });
    }
  };
};

// Extend the Express Request type to include community membership info
declare global {
  namespace Express {
    interface Request {
      communityMembership?: {
        role: CommunityRole;
        communityId: string;
      };
    }
  }
}
