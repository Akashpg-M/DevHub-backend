import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../../db';
import { UserRole, AuthProvider } from '@prisma/client';

interface DecodedToken {
  userId: string;
  iat: number;
  exp: number;
}

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: UserRole;
    name: string;
    provider: AuthProvider;
    profilePicture?: string | null;
  };
}

// Helper function to get token from request
const getToken = (req: Request): string | null => {
  return req.cookies?.jwt || 
         req.headers.authorization?.split(' ')[1] || 
         null;
};

// Middleware to protect routes that require authentication
export async function protectRoute(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authReq = req as AuthenticatedRequest;
  try {
    // 1) Get token and check if it exists
    const token = getToken(req);
    if (!token) {
      res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
      return;
    }

    // 2) Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as DecodedToken;

    // 3) Check if user still exists
    const currentUser = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        profilePicture: true,
        provider: true
      },
    });

    if (!currentUser) {
      res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
      return;
    }

    // 4) Grant access to protected route
    authReq.user = currentUser;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({
        success: false,
        message: 'Your token has expired. Please log in again.'
      });
      return;
    }
    
    if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        success: false,
        message: 'Invalid token. Please log in again.'
      });
      return;
    }
    
    // For any other errors
    console.error('Unexpected authentication error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during authentication. Please try again later.'
    });
  }
}

// Middleware to restrict routes to specific roles
export const restrictTo = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const authReq = req as AuthenticatedRequest;
      
      // Check if user is authenticated
      if (!authReq.user) {
        return res.status(401).json({
          status: 'fail',
          message: 'You are not logged in! Please log in to get access.'
        });
      }

      // Check if user has required role
      if (!roles.includes(authReq.user.role)) {
        return res.status(403).json({
          status: 'fail',
          message: 'You do not have permission to perform this action'
        });
      }

      // If user has required role, proceed to next middleware
      return next();
    } catch (error) {
      console.error('Authorization error:', error);
      return res.status(500).json({
        success: false,
        message: 'An error occurred during authorization. Please try again later.'
      });
    }
  };
};