import { Request } from 'express';
import { AuthProvider } from '@prisma/client';

declare global {
  namespace Express {
    interface User {
      id: string;
      name: string;
      email: string;
      provider: AuthProvider;
      profilePicture?: string | null;
    }

    interface Request {
      user?: User;
    }
  }
}

export interface AuthenticatedRequest extends Request {
  user: NonNullable<Request['user']>;
}
