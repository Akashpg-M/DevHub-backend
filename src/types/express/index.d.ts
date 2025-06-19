import { UserRole, AuthProvider } from '@prisma/client';

//Base user type that matches by the auth middleware
type BaseUser = {
  id: string;
  name: string;
  email: string;
  provider: AuthProvider;
  profilePicture?: string | null;
};

type AuthUser = BaseUser & {
  role: UserRole;
};

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        role: UserRole;
      };
    }
  }
}

export {};
