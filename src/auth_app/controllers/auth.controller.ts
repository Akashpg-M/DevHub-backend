import { Response, Request, NextFunction } from "express";
import { AuthenticatedRequest } from "../../types/express";
import { PrismaClient, AuthProvider, UserRole } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { URL } from 'url';

const prisma = new PrismaClient();


// Configure Passport for Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
      callbackURL: process.env.GOOGLE_CALLBACK_URL as string,
      passReqToCallback: true,
      scope: ['profile', 'email']
    },
    async (_req, _accessToken, _refreshToken, profile, done) => {
      try {

        if (!profile.emails?.[0]?.value) {
          console.error('No email provided by Google OAuth');
          return done(new Error("No email provided by Google"), undefined);
        }

        const email = profile.emails[0].value;
        
        // Try to find existing user by email
        let user = await prisma.user.findUnique({
          where: { email },
        });

        if (!user) {
          // Create new user if not exists
          user = await prisma.user.create({
            data: {
              name: profile.displayName || email.split('@')[0],
              email,
              provider: AuthProvider.GOOGLE,
              role: UserRole.USER,
              profilePicture: profile.photos?.[0]?.value || null,
            },
          });
        } else if (user.provider !== AuthProvider.GOOGLE) {
          // User exists but with different provider
          const errorMsg = `Email already in use with ${user.provider} sign-in method`;
          return done(new Error(errorMsg), undefined);
        }

        return done(null, user);
      } catch (error) {
        console.error('Error in Google OAuth strategy:', error);
        return done(error, undefined);
      }
    }
  )
);

// Serialize user into the session
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) {
      return done(new Error('User not found'), undefined);
    }
    done(null, user);
  } catch (error) {
    done(error, undefined);
  }
});

export const signUpSchema = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Invalid email"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const loginSchema = z.object({
  email: z.string().email("Invalid email"),
  password: z.string().min(1, "Password is required"),
});

export type SignUpInput = z.infer<typeof signUpSchema>;
export type LoginInput = z.infer<typeof loginSchema>;

// Generate JWT token with role
export const generateToken = (user: { id: string; role: UserRole }, res: Response) => {
  const token = jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET as string,
    { expiresIn: "1h" }
  );
  res.cookie("jwt", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 3600000, // 1 hour
    path : "/", // To Ensure cookie is accessible on all routes
  });
};

// --------------------- SIGN UP ---------------------
export const signUp = async (req: Request, res: Response): Promise<void> => {
  try {
    const parsed = signUpSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ success: false, message: parsed.error.errors[0].message });
      return;
    }

    const { name, email, password }: SignUpInput = parsed.data;

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(400).json({ success: false, message: "Email already exists" });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        provider: AuthProvider.LOCAL,
        role: UserRole.USER,
      },
    });

    generateToken({ id: newUser.id, role: newUser.role }, res);

    res.status(201).json({
      success: true,
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    });
  } catch (error: unknown) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

// --------------------- LOGIN ---------------------
export const login = async (req: Request, res: Response): Promise<Response | void> => {
  try {
    
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      console.log('Validation error:', parsed.error.errors);
      return res.status(400).json({ 
        success: false, 
        message: parsed.error.errors[0].message 
      }) as Response;
    }

    const { email, password }: LoginInput = parsed.data;

    const user = await prisma.user.findUnique({ 
      where: { email },
      select: {
        id: true,
        email: true,
        password: true,
        name: true,
        role: true,
        provider: true
      }
    });
    
    if (!user) {
      console.log('No user found with email:', email);
      return res.status(400).json({ 
        success: false, 
        message: "Invalid email or password" 
      }) as Response;
    }

    if (!user.password) {
      console.log('User has no password (possibly OAuth user):', user.id);
      return res.status(400).json({ 
        success: false, 
        message: "Please sign in with your OAuth provider" 
      }) as Response;
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid email or password" 
      }) as Response;
    }

    generateToken({ id: user.id, role: user.role }, res);

    const userData = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      provider: user.provider
    };

    res.status(200).json({
      success: true,
      data: userData
    });
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error("Error in login:", errorMessage);
    console.error('Error stack:', error instanceof Error ? error.stack : 'No stack trace');
    
    res.status(500).json({ 
      success: false, 
      message: "An error occurred during login. Please try again.",
      ...(process.env.NODE_ENV === 'development' && { error: errorMessage })
    });
  }
};

// --------------------- GOOGLE OAUTH ---------------------
export const googleAuth = (req: Request, res: Response, next: NextFunction) => {
  try {
    const returnTo = req.query.returnTo || '/';
    const state = Buffer.from(JSON.stringify({ returnTo })).toString('base64');
    
    
    const options = {
      scope: ['profile', 'email'],
      state,
      session: false,
      prompt: 'select_account' as const,
      accessType: 'offline',
      includeGrantedScopes: true
    };
    
    const authenticator = passport.authenticate('google', options);
    return authenticator(req, res, next);
  } catch (error) {
    console.error('Error in googleAuth:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to initiate Google OAuth';
    res.redirect(`${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(errorMessage)}`);
  }
};

export const googleAuthCallback = [
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login`,
    session: false 
  }),
  async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        throw new Error('Authentication failed: No user data');
      }

      const user = req.user as any;
      
      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, role: user.role },
        process.env.JWT_SECRET as string,
        { expiresIn: '1h' }
      );

      // Set the JWT in a cookie
      res.cookie('jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "none",
        maxAge: 3600000, // 1 hour
        path: "/", // To Ensure cookie is accessible on all routes
      });

      // Parse state if it exists
      let returnTo = '/';
      if (req.query.state) {
        try {
          const state = JSON.parse(Buffer.from(req.query.state as string, 'base64').toString());
          if (state.returnTo) {
            returnTo = state.returnTo;
          }
        } catch (e) {
          console.error('Error parsing state:', e);
        }
      }
      
      // Redirect to the frontend without token query param
      const redirectUrl = new URL(returnTo, process.env.FRONTEND_URL as string);
      console.log('Redirecting to:', redirectUrl.toString());
      return res.redirect(redirectUrl.toString());
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      const frontendUrl = process.env.FRONTEND_URL as string;
      const errorMessage = error instanceof Error ? error.message : 'Authentication failed';
      return res.redirect(
        `${frontendUrl}/login?error=${encodeURIComponent(errorMessage)}`
      );
    }
  }
];

// --------------------- LOGOUT ---------------------
export const logout = (_req: Request, res: Response): void => {
  try {
    res.cookie("jwt", "", { maxAge: 0 });
    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error: unknown) {
    console.error("Logout error:", error instanceof Error ? error.message : "Unknown error");
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

// --------------------- CHECK AUTH ---------------------
export const checkAuth = async (req: Request, res: Response): Promise<void> => {
  try {
    // Safely cast to AuthenticatedRequest
    const authReq = req as AuthenticatedRequest;
    
    // This should never happen if the protectRoute middleware is working correctly
    if (!authReq.user) {
      res.status(401).json({ success: false, message: "Not authenticated" });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: authReq.user.id },
      select: {
        id: true,
        name: true,
        email: true,
        provider: true,
        role: true,
        profilePicture: true,
      },
    });

    if (!user) {
      res.status(404).json({ success: false, message: "User not found" });
      return;
    }

    res.status(200).json({ 
      success: true, 
      data: user 
    });
  } catch (error: unknown) {
    console.error("Check auth error:", error instanceof Error ? error.message : "Unknown error");
    res.status(500).json({ 
      success: false, 
      message: "Internal Server Error" 
    });
  }
};
