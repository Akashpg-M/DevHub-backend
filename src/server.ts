import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createServer } from 'http';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import passport from 'passport';

declare module 'express-session' {
  interface SessionData {
    user?: any;
    returnTo?: string;
  }
}

import authRouter from './auth_app/routes/auth.route';
import communityRouter from './community/routes/index';
import { connectDB } from './db';
// Load environment variables
dotenv.config();

const app = express();
const httpServer = createServer(app);

// Middleware
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  session({
    secret: process.env.JWT_SECRET || "your-session-secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Health check endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
  });
});

// Routes

app.use('/api/auth', authRouter);
app.use('/api/community', communityRouter);

// Error handling middleware
interface AppError extends Error {
  statusCode?: number;
  status?: number;
  message: string;
  stack?: string;
}

app.use((err: AppError, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Error:', err.stack);
  const statusCode = err.statusCode || err.status || 500;
  
  res.status(statusCode).json({
    success: false,
    message: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Start server
const PORT = process.env.PORT || 3000;

// Initialize database and start the server
connectDB()
  .then(() => {
    httpServer.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Error starting server:', error);
    process.exit(1);
  });

export default app;
