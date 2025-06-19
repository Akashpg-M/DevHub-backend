import 'express-session';

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    // Add other session properties you're using
  }
}
