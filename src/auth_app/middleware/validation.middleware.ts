import { Request, Response, NextFunction } from 'express';
import { ZodObject, ZodRawShape, ZodTypeAny } from 'zod';

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

type RequestSchemas = {
  params?: ZodObject<ZodRawShape>;
  query?: ZodObject<ZodRawShape>;
  body?: ZodTypeAny;
};

export const validateRequest = (schemas: RequestSchemas | ZodTypeAny) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      if ('params' in schemas || 'query' in schemas || 'body' in schemas) {
        const { params, query, body } = schemas as RequestSchemas;
        
        if (params) {
          req.params = params.parse(req.params);
        }
        if (query) {
          req.query = query.parse(req.query);
        }
        if (body) {
          req.body = body.parse(req.body);
        }
      } else {
        // Handle single schema (backward compatibility)
        const schema = schemas as ZodTypeAny;
        req.body = schema.parse(req.body);
      }
      next();
    } catch (error: any) {
      console.error('Validation error:', error);
      if (error.errors) {
        res.status(400).json({ error: error.errors });
        return;
      }
      res.status(400).json({ error: 'Validation failed' });
    }
  };
};