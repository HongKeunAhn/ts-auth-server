import { NextFunction, Request, Response } from 'express';
import { AnyZodObject, ZodError } from 'zod';

export const validate = (schema: AnyZodObject) => {
  (request: Request, response: Response, next: NextFunction) => {
    try {
      schema.parse({
        params: request.params,
        query: request.query,
        body: request.body,
      });

      next();
    } catch (error: any) {
      if (error instanceof ZodError) {
        return response.status(400).json({
          status: 'fail',
          error: error.errors,
        });
      }

      next(error);
    }
  };
};
