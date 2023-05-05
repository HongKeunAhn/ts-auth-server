import { NextFunction, Request, Response } from 'express';
import AppError from '../utils/appError';

export const requireUser = (request: Request, response: Response, next: NextFunction) => {
  try {
    const user = response.locals.user;

    if (!user) {
      return next(new AppError('Invalid token or session has expired', 401));
    }

    next();
  } catch (error: any) {
    next(error);
  }
};
