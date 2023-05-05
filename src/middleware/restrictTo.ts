import { NextFunction, Request, Response } from 'express';
import AppError from '../utils/appError';

export const restrictTo =
  (...allowedRoles: string[]) =>
  (request: Request, response: Response, next: NextFunction) => {
    const user = response.locals.user;

    if (!allowedRoles.includes(user.role)) {
      return next(new AppError('You are not allowed to perform this action', 403));
    }

    next();
  };
