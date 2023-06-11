import { NextFunction, Request, Response } from 'express';
import { findUserById } from '../services/user.service';
import AppError from '../utils/appError';
import redisClient from '../utils/connectRedis';
import { verifyJwt } from '../utils/jwt';

export const deserializeUser = async (request: Request, response: Response, next: NextFunction) => {
  try {
    let access_token;

    if (request.headers.authorization && request.headers.authorization.startsWith('Bearer')) {
      access_token = request.headers.authorization.split(' ')[1];
    } else if (request.cookies.access_token) {
      access_token = request.cookies.access_token;
    }

    if (!access_token) {
      return next(new AppError('You are not logged in', 401));
    }

    const decoded = verifyJwt<{ sub: string }>(access_token);

    if (!decoded) {
      return next(new AppError(`Invalid token or user doesn't exist`, 401));
    }

    const session = await redisClient.get(decoded.sub);

    if (!session) {
      return next(new AppError(`User session has expired`, 401));
    }

    const user = await findUserById(JSON.parse(session)._id);

    if (!user) {
      return next(new AppError(`User with that token no longer exist`, 401));
    }

    response.locals.user = user;

    next();
  } catch (error: any) {
    next(error);
  }
};
