import { NextFunction, Request, Response } from 'express';
import { findAllUsers } from '../services/user.service';
export const getHandler = (request: Request, response: Response, next: NextFunction) => {
  try {
    const user = response.locals.user;

    response.status(200).json({
      status: 'success',
      data: {
        user,
      },
    });
  } catch (error: any) {
    next(error);
  }
};

export const getAllUsersHandler = async (
  request: Request,
  response: Response,
  next: NextFunction
) => {
  try {
    const users = await findAllUsers();

    response.status(200).json({
      status: 'success',
      result: users.length,
      data: {
        users,
      },
    });
  } catch (error: any) {
    next(error);
  }
};
