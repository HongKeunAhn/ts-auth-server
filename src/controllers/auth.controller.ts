import config from 'config';
import { CookieOptions, NextFunction, Request, Response } from 'express';

import { CreateUserInput, LoginUserInput } from '../schema/user.schema';
import { createUser, findUser, signToken } from '../services/user.service';
import AppError from '../utils/appError';

export const excludedFields = ['password'];

const accessTokenCookieOptions: CookieOptions = {
  expires: new Date(Date.now() + config.get<number>('accessTokenExpiresIn') * 60 * 1000),
  maxAge: config.get<number>('accessTokenExpiresIn') * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
};

const refreshTokenCookieOptions: CookieOptions = {
  expires: new Date(Date.now() + config.get<number>('refreshTokenExpiresIn') * 60 * 1000),
  maxAge: config.get<number>('refreshTokenExpiresIn') * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
};

if (process.env.NODE_ENV === 'production') accessTokenCookieOptions.secure = true;

export const registerHandler = async (
  request: Request<{}, {}, CreateUserInput>,
  response: Response,
  next: NextFunction
) => {
  try {
    const user = await createUser({
      email: request.body.email,
      name: request.body.name,
      password: request.body.password,
    });

    response.status(201).json({
      status: 'success',
      data: {
        user,
      },
    });
  } catch (error: any) {
    if (error.code === 11000) {
      return response.status(409).json({
        status: 'fail',
        message: 'Email already exist',
      });
    }

    next(error);
  }
};

export const loginHandler = async (
  request: Request<{}, {}, LoginUserInput>,
  response: Response,
  next: NextFunction
) => {
  try {
    const user = await findUser({ email: request.body.email });

    if (!user || !(await user.comparePasswords(user.password, request.body.password))) {
      return next(new AppError('Invalid email or password', 401));
    }

    const { access_token, refresh_token } = await signToken(user);

    response.cookie('access_token', access_token, accessTokenCookieOptions);
    response.cookie('refresh_token', refresh_token, refreshTokenCookieOptions);
    response.cookie('logged_in', true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    response.status(200).json({
      status: 'success',
      access_token,
    });
  } catch (error: any) {
    next(error);
  }
};
