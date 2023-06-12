import config from 'config';
import { CookieOptions, NextFunction, Request, Response } from 'express';

import { CreateUserInput, LoginUserInput } from '../schema/user.schema';
import { createUser, findUser, findUserById, signToken } from '../services/user.service';
import AppError from '../utils/appError';
import { signJwt, verifyJwt } from '../utils/jwt';
import redisClient from '../utils/connectRedis';

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

export const refreshAccessTokenHandler = async (
  request: Request,
  response: Response,
  next: NextFunction
) => {
  try {
    const refresh_token = request.cookies.refresh_token as string;

    const decoded = verifyJwt<{ sub: string }>(refresh_token, 'refreshTokenPublicKey');

    const message = 'Could not refresh access token';

    if (!decoded) {
      return next(new AppError(message, 403));
    }

    const session = await redisClient.get(decoded.sub);

    if (!session) {
      return next(new AppError(message, 403));
    }

    const user = await findUserById(JSON.parse(session)._id);

    if (!user) {
      return next(new AppError(message, 403));
    }

    const access_token = signJwt({ sub: user._id }, 'accessTokenPrivateKey', {
      expiresIn: `${config.get<number>('accessTokenExpiresIn')}m`,
    });

    response.cookie('access_token', access_token, accessTokenCookieOptions);
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

const logout = (response: Response) => {
  response.cookie('access_token', '', { maxAge: 1 });
  response.cookie('refresh_token', '', { maxAge: 1 });
  response.cookie('logged_in', '', { maxAge: 1 });
};

export const logoutHandler = async (request: Request, response: Response, next: NextFunction) => {
  try {
    const user = response.locals.user;
    await redisClient.del(user._id);

    logout(response);

    return response.status(200).json({ status: 'success' });
  } catch (error: any) {
    next(error);
  }
};
