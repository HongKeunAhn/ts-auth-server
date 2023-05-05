require('dotenv').config();
import express, { NextFunction, Request, Response } from 'express';
import config from 'config';

import connectDB from './utils/connectDB';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import cors from 'cors';
import userRouter from './routes/user.route';
import authRouter from './routes/auth.route';

const app = express();

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

if (process.env.NODE_ENV === 'development') app.use(morgan('dev'));

app.use(
  cors({
    origin: config.get<string>('origin'),
    credentials: true,
  })
);

app.use('/api/users', userRouter);
app.use('/api/auth', authRouter);

app.get('/healthChecker', (request: Request, response: Response, next: NextFunction) => {
  response.status(200).json({
    status: 'success',
    message: 'Welcome to Jwt auth start!',
  });
});

app.all('*', (request: Request, response: Response, next: NextFunction) => {
  const error = new Error(`Route ${request.originalUrl} not found`) as any;

  error.statusCode = 404;
  next(error);
});

app.use((error: any, request: Request, response: Response) => {
  error.status = error.status || 'error';
  error.statusCode = error.statusCode || 500;

  response.status(error.statusCode).json({
    status: error.status,
    message: error.message,
  });
});

const port = config.get<number>('port');
app.listen(port, () => {
  console.log(`Server started on port: ${port}`);

  connectDB();
});
