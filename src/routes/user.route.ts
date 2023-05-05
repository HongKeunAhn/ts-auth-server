import express from 'express';
import { getAllUsersHandler, getHandler } from '../controllers/user.controller';
import { deserializeUser } from '../middleware/deserializeUser';
import { requireUser } from '../middleware/requireUser';
import { restrictTo } from './../middleware/restrictTo';

const router = express.Router();
router.use(deserializeUser, requireUser);

router.get('/', restrictTo('admin'), getAllUsersHandler);

router.get('/me', getHandler);

export default router;
