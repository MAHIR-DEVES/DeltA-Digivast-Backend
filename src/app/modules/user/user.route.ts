import { Router } from 'express';
import { UserController } from './user.controller';
import { auth } from '../../middleware/auth';
import { Role } from '../../../generated/prisma/enums';

const router = Router();

router.post('/', auth(Role.ADMIN), UserController.registerUser);
router.post('/login', UserController.loginUser);
router.get('/', auth(Role.ADMIN, Role.MANAGER), UserController.getAllUsers);
router.delete('/:id', auth(Role.ADMIN), UserController.deleteUser);

export const UserRoute = router;
