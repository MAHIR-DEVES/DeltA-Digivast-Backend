import { Router } from 'express';
import { UserController } from './user.controller';
import { auth } from '../../middleware/auth';
import { Role } from '../../../generated/prisma/enums';

const router = Router();

router.post('/', UserController.registerUser);
router.post('/login', UserController.loginUser);
router.get('/', UserController.getAllUsers);
router.get(
  '/:id',
  auth(Role.ADMIN, Role.MANAGER),
  UserController.getSingleUser,
); // Single user
router.put(
  '/:id',
  auth(Role.EMPLOY, Role.ADMIN, Role.MANAGER),
  UserController.updateUser,
); // Update user
router.put(
  '/:id/password',
  auth(Role.EMPLOY, Role.ADMIN, Role.MANAGER),
  UserController.changePassword,
);
router.delete('/:id', auth(Role.ADMIN), UserController.deleteUser);

export const UserRoute = router;
