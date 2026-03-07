import express from 'express';
import { AttendanceController } from './attendance.controller';
import { auth } from '../../middleware/auth';
import { Role } from '../../../generated/prisma/enums';

const router = express.Router();

// ✅ Employee sees only their own attendance
router.get(
  '/my',
  auth(Role.EMPLOY, Role.MANAGER, Role.ADMIN),
  AttendanceController.getMyAttendance,
);

// ✅ Admin/Manager Routes
router.post(
  '/',
  auth(Role.EMPLOY, Role.ADMIN, Role.MANAGER),
  AttendanceController.createAttendance,
);
router.get(
  '/',
  auth(Role.MANAGER, Role.ADMIN),
  AttendanceController.getAllAttendance,
);
router.get('/:id', auth(Role.ADMIN), AttendanceController.getSingleAttendance);
router.patch(
  '/:id',
  auth(Role.EMPLOY, Role.MANAGER, Role.ADMIN),
  AttendanceController.updateAttendance,
);
router.delete('/:id', auth(Role.ADMIN), AttendanceController.deleteAttendance);

export const AttendanceRoutes = router;
