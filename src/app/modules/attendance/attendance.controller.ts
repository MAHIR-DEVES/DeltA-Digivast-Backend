/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response } from 'express';
import { AttendanceService } from './attendance.service';

// ✅ Employee creates attendance (Admin/Manager can also do)
const createAttendance = async (req: Request, res: Response) => {
  try {
    const result = await AttendanceService.createAttendance({
      ...req.body,
      checkIn: new Date(req.body.checkIn),
      checkOut: req.body.checkOut ? new Date(req.body.checkOut) : undefined,
    });

    res.status(201).json({
      success: true,
      message: 'Attendance recorded successfully',
      data: result,
    });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// ✅ Employee sees only **his own** attendance (paginated)
const getMyAttendance = async (req: Request, res: Response) => {
  try {
    const employeeId = req.user?.employeeId; // auth middleware থেকে set
    console.log(employeeId);
    if (!employeeId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 30;

    const result = await AttendanceService.getEmployeeAttendancePaginated(
      employeeId,
      page,
      limit,
    );

    res.status(200).json({ success: true, ...result });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// ✅ Admin routes
const getAllAttendance = async (req: Request, res: Response) => {
  const result = await AttendanceService.getAllAttendance(req.query);
  res.status(200).json({ success: true, ...result });
};

const getSingleAttendance = async (req: Request, res: Response) => {
  const result = await AttendanceService.getSingleAttendance(
    req.params.id as string,
  );
  res.status(200).json({ success: true, data: result });
};

const updateAttendance = async (req: Request, res: Response) => {
  try {
    const payload: any = {};
    if (req.body.checkOut) {
      payload.checkOut = new Date(req.body.checkOut); // Prisma-compatible Date
    }

    const result = await AttendanceService.updateAttendance(
      req.params.id as string,
      payload,
    );

    res.status(200).json({
      success: true,
      message: 'Attendance updated',
      data: result,
    });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
};

const deleteAttendance = async (req: Request, res: Response) => {
  await AttendanceService.deleteAttendance(req.params.id as string);
  res.status(200).json({ success: true, message: 'Attendance deleted' });
};

export const AttendanceController = {
  createAttendance,
  getMyAttendance,
  getAllAttendance,
  getSingleAttendance,
  updateAttendance,
  deleteAttendance,
};
