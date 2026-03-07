/* eslint-disable @typescript-eslint/no-explicit-any */
import { prisma } from '../../lib/prisma';

interface IAttendanceData {
  employeeName: string;
  employeeId: string;
  designation: string;
  checkIn: Date;
  checkOut?: Date;
}

const createAttendance = async (payload: IAttendanceData) => {
  return await prisma.attendance.create({
    data: payload,
  });
};

const getAllAttendance = async (query: any) => {
  const { page = 1, limit = 10 } = query;
  const skip = (Number(page) - 1) * Number(limit);

  const data = await prisma.attendance.findMany({
    skip,
    take: Number(limit),
    orderBy: { createdAt: 'desc' },
  });

  const total = await prisma.attendance.count();

  return {
    meta: { page: Number(page), limit: Number(limit), total },
    data,
  };
};

const getSingleAttendance = async (id: string) => {
  return await prisma.attendance.findUnique({
    where: { id },
  });
};

const updateAttendance = async (
  id: string,
  payload: Partial<IAttendanceData>,
) => {
  return await prisma.attendance.update({
    where: { id },
    data: payload,
  });
};

const deleteAttendance = async (id: string) => {
  return await prisma.attendance.delete({
    where: { id },
  });
};

// ✅ Employee-specific paginated attendance
const getEmployeeAttendancePaginated = async (
  employeeId: string,
  page: number = 1,
  limit: number = 30,
) => {
  const skip = (page - 1) * limit;

  const records = await prisma.attendance.findMany({
    where: { employeeId },
    orderBy: { checkIn: 'desc' },
    skip,
    take: limit,
  });

  const total = await prisma.attendance.count({
    where: { employeeId },
  });

  return {
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
    records,
  };
};

export const AttendanceService = {
  createAttendance,
  getAllAttendance,
  getSingleAttendance,
  updateAttendance,
  deleteAttendance,
  getEmployeeAttendancePaginated,
};
