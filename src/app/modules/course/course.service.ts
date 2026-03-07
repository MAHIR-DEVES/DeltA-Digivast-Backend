/* eslint-disable @typescript-eslint/no-explicit-any */

import { prisma } from '../../lib/prisma';

interface ICourseData {
  imageUrl: string;
  title: string;
  category: string;
  instructor: string;
  duration: string;
  price: number;
  status?: 'DRAFT' | 'PUBLISHED' | 'ARCHIVED';
  description: string;
}

const createCourse = async (payload: ICourseData) => {
  return await prisma.course.create({
    data: payload,
  });
};

const getAllCourses = async (query: any) => {
  const { page = 1, limit = 10, category, status } = query;

  const skip = (Number(page) - 1) * Number(limit);

  const whereCondition: any = {};

  if (category) {
    whereCondition.category = {
      equals: category,
      mode: 'insensitive',
    };
  }

  if (status) {
    whereCondition.status = status;
  }

  const data = await prisma.course.findMany({
    where: whereCondition,
    skip,
    take: Number(limit),
    orderBy: {
      createdAt: 'desc',
    },
  });

  const total = await prisma.course.count({
    where: whereCondition,
  });

  return {
    meta: {
      page: Number(page),
      limit: Number(limit),
      total,
    },
    data,
  };
};

const getSingleCourse = async (id: string) => {
  return await prisma.course.findUnique({
    where: { id },
  });
};

const updateCourse = async (id: string, payload: Partial<ICourseData>) => {
  return await prisma.course.update({
    where: { id },
    data: payload,
  });
};

const deleteCourse = async (id: string) => {
  return await prisma.course.delete({
    where: { id },
  });
};

export const CourseService = {
  createCourse,
  getAllCourses,
  getSingleCourse,
  updateCourse,
  deleteCourse,
};
