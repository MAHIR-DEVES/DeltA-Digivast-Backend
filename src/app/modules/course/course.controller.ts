import { Request, Response } from 'express';
import { CourseService } from './course.service';

const createCourse = async (req: Request, res: Response) => {
  const result = await CourseService.createCourse(req.body);

  res.status(201).json({
    success: true,
    message: 'Course created successfully',
    data: result,
  });
};

const getAllCourses = async (req: Request, res: Response) => {
  const result = await CourseService.getAllCourses(req.query);

  res.status(200).json({
    success: true,
    ...result,
  });
};

const getSingleCourse = async (req: Request, res: Response) => {
  const result = await CourseService.getSingleCourse(req.params.id as string);

  res.status(200).json({
    success: true,
    data: result,
  });
};

const updateCourse = async (req: Request, res: Response) => {
  const result = await CourseService.updateCourse(
    req.params.id as string,
    req.body,
  );

  res.status(200).json({
    success: true,
    message: 'Course updated successfully',
    data: result,
  });
};

const deleteCourse = async (req: Request, res: Response) => {
  await CourseService.deleteCourse(req.params.id as string);

  res.status(200).json({
    success: true,
    message: 'Course deleted successfully',
  });
};

export const CourseController = {
  createCourse,
  getAllCourses,
  getSingleCourse,
  updateCourse,
  deleteCourse,
};
