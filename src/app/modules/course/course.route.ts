import express from 'express';
import { CourseController } from './course.controller';
import { auth } from '../../middleware/auth';

const router = express.Router();

// Public
router.get('/', CourseController.getAllCourses);
router.get('/:id', CourseController.getSingleCourse);

// Admin Only
router.post('/', auth('ADMIN'), CourseController.createCourse);
router.patch('/:id', auth('ADMIN'), CourseController.updateCourse);
router.delete('/:id', auth('ADMIN'), CourseController.deleteCourse);

export const CourseRoutes = router;

// POST    /api/v1/courses        (ADMIN)
// GET     /api/v1/courses        (PUBLIC)
// GET     /api/v1/courses/:id    (PUBLIC)
// PATCH   /api/v1/courses/:id    (ADMIN)
// DELETE  /api/v1/courses/:id    (ADMIN)
