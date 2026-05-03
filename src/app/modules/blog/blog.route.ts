import express from 'express';
import { BlogController } from './blog.controller';
import { auth } from '../../middleware/auth';
import { Role } from '../../../generated/prisma/enums';

const router = express.Router();

// Public Routes
router.get('/', BlogController.getAllBlogs);
router.get('/:id', BlogController.getSingleBlog);

// Admin Only Routes
router.post('/', auth(Role.ADMIN), BlogController.createBlog);
router.patch('/:id', auth('ADMIN'), BlogController.updateBlog);
router.delete('/:id', auth('ADMIN'), BlogController.deleteBlog);

// POST    /api/v1/blogs      (ADMIN)
// GET     /api/v1/blogs      (PUBLIC)
// GET     /api/v1/blogs/:id  (PUBLIC)
// PATCH   /api/v1/blogs/:id  (ADMIN)
// DELETE  /api/v1/blogs/:id  (ADMIN)

export const BlogRoutes = router;
