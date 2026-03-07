import { Request, Response } from 'express';
import { BlogService } from './blog.service';

const createBlog = async (req: Request, res: Response) => {
  const result = await BlogService.createBlog(req.body);

  res.status(201).json({
    success: true,
    message: 'Blog created successfully',
    data: result,
  });
};

const getAllBlogs = async (req: Request, res: Response) => {
  const result = await BlogService.getAllBlogs(req.query);

  res.status(200).json({
    success: true,
    ...result,
  });
};

const getSingleBlog = async (req: Request, res: Response) => {
  const { id } = req.params;

  const result = await BlogService.getSingleBlog(id as string);

  res.status(200).json({
    success: true,
    data: result,
  });
};

const updateBlog = async (req: Request, res: Response) => {
  const { id } = req.params;

  const result = await BlogService.updateBlog(id as string, req.body);

  res.status(200).json({
    success: true,
    message: 'Blog updated successfully',
    data: result,
  });
};

const deleteBlog = async (req: Request, res: Response) => {
  const { id } = req.params;

  await BlogService.deleteBlog(id as string);

  res.status(200).json({
    success: true,
    message: 'Blog deleted successfully',
  });
};

export const BlogController = {
  createBlog,
  getAllBlogs,
  getSingleBlog,
  updateBlog,
  deleteBlog,
};
