/* eslint-disable @typescript-eslint/no-explicit-any */
import { prisma } from '../../lib/prisma';

interface IBlogData {
  title: string;
  description: string;
  imageUrl?: string;
}

const createBlog = async (payload: IBlogData) => {
  const result = await prisma.blog.create({
    data: payload,
  });

  return result;
};

const getAllBlogs = async (query: any) => {
  const { page = 1, limit = 10, search } = query;

  const skip = (Number(page) - 1) * Number(limit);

  const whereCondition = search
    ? {
        title: {
          contains: search,
          mode: 'insensitive',
        },
      }
    : {};

  const result = await prisma.blog.findMany({
    where: whereCondition,
    skip,
    take: Number(limit),
    orderBy: {
      createdAt: 'desc',
    },
  });

  const total = await prisma.blog.count({
    where: whereCondition,
  });

  return {
    meta: {
      page: Number(page),
      limit: Number(limit),
      total,
    },
    data: result,
  };
};

const getSingleBlog = async (id: string) => {
  return await prisma.blog.findUnique({
    where: { id },
  });
};

const updateBlog = async (id: string, payload: Partial<IBlogData>) => {
  return await prisma.blog.update({
    where: { id },
    data: payload,
  });
};

const deleteBlog = async (id: string) => {
  return await prisma.blog.delete({
    where: { id },
  });
};

export const BlogService = {
  createBlog,
  getAllBlogs,
  getSingleBlog,
  updateBlog,
  deleteBlog,
};
