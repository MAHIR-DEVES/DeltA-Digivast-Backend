/* eslint-disable @typescript-eslint/no-explicit-any */

import { prisma } from '../../lib/prisma';

interface IPortfolioData {
  title: string;
  category: string;
  description: string;
  imageUrl?: string;
  videoUrl?: string;
}

const createPortfolio = async (payload: IPortfolioData) => {
  return await prisma.portfolio.create({
    data: payload,
  });
};

const getAllPortfolio = async (query: any) => {
  const { page = 1, limit = 10, category } = query;

  const skip = (Number(page) - 1) * Number(limit);

  const whereCondition = category
    ? { category: { equals: category, mode: 'insensitive' } }
    : {};

  const data = await prisma.portfolio.findMany({
    where: whereCondition,
    skip,
    take: Number(limit),
    orderBy: { createdAt: 'desc' },
  });

  const total = await prisma.portfolio.count({
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

const getSinglePortfolio = async (id: string) => {
  return await prisma.portfolio.findUnique({
    where: { id },
  });
};

const updatePortfolio = async (
  id: string,
  payload: Partial<IPortfolioData>,
) => {
  return await prisma.portfolio.update({
    where: { id },
    data: payload,
  });
};

const deletePortfolio = async (id: string) => {
  return await prisma.portfolio.delete({
    where: { id },
  });
};

export const PortfolioService = {
  createPortfolio,
  getAllPortfolio,
  getSinglePortfolio,
  updatePortfolio,
  deletePortfolio,
};
