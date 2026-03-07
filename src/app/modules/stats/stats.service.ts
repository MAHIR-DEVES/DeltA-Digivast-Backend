import { prisma } from '../../lib/prisma';

const getStats = async () => {
  const [users, blogs, leads, courses, portfolios] = await Promise.all([
    prisma.user.count(),
    prisma.blog.count(),
    prisma.lead.count(),
    prisma.course.count(),
    prisma.portfolio.count(),
  ]);

  return {
    users,
    blogs,
    leads,
    courses,
    portfolios,
  };
};

export const StatsService = {
  getStats,
};
