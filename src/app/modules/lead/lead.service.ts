/* eslint-disable @typescript-eslint/no-explicit-any */
import { prisma } from '../../lib/prisma';

interface ILeadData {
  name: string;
  email: string;
  from: string;
  company?: string;
  date: Date;
}

const createLead = async (payload: ILeadData) => {
  return await prisma.lead.create({
    data: payload,
  });
};

const getAllLeads = async (query: any) => {
  const { page = 1, limit = 10 } = query;
  const skip = (Number(page) - 1) * Number(limit);

  const data = await prisma.lead.findMany({
    skip,
    take: Number(limit),
    orderBy: {
      createdAt: 'desc',
    },
  });

  const total = await prisma.lead.count();

  return {
    meta: {
      page: Number(page),
      limit: Number(limit),
      total,
    },
    data,
  };
};

const getSingleLead = async (id: string) => {
  return await prisma.lead.findUnique({
    where: { id },
  });
};

const deleteLead = async (id: string) => {
  return await prisma.lead.delete({
    where: { id },
  });
};

export const LeadService = {
  createLead,
  getAllLeads,
  getSingleLead,
  deleteLead,
};
