import { Request, Response } from 'express';
import { LeadService } from './lead.service';

const createLead = async (req: Request, res: Response) => {
  const result = await LeadService.createLead({
    ...req.body,
    date: new Date(req.body.date),
  });

  res.status(201).json({
    success: true,
    message: 'Lead submitted successfully',
    data: result,
  });
};

const getAllLeads = async (req: Request, res: Response) => {
  const result = await LeadService.getAllLeads(req.query);

  res.status(200).json({
    success: true,
    ...result,
  });
};

const getSingleLead = async (req: Request, res: Response) => {
  const result = await LeadService.getSingleLead(req.params.id as string);

  res.status(200).json({
    success: true,
    data: result,
  });
};

const markAsViewed = async (req: Request, res: Response) => {
  const result = await LeadService.markAsViewed(req.params.id as string);

  res.status(200).json({
    success: true,
    message: 'Lead marked as viewed',
    data: result,
  });
};

const deleteLead = async (req: Request, res: Response) => {
  await LeadService.deleteLead(req.params.id as string);

  res.status(200).json({
    success: true,
    message: 'Lead deleted successfully',
  });
};

export const LeadController = {
  createLead,
  getAllLeads,
  getSingleLead,
  deleteLead,
  markAsViewed,
};
