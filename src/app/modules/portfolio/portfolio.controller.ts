import { Request, Response } from 'express';
import { PortfolioService } from './portfolio.service';

const createPortfolio = async (req: Request, res: Response) => {
  const result = await PortfolioService.createPortfolio(req.body);

  res.status(201).json({
    success: true,
    message: 'Portfolio created successfully',
    data: result,
  });
};

const getAllPortfolio = async (req: Request, res: Response) => {
  const result = await PortfolioService.getAllPortfolio(req.query);

  res.status(200).json({
    success: true,
    ...result,
  });
};

const getSinglePortfolio = async (req: Request, res: Response) => {
  const result = await PortfolioService.getSinglePortfolio(
    req.params.id as string,
  );

  res.status(200).json({
    success: true,
    data: result,
  });
};

const updatePortfolio = async (req: Request, res: Response) => {
  const result = await PortfolioService.updatePortfolio(
    req.params.id as string,
    req.body,
  );

  res.status(200).json({
    success: true,
    message: 'Portfolio updated successfully',
    data: result,
  });
};

const deletePortfolio = async (req: Request, res: Response) => {
  await PortfolioService.deletePortfolio(req.params.id as string);

  res.status(200).json({
    success: true,
    message: 'Portfolio deleted successfully',
  });
};

export const PortfolioController = {
  createPortfolio,
  getAllPortfolio,
  getSinglePortfolio,
  updatePortfolio,
  deletePortfolio,
};
