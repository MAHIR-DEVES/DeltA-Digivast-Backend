import { Request, Response } from 'express';
import { HeroService } from './hero.service';

const createHero = async (req: Request, res: Response) => {
  const result = await HeroService.createHero(req.body);

  res.status(201).json({
    success: true,
    message: 'Hero content created successfully',
    data: result,
  });
};

const getAllHero = async (req: Request, res: Response) => {
  const result = await HeroService.getAllHero();

  res.status(200).json({
    success: true,
    data: result,
  });
};

const getSingleHero = async (req: Request, res: Response) => {
  const result = await HeroService.getSingleHero(req.params.id as string);

  res.status(200).json({
    success: true,
    data: result,
  });
};

const updateHero = async (req: Request, res: Response) => {
  const result = await HeroService.updateHero(
    req.params.id as string,
    req.body,
  );

  res.status(200).json({
    success: true,
    message: 'Hero updated successfully',
    data: result,
  });
};

const deleteHero = async (req: Request, res: Response) => {
  await HeroService.deleteHero(req.params.id as string);

  res.status(200).json({
    success: true,
    message: 'Hero deleted successfully',
  });
};

export const HeroController = {
  createHero,
  getAllHero,
  getSingleHero,
  updateHero,
  deleteHero,
};
