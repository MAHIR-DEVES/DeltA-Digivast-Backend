/* eslint-disable @typescript-eslint/no-unused-vars */
import { Request, Response } from 'express';
import { StatsService } from './stats.service';

const getStats = async (req: Request, res: Response) => {
  try {
    const result = await StatsService.getStats();

    res.status(200).json({
      success: true,
      message: 'Stats fetched successfully',
      data: result,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch stats',
    });
  }
};

export const StatsController = {
  getStats,
};
