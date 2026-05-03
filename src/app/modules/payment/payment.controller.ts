import { Request, Response } from 'express';
import { createCheckoutSessionService } from './payment.service';

export const createCheckoutSession = async (req: Request, res: Response) => {
  const session = await createCheckoutSessionService(req.body);

  res.json({
    success: true,
    url: session.url,
  });
};
