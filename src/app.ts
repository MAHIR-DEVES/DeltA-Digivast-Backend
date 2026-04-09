import express, { Application, Request, Response } from 'express';
import { globalErrorHandler } from './app/middleware/golbelErrorHandler';
import { notFound } from './app/middleware/notFound';
import cors from 'cors';
import router from './app/routes';
import { handleWebhook } from './app/modules/payment/payment.webhook';

const app: Application = express();

// Middleware
app.use(express.urlencoded({ extended: true }));

// Stripe webhook needs the raw body, so we use express.raw for that specific route
app.post('/webhook', express.raw({ type: 'application/json' }), handleWebhook);

app.use(express.json());
app.use(
  cors({
    origin: [
      'http://localhost:3000',
      'https://delt-a-digivast-frontend.vercel.app',
      'https://deltadigivast.vercel.app',
    ],
    credentials: true,
  }),
);

app.use('/api/v1', router);

// Basic route
app.get('/', (req: Request, res: Response) => {
  res.status(200).json({
    message: 'Server is running',
  });
});

app.use(globalErrorHandler);
app.use(notFound);

export default app;
