import express, { Application, Request, Response } from 'express';
import { IndexRoutes } from './app/routes';
import { globalErrorHandler } from './app/middleware/golbelErrorHandler';
import { notFound } from './app/middleware/notFound';

const app: Application = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use('/api/v1', IndexRoutes);

// Basic route
app.get('/', (req: Request, res: Response) => {
  res.status(200).json({
    message: 'Server is running',
  });
});

app.use(globalErrorHandler);
app.use(notFound);

export default app;
