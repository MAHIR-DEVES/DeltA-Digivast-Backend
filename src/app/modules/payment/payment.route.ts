import express from 'express';
import { createCheckoutSession } from './payment.controller';

const router = express.Router();

router.post('/create-checkout-session', createCheckoutSession);

export const paymentRoutes = router;
