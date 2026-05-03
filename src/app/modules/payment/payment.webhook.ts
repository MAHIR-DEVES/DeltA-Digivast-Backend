/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import Stripe from 'stripe';
import { prisma } from '../../lib/prisma';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export const handleWebhook = async (req: any, res: any) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET!;

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    return res.status(400).send('Webhook Error');
  }

  if (event.type === 'checkout.session.completed') {
    const session: any = event.data.object;

    await prisma.payment.create({
      data: {
        userId: session.metadata.userId,
        courseId: session.metadata.courseId,
        amount: session.amount_total / 100,
        currency: session.currency,
        status: session.payment_status,
        stripeSessionId: session.id,
      },
    });
  }

  res.json({ received: true });
};
