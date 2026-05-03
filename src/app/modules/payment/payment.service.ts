/* eslint-disable @typescript-eslint/no-explicit-any */
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export const createCheckoutSessionService = async (payload: any) => {
  const { courseId, price, userId } = payload;

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    mode: 'payment',
    success_url: `${process.env.CLIENT_URL}/courses/${courseId}`,
    cancel_url: `${process.env.CLIENT_URL}/courses/${courseId}`,
    line_items: [
      {
        price_data: {
          currency: 'bdt',
          product_data: {
            name: 'Course Purchase',
          },
          unit_amount: price * 100,
        },
        quantity: 1,
      },
    ],
    metadata: {
      courseId,
      userId,
    },
  });

  return session;
};
