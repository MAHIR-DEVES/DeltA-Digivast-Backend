import { Request, Response } from 'express';
import { catchAsync } from '../../shared/catchAsync';
import { sendResponse } from '../../shared/sendResponse';
import { ChatbotService } from './chatbot.service';

const chat = catchAsync(async (req: Request, res: Response) => {
  const { messages, leadData } = req.body;

  const result = await ChatbotService.chat({ messages, leadData });

  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: 'Chatbot reply generated successfully',
    data: result,
  });
});

export const ChatbotController = { chat };
