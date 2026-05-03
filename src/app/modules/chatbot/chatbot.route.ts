import express from 'express';
import { ChatbotController } from './chatbot.controller';

const router = express.Router();

// POST /api/v1/chatbot/chat  →  Public (no auth required)
router.post('/chat', ChatbotController.chat);

export const ChatbotRoutes = router;

// POST  /api/v1/chatbot/chat   (PUBLIC)
