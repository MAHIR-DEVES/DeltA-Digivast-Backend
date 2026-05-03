import { GoogleGenerativeAI } from '@google/generative-ai';
import { SYSTEM_PROMPT } from './chatbot.knowledge';
import { prisma } from '../../lib/prisma';

// ── Types ────────────────────────────────────────────────────────────────────

export interface IChatMessage {
  role: 'user' | 'model';
  content: string;
}

export interface IChatLeadData {
  name: string;
  email: string;
  message?: string;
}

export interface IChatRequest {
  messages: IChatMessage[];
  leadData?: IChatLeadData;
}

// ── Gemini client (lazy-initialised so tests can skip it) ────────────────────

let genAI: GoogleGenerativeAI | null = null;

const getClient = () => {
  if (!genAI) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) throw new Error('GEMINI_API_KEY is not set in environment variables');
    genAI = new GoogleGenerativeAI(apiKey);
  }
  return genAI;
};

// ── Service ──────────────────────────────────────────────────────────────────

const chat = async ({ messages, leadData }: IChatRequest) => {
  // ── 1. Validate ─────────────────────────────────────────────────────────
  if (!messages || messages.length === 0) {
    throw new Error('messages array cannot be empty');
  }

  // The last message must be from the user
  const lastMessage = messages[messages.length - 1];
  if (lastMessage.role !== 'user') {
    throw new Error('The last message must have role "user"');
  }

  // ── 2. Build history for Gemini (all messages except the last one) ───────
  //    Gemini expects: { role: 'user'|'model', parts: [{ text }] }[]
  const history = messages.slice(0, -1).map((m) => ({
    role: m.role,
    parts: [{ text: m.content }],
  }));

  // ── 3. Send to Gemini ────────────────────────────────────────────────────
  const attemptChat = async (modelName: string) => {
    const model = getClient().getGenerativeModel({
      model: modelName,
    });

    const chatSession = model.startChat({
      history: [
        { role: 'user', parts: [{ text: SYSTEM_PROMPT }] },
        {
          role: 'model',
          parts: [
            {
              text: 'I understand. I am the DeltA Digivast AI assistant. I will help visitors according to your instructions. How can I help you today?',
            },
          ],
        },
        ...history,
      ],
      generationConfig: {
        maxOutputTokens: 512,
        temperature: 0.7,
      },
    });

    return await chatSession.sendMessage(lastMessage.content);
  };

  let result;
  try {
    // Try the newest 2.5 Flash model
    result = await attemptChat('gemini-2.5-flash');
  } catch (err: any) {
    const message = err.message || '';
    if (message.includes('404')) {
      try {
        // Fallback to the generic latest flash
        result = await attemptChat('gemini-flash-latest');
      } catch (fallbackErr: any) {
        throw new Error(
          `AI Model Error: ${fallbackErr.message || 'Models not found.'}`,
        );
      }
    } else if (message.includes('429') || message.includes('quota')) {
      throw new Error(
        'Our AI assistant is temporarily busy (Quota exceeded). Please try again in a moment.',
      );
    } else {
      throw err;
    }
  }

  const reply = result.response.text();

  // ── 4. Optionally save lead ──────────────────────────────────────────────
  let leadSaved = false;

  if (leadData?.email && leadData?.name) {
    await prisma.lead.create({
      data: {
        name: leadData.name,
        email: leadData.email,
        from: 'chatbot',
        company: leadData.message ?? undefined,
        date: new Date(),
      },
    });
    leadSaved = true;
  }

  return { reply, leadSaved };
};

export const ChatbotService = { chat };
