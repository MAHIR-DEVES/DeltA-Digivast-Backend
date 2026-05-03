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
  const model = getClient().getGenerativeModel({
    model: 'gemini-1.5-flash',
    systemInstruction: SYSTEM_PROMPT,
  });

  const chatSession = model.startChat({
    history,
    generationConfig: {
      maxOutputTokens: 512,
      temperature: 0.7,
    },
  });

  let result;
  try {
    result = await chatSession.sendMessage(lastMessage.content);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('429') || message.includes('quota')) {
      throw new Error(
        'Our AI assistant is temporarily busy. Please try again in a moment or contact us directly at /contact.',
      );
    }
    throw err;
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
