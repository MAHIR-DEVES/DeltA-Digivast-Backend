import { IUserPayload } from '../interfaces/user.interface';

declare global {
  namespace Express {
    interface Request {
      user?: IUserPayload; // optional যদি কখনও token না থাকে
    }
  }
}
