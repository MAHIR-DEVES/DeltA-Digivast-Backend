/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { envVars } from '../config/env';

export const auth = (...requiredRoles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        return res.status(401).json({
          success: false,
          message: 'You are not authorized',
        });
      }

      //  Split Bearer token
      const token = authHeader.split(' ')[1];

      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token format',
        });
      }

      const verifiedUser = jwt.verify(token, envVars.JWT_SECRET) as any;

      // Role check
      if (requiredRoles.length && !requiredRoles.includes(verifiedUser.role)) {
        return res.status(403).json({
          success: false,
          message: 'Forbidden access',
        });
      }

      (req as any).user = verifiedUser;

      next();
    } catch (error) {
      next(error);
    }
  };
};
