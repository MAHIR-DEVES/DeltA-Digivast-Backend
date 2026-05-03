/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response } from 'express';
import { UseService } from './user.service';
import { catchAsync } from '../../shared/catchAsync';
import { sendResponse } from '../../shared/sendResponse';

const registerUser = catchAsync(async (req: Request, res: Response) => {
  const payload = req.body;
  const result = await UseService.registerUser(payload);

  sendResponse(res, {
    httpStatusCode: 201,
    success: true,
    message: 'user created successfully',
    data: result,
  });
});

const loginUser = catchAsync(async (req: Request, res: Response) => {
  const result = await UseService.loginUser(req.body);

  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: 'Login successful',
    data: result,
  });
});

const getAllUsers = catchAsync(async (req: Request, res: Response) => {
  const result = await UseService.getAllUsers();
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: 'user fetched successfully',
    data: result,
  });
});

const getSingleUser = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params;
  const result = await UseService.getSingleUser(id as string);
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: 'user fetched successfully',
    data: result,
  });
});

const updateUser = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params;
  const payload = req.body;
  const result = await UseService.updateUser(id as string, payload);
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: 'user updated successfully',
    data: result,
  });
});

const changePassword = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params;
  const { oldPassword, newPassword } = req.body;

  const result = await UseService.updatePassword(
    id as string,
    oldPassword,
    newPassword,
  );

  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: 'Password updated successfully',
    data: result,
  });
});

const deleteUser = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params;
  const result = await UseService.deleteUser(id as string);
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: 'user delete successfully',
    data: result,
  });
});

export const UserController = {
  registerUser,
  getAllUsers,
  deleteUser,
  loginUser,
  getSingleUser,
  updateUser,
  changePassword,
};
