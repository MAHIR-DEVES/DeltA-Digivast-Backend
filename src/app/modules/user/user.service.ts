import { Designation, Role, User } from '../../../generated/prisma/client';
import { envVars } from '../../config/env';
import { prisma } from '../../lib/prisma';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

interface IRegisterUser {
  name: string;
  email: string;
  password: string;
  phone?: string;
  photoUrl?: string;
  role?: Role;
  designation?: Designation;
  skills?: string;
  experience?: number;
  department?: string;
  salary?: number;
  joiningDate?: Date;
}

const registerUser = async (payload: IRegisterUser) => {
  const hashedPassword = await bcrypt.hash(payload.password, 10);

  if (payload.joiningDate) {
    payload.joiningDate = new Date(payload.joiningDate);
  }

  const user = await prisma.user.create({
    data: {
      ...payload,
      password: hashedPassword,
    },
    select: {
      id: true,
      name: true,
      email: true,
      phone: true,
      photoUrl: true,
      role: true,
      designation: true,
      skills: true,
      experience: true,
      department: true,
      joiningDate: true,
      salary: true,
      status: true,
      createdAt: true,
      updatedAt: true,
      lastLogin: true,
    },
  });

  return user;
};

interface ILoginUser {
  email: string;
  password: string;
}

const loginUser = async (payload: ILoginUser) => {
  const { email, password } = payload;

  // 1️⃣ Find user with password
  const user = await prisma.user.findUnique({
    where: { email },
  });
  if (!user) {
    throw new Error('User not found');
  }
  // 2️⃣ Compare password
  const isPasswordMatched = await bcrypt.compare(password, user.password);
  if (!isPasswordMatched) {
    throw new Error('Invalid password');
  }
  // 3️⃣ Generate JWT
  const token = jwt.sign(
    {
      id: user.id,
      employeeId: user.employeeId,
      email: user.email,
      role: user.role,
      name: user.name,
      phone: user.phone,
      photoUrl: user.photoUrl,
      designation: user.designation,
      skills: user.skills,
      experience: user.experience,
      department: user.department,
      status: user.status,
      salary: user.salary,
    },
    envVars.JWT_SECRET,
    {
      expiresIn: '7d',
    },
  );
  // 4️⃣ Remove password before return
  const { password: _, ...userWithoutPassword } = user;
  return {
    accessToken: token,
    user: userWithoutPassword,
  };
};

const getAllUsers = async (): Promise<User[]> => {
  const users = await prisma.user.findMany();
  return users;
};
const getSingleUser = async (id: string): Promise<User | null> => {
  return await prisma.user.findUnique({
    where: { id },
  });
};

const updateUser = async (
  id: string,
  payload: Partial<IRegisterUser>,
): Promise<User> => {
  if (payload.password) {
    payload.password = await bcrypt.hash(payload.password, 10);
  }

  if (payload.joiningDate) {
    payload.joiningDate = new Date(payload.joiningDate);
  }

  return await prisma.user.update({
    where: { id },
    data: payload,
    select: {
      id: true,
      name: true,
      email: true,
      phone: true,
      photoUrl: true,
      role: true,
      designation: true,
      skills: true,
      experience: true,
      department: true,
      status: true,
      joiningDate: true,
      createdAt: true,
      updatedAt: true,
      lastLogin: true,
    },
  });
};

const updatePassword = async (
  id: string,
  oldPassword: string,
  newPassword: string,
): Promise<User> => {
  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) throw new Error('User not found');

  // 1. পুরনো password check
  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) throw new Error('Old password is incorrect');

  // 2. নতুন password hash
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  // 3. password update
  return await prisma.user.update({
    where: { id },
    data: { password: hashedPassword },
    select: {
      id: true,
      name: true,
      email: true,
      phone: true,
      photoUrl: true,
      role: true,
      designation: true,
      skills: true,
      experience: true,
      department: true,
      status: true,
      joiningDate: true,
      createdAt: true,
      updatedAt: true,
      lastLogin: true,
    },
  });
};

const deleteUser = async (id: string): Promise<User> => {
  const user = await prisma.user.delete({
    where: { id },
  });
  return user;
};

export const UseService = {
  registerUser,
  deleteUser,
  getAllUsers,
  loginUser,
  getSingleUser,
  updateUser,
  updatePassword,
};
