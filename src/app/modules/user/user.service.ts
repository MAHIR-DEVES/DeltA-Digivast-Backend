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
}

const registerUser = async (payload: IRegisterUser) => {
  const hashedPassword = await bcrypt.hash(payload.password, 10);

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
};
