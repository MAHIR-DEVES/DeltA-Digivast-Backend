/*
  Warnings:

  - Added the required column `password` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `User` table without a default value. This is not possible if the table is not empty.
  - Made the column `name` on table `User` required. This step will fail if there are existing NULL values in that column.

*/
-- CreateEnum
CREATE TYPE "Role" AS ENUM ('SUPER_ADMIN', 'ADMIN', 'EMPLOY');

-- CreateEnum
CREATE TYPE "STATUS" AS ENUM ('ACTIVE', 'BLOCK');

-- CreateEnum
CREATE TYPE "Designation" AS ENUM ('VIDEO_EDITOR', 'GRAPHIC_DESIGNER', 'WEB_DEVELOPER', 'UI_UX_DESIGNER');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "department" TEXT,
ADD COLUMN     "designation" "Designation",
ADD COLUMN     "experience" INTEGER,
ADD COLUMN     "lastLogin" TIMESTAMP(3),
ADD COLUMN     "password" TEXT NOT NULL,
ADD COLUMN     "phone" TEXT,
ADD COLUMN     "photoUrl" TEXT,
ADD COLUMN     "role" "Role" NOT NULL DEFAULT 'EMPLOY',
ADD COLUMN     "skills" TEXT,
ADD COLUMN     "status" "STATUS" NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL,
ALTER COLUMN "name" SET NOT NULL;
