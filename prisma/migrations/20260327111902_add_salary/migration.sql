/*
  Warnings:

  - The values [GRAPHIC_DESIGNER,UI_UX_DESIGNER] on the enum `Designation` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "Designation_new" AS ENUM ('GRAPHICS_DESIGNER', 'VIDEO_EDITOR', 'WEB_DEVELOPER', 'CINEMATOGRAPHER', 'CONTENT_WRITER', 'VOICE_ARTIST', 'DIGITAL_MARKETER');
ALTER TABLE "User" ALTER COLUMN "designation" TYPE "Designation_new" USING ("designation"::text::"Designation_new");
ALTER TYPE "Designation" RENAME TO "Designation_old";
ALTER TYPE "Designation_new" RENAME TO "Designation";
DROP TYPE "public"."Designation_old";
COMMIT;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "salary" TEXT;
