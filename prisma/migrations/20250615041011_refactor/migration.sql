/*
  Warnings:

  - The values [REVIEW] on the enum `TaskStatus` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `githubProfile` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `isEmailVerified` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `linkedinProfile` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `refreshToken` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `role` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `website` on the `users` table. All the data in the column will be lost.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "TaskStatus_new" AS ENUM ('BACKLOG', 'TODO', 'IN_PROGRESS', 'IN_REVIEW', 'DONE');
ALTER TABLE "Task" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "TaskStatusHistory" ALTER COLUMN "oldStatus" TYPE "TaskStatus_new" USING ("oldStatus"::text::"TaskStatus_new");
ALTER TABLE "TaskStatusHistory" ALTER COLUMN "newStatus" TYPE "TaskStatus_new" USING ("newStatus"::text::"TaskStatus_new");
ALTER TABLE "Task" ALTER COLUMN "status" TYPE "TaskStatus_new" USING ("status"::text::"TaskStatus_new");
ALTER TYPE "TaskStatus" RENAME TO "TaskStatus_old";
ALTER TYPE "TaskStatus_new" RENAME TO "TaskStatus";
DROP TYPE "TaskStatus_old";
ALTER TABLE "Task" ALTER COLUMN "status" SET DEFAULT 'TODO';
COMMIT;

-- AlterTable
ALTER TABLE "users" DROP COLUMN "githubProfile",
DROP COLUMN "isEmailVerified",
DROP COLUMN "linkedinProfile",
DROP COLUMN "refreshToken",
DROP COLUMN "role",
DROP COLUMN "website";

-- DropEnum
DROP TYPE "UserRole";
