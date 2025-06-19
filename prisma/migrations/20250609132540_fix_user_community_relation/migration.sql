/*
  Warnings:

  - The values [ASSIGNED] on the enum `TaskStatus` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `role` on the `ProjectMember` table. All the data in the column will be lost.
  - You are about to drop the column `taskCode` on the `Task` table. All the data in the column will be lost.
  - You are about to drop the column `change` on the `TaskChange` table. All the data in the column will be lost.
  - You are about to drop the column `createdAt` on the `TaskChange` table. All the data in the column will be lost.
  - The `role` column on the `users` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - Added the required column `field` to the `TaskChange` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('USER', 'ADMIN', 'SUPER_ADMIN');

-- AlterEnum
BEGIN;
CREATE TYPE "TaskStatus_new" AS ENUM ('TODO', 'IN_PROGRESS', 'REVIEW', 'DONE');
ALTER TABLE "Task" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "TaskStatusHistory" ALTER COLUMN "oldStatus" TYPE "TaskStatus_new" USING ("oldStatus"::text::"TaskStatus_new");
ALTER TABLE "TaskStatusHistory" ALTER COLUMN "newStatus" TYPE "TaskStatus_new" USING ("newStatus"::text::"TaskStatus_new");
ALTER TABLE "Task" ALTER COLUMN "status" TYPE "TaskStatus_new" USING ("status"::text::"TaskStatus_new");
ALTER TYPE "TaskStatus" RENAME TO "TaskStatus_old";
ALTER TYPE "TaskStatus_new" RENAME TO "TaskStatus";
DROP TYPE "TaskStatus_old";
ALTER TABLE "Task" ALTER COLUMN "status" SET DEFAULT 'TODO';
COMMIT;

-- DropForeignKey
ALTER TABLE "CommunityInvite" DROP CONSTRAINT "CommunityInvite_userId_fkey";

-- DropIndex
DROP INDEX "CommunityInvite_communityId_code_key";

-- DropIndex
DROP INDEX "Task_taskCode_key";

-- AlterTable
ALTER TABLE "Project" ALTER COLUMN "emoji" DROP NOT NULL;

-- AlterTable
ALTER TABLE "ProjectMember" DROP COLUMN "role";

-- AlterTable
ALTER TABLE "Task" DROP COLUMN "taskCode";

-- AlterTable
ALTER TABLE "TaskChange" DROP COLUMN "change",
DROP COLUMN "createdAt",
ADD COLUMN     "changedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "field" TEXT NOT NULL,
ADD COLUMN     "newValue" TEXT,
ADD COLUMN     "oldValue" TEXT;

-- AlterTable
ALTER TABLE "users" ALTER COLUMN "provider" SET DEFAULT 'LOCAL',
DROP COLUMN "role",
ADD COLUMN     "role" "UserRole" NOT NULL DEFAULT 'USER';

-- CreateIndex
CREATE INDEX "CommunityInvite_communityId_idx" ON "CommunityInvite"("communityId");

-- CreateIndex
CREATE INDEX "CommunityInvite_userId_idx" ON "CommunityInvite"("userId");

-- AddForeignKey
ALTER TABLE "CommunityInvite" ADD CONSTRAINT "CommunityInvite_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
