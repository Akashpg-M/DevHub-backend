/*
  Warnings:

  - The `role` column on the `CommunityMember` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - The `role` column on the `users` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - You are about to drop the `Comment` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `CommunityFile` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `CommunityFolder` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `FileHistory` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Kanban` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `KanbanColumn` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `KanbanTask` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Post` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `userId` to the `CommunityInvite` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "TaskPriority" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'URGENT');

-- DropForeignKey
ALTER TABLE "Comment" DROP CONSTRAINT "Comment_authorId_fkey";

-- DropForeignKey
ALTER TABLE "Comment" DROP CONSTRAINT "Comment_postId_fkey";

-- DropForeignKey
ALTER TABLE "CommunityFile" DROP CONSTRAINT "CommunityFile_communityId_fkey";

-- DropForeignKey
ALTER TABLE "CommunityFile" DROP CONSTRAINT "CommunityFile_folderId_fkey";

-- DropForeignKey
ALTER TABLE "CommunityFile" DROP CONSTRAINT "CommunityFile_uploadedBy_fkey";

-- DropForeignKey
ALTER TABLE "CommunityFolder" DROP CONSTRAINT "CommunityFolder_communityId_fkey";

-- DropForeignKey
ALTER TABLE "CommunityFolder" DROP CONSTRAINT "CommunityFolder_createdBy_fkey";

-- DropForeignKey
ALTER TABLE "FileHistory" DROP CONSTRAINT "FileHistory_changedBy_fkey";

-- DropForeignKey
ALTER TABLE "FileHistory" DROP CONSTRAINT "FileHistory_fileId_fkey";

-- DropForeignKey
ALTER TABLE "Kanban" DROP CONSTRAINT "Kanban_communityId_fkey";

-- DropForeignKey
ALTER TABLE "KanbanColumn" DROP CONSTRAINT "KanbanColumn_kanbanId_fkey";

-- DropForeignKey
ALTER TABLE "KanbanTask" DROP CONSTRAINT "KanbanTask_assignedTo_fkey";

-- DropForeignKey
ALTER TABLE "KanbanTask" DROP CONSTRAINT "KanbanTask_columnId_fkey";

-- DropForeignKey
ALTER TABLE "KanbanTask" DROP CONSTRAINT "KanbanTask_communityId_fkey";

-- DropForeignKey
ALTER TABLE "Post" DROP CONSTRAINT "Post_authorId_fkey";

-- DropForeignKey
ALTER TABLE "Post" DROP CONSTRAINT "Post_communityId_fkey";

-- DropForeignKey
ALTER TABLE "TaskChange" DROP CONSTRAINT "TaskChange_taskId_fkey";

-- DropForeignKey
ALTER TABLE "TaskStatusHistory" DROP CONSTRAINT "TaskStatusHistory_taskId_fkey";

-- AlterTable
ALTER TABLE "CommunityInvite" ADD COLUMN     "userId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "CommunityMember" DROP COLUMN "role",
ADD COLUMN     "role" TEXT NOT NULL DEFAULT 'VIEWER';

-- AlterTable
ALTER TABLE "users" DROP COLUMN "role",
ADD COLUMN     "role" TEXT NOT NULL DEFAULT 'USER';

-- DropTable
DROP TABLE "Comment";

-- DropTable
DROP TABLE "CommunityFile";

-- DropTable
DROP TABLE "CommunityFolder";

-- DropTable
DROP TABLE "FileHistory";

-- DropTable
DROP TABLE "Kanban";

-- DropTable
DROP TABLE "KanbanColumn";

-- DropTable
DROP TABLE "KanbanTask";

-- DropTable
DROP TABLE "Post";

-- DropEnum
DROP TYPE "CommunityRole";

-- DropEnum
DROP TYPE "UserRole";

-- CreateTable
CREATE TABLE "Project" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "emoji" TEXT NOT NULL DEFAULT '📊',
    "communityId" TEXT NOT NULL,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Project_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProjectMember" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'MEMBER',
    "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ProjectMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Task" (
    "id" TEXT NOT NULL,
    "taskCode" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "status" "TaskStatus" NOT NULL DEFAULT 'TODO',
    "priority" "TaskPriority" NOT NULL DEFAULT 'MEDIUM',
    "dueDate" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "projectId" TEXT NOT NULL,
    "communityId" TEXT NOT NULL,
    "assignedToId" TEXT,
    "createdById" TEXT NOT NULL,

    CONSTRAINT "Task_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Project_communityId_idx" ON "Project"("communityId");

-- CreateIndex
CREATE INDEX "Project_createdById_idx" ON "Project"("createdById");

-- CreateIndex
CREATE UNIQUE INDEX "Project_name_communityId_key" ON "Project"("name", "communityId");

-- CreateIndex
CREATE INDEX "ProjectMember_projectId_idx" ON "ProjectMember"("projectId");

-- CreateIndex
CREATE INDEX "ProjectMember_userId_idx" ON "ProjectMember"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "ProjectMember_projectId_userId_key" ON "ProjectMember"("projectId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "Task_taskCode_key" ON "Task"("taskCode");

-- CreateIndex
CREATE INDEX "Task_projectId_idx" ON "Task"("projectId");

-- CreateIndex
CREATE INDEX "Task_communityId_idx" ON "Task"("communityId");

-- CreateIndex
CREATE INDEX "Task_assignedToId_idx" ON "Task"("assignedToId");

-- CreateIndex
CREATE INDEX "Task_createdById_idx" ON "Task"("createdById");

-- AddForeignKey
ALTER TABLE "CommunityInvite" ADD CONSTRAINT "CommunityInvite_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Project" ADD CONSTRAINT "Project_communityId_fkey" FOREIGN KEY ("communityId") REFERENCES "Community"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Project" ADD CONSTRAINT "Project_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProjectMember" ADD CONSTRAINT "ProjectMember_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProjectMember" ADD CONSTRAINT "ProjectMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_communityId_fkey" FOREIGN KEY ("communityId") REFERENCES "Community"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_assignedToId_fkey" FOREIGN KEY ("assignedToId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
