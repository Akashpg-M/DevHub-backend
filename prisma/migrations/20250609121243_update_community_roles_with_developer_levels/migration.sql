/*
  Warnings:

  - The `role` column on the `CommunityMember` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- CreateEnum
CREATE TYPE "CommunityRole" AS ENUM ('OWNER', 'ADMIN', 'MANAGER', 'DEVELOPER_I', 'DEVELOPER_II', 'DEVELOPER_III', 'VIEWER');

-- AlterTable
ALTER TABLE "CommunityMember" DROP COLUMN "role",
ADD COLUMN     "role" "CommunityRole" NOT NULL DEFAULT 'VIEWER';
