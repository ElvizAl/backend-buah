/*
  Warnings:

  - A unique constraint covering the columns `[userId,purpose]` on the table `VerificationCode` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "VerificationCode_userId_key";

-- CreateIndex
CREATE UNIQUE INDEX "VerificationCode_userId_purpose_key" ON "VerificationCode"("userId", "purpose");
