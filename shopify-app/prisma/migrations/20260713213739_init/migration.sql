-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "shop" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "isOnline" BOOLEAN NOT NULL DEFAULT false,
    "scope" TEXT,
    "expires" DATETIME,
    "accessToken" TEXT NOT NULL,
    "userId" BIGINT,
    "firstName" TEXT,
    "lastName" TEXT,
    "email" TEXT,
    "accountOwner" BOOLEAN NOT NULL DEFAULT false,
    "locale" TEXT,
    "collaborator" BOOLEAN DEFAULT false,
    "emailVerified" BOOLEAN DEFAULT false
);

-- CreateTable
CREATE TABLE "ShopSettings" (
    "shop" TEXT NOT NULL PRIMARY KEY,
    "acceptVerifiedAgents" BOOLEAN NOT NULL DEFAULT true,
    "defaultDiscountPct" INTEGER NOT NULL DEFAULT 10,
    "maxDiscountPct" INTEGER NOT NULL DEFAULT 20,
    "identityOnlyDiscountPct" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "VerificationEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "shop" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "protocol" TEXT,
    "platform" TEXT,
    "outcome" TEXT NOT NULL,
    "reason" TEXT,
    "identityOnly" BOOLEAN NOT NULL DEFAULT false,
    "discountPct" INTEGER,
    "discountCode" TEXT
);

-- CreateTable
CREATE TABLE "AgentCommerceEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "shop" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "kind" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "orderName" TEXT,
    "totalMinor" INTEGER,
    "currency" TEXT,
    "discountCode" TEXT,
    "platform" TEXT,
    "protocol" TEXT
);

-- CreateIndex
CREATE INDEX "VerificationEvent_shop_createdAt_idx" ON "VerificationEvent"("shop", "createdAt");

-- CreateIndex
CREATE INDEX "VerificationEvent_shop_discountCode_idx" ON "VerificationEvent"("shop", "discountCode");

-- CreateIndex
CREATE INDEX "AgentCommerceEvent_shop_createdAt_idx" ON "AgentCommerceEvent"("shop", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AgentCommerceEvent_shop_kind_sourceId_key" ON "AgentCommerceEvent"("shop", "kind", "sourceId");
