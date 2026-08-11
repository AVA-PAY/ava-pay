-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "shop" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "isOnline" BOOLEAN NOT NULL DEFAULT false,
    "scope" TEXT,
    "expires" TIMESTAMP(3),
    "accessToken" TEXT NOT NULL,
    "userId" BIGINT,
    "firstName" TEXT,
    "lastName" TEXT,
    "email" TEXT,
    "accountOwner" BOOLEAN NOT NULL DEFAULT false,
    "locale" TEXT,
    "collaborator" BOOLEAN DEFAULT false,
    "emailVerified" BOOLEAN DEFAULT false,
    "refreshToken" TEXT,
    "refreshTokenExpires" TIMESTAMP(3),

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ShopSettings" (
    "shop" TEXT NOT NULL,
    "acceptVerifiedAgents" BOOLEAN NOT NULL DEFAULT true,
    "defaultDiscountPct" INTEGER NOT NULL DEFAULT 10,
    "maxDiscountPct" INTEGER NOT NULL DEFAULT 20,
    "identityOnlyDiscountPct" INTEGER NOT NULL DEFAULT 0,
    "policyJson" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ShopSettings_pkey" PRIMARY KEY ("shop")
);

-- CreateTable
CREATE TABLE "VerificationEvent" (
    "id" TEXT NOT NULL,
    "shop" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "protocol" TEXT,
    "platform" TEXT,
    "outcome" TEXT NOT NULL,
    "reason" TEXT,
    "identityOnly" BOOLEAN NOT NULL DEFAULT false,
    "discountPct" INTEGER,
    "discountCode" TEXT,

    CONSTRAINT "VerificationEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AgentCommerceEvent" (
    "id" TEXT NOT NULL,
    "shop" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "kind" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "orderName" TEXT,
    "totalMinor" INTEGER,
    "currency" TEXT,
    "discountCode" TEXT,
    "platform" TEXT,
    "protocol" TEXT,

    CONSTRAINT "AgentCommerceEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "VerificationEvent_shop_createdAt_idx" ON "VerificationEvent"("shop", "createdAt");

-- CreateIndex
CREATE INDEX "VerificationEvent_shop_discountCode_idx" ON "VerificationEvent"("shop", "discountCode");

-- CreateIndex
CREATE INDEX "AgentCommerceEvent_shop_createdAt_idx" ON "AgentCommerceEvent"("shop", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AgentCommerceEvent_shop_kind_sourceId_key" ON "AgentCommerceEvent"("shop", "kind", "sourceId");

