-- Distinguish a proxy-delivered agent request from a merchant-initiated test
-- visit. Existing rows are all proxy-delivered, which is what the default
-- backfills them to.
ALTER TABLE "VerificationEvent" ADD COLUMN "source" TEXT NOT NULL DEFAULT 'storefront';
