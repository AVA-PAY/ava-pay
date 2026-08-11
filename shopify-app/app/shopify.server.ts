import '@shopify/shopify-app-react-router/adapters/node';
import {
  ApiVersion,
  AppDistribution,
  shopifyApp,
} from '@shopify/shopify-app-react-router/server';
import { PrismaSessionStorage } from '@shopify/shopify-app-session-storage-prisma';
import prisma from './db.server.js';

/**
 * Single Shopify app instance. Routes import `authenticate`, `unauthenticated`,
 * and `addDocumentResponseHeaders` from here. Auth, OAuth, and webhook
 * verification are handled by this library — we only own AVA-specific logic.
 */
const shopify = shopifyApp({
  apiKey: process.env.SHOPIFY_API_KEY,
  apiSecretKey: process.env.SHOPIFY_API_SECRET ?? '',
  apiVersion: ApiVersion.January26,
  scopes: process.env.SCOPES?.split(','),
  // SHOPIFY_APP_URL is what the Shopify CLI injects during `shopify app dev`;
  // HOST is kept as a fallback for existing .env files. Don't set HOST in
  // production — react-router-serve interprets it as the bind address.
  appUrl: process.env.SHOPIFY_APP_URL ?? process.env.HOST ?? '',
  authPathPrefix: '/auth',
  sessionStorage: new PrismaSessionStorage(prisma),
  distribution: AppDistribution.AppStore,
  future: {
    // Public apps must use EXPIRING offline access tokens since 2026-04-01.
    // Without this, token exchange mints a non-expiring token and Shopify
    // rejects it with a bare 403 before the query even runs — every Admin API
    // call fails identically, including ones that need no scopes at all, which
    // is exactly what production did on 2026-08-11 once distribution was set
    // to public. The Session model's refreshToken/refreshTokenExpires columns
    // (added 2026-08-10) exist to persist what this flag produces; the library
    // refreshes the token within five minutes of expiry.
    expiringOfflineAccessTokens: true,
  },
});

export default shopify;
export const apiVersion = ApiVersion.January26;
export const addDocumentResponseHeaders = shopify.addDocumentResponseHeaders;
export const authenticate = shopify.authenticate;
export const unauthenticated = shopify.unauthenticated;
export const login = shopify.login;
export const registerWebhooks = shopify.registerWebhooks;
export const sessionStorage = shopify.sessionStorage;
