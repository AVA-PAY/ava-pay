/**
 * I/O around the test visit: read the merchant's settings, call the hosted
 * verifier, write the VerificationEvent. See test-visit.ts for the feature.
 *
 * Deliberately no Admin API use. A test visit never mints a discount code, so
 * this path needs no `admin` context and cannot write anything into the
 * merchant's store beyond the event row it is recording.
 */

import prisma from '../db.server.js';
import { getAvaPayClient } from './ava.server.js';
import { getShopSettings } from './settings.server.js';
import { decideTestVisit, type TestVisitResult } from './test-visit.js';
import { buildTestVisitRequest } from './test-visit-request.js';

export async function sendTestVisit(shop: string): Promise<TestVisitResult> {
  const request = buildTestVisitRequest(shop);
  const settings = await getShopSettings(shop);
  const call = await getAvaPayClient().verify(request);

  const { event, result } = decideTestVisit(settings, call, request);

  await prisma.verificationEvent.create({ data: { shop, ...event } });

  return result;
}
