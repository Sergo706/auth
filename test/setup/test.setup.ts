import mysql2 from 'mysql2/promise';
import mysql from 'mysql2';
import { cleanupTestDatabase, createTestUser, setupTestConfiguration } from "./testConfig";
import { afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache';


declare module 'vitest' {
  export interface TestContext {
    testUserId: number;
    anotherUserId: number;
    mainPool: mysql2.Pool;
    rateLimiterPool: mysql.Pool;
  }
}

  let mainPool: mysql2.Pool;
  let rateLimiterPool: mysql.Pool;
  let testUserId: number;
  let anotherUserId: number;

beforeAll(async () => {
    const pools = setupTestConfiguration();
    mainPool = pools.mainPool;
    rateLimiterPool = pools.rateLimiterPool;
    const uniq = `${Date.now()}_${Math.random().toString(36).slice(2)}`;
    testUserId = await createTestUser(`test${uniq}@example.com`);
    anotherUserId = await createTestUser(`another${uniq}@example.com`);
  });
  
    afterAll(async () => {
    await cleanupTestDatabase();
    if (mainPool) await mainPool.end();
    if (rateLimiterPool) rateLimiterPool.end();
  });

  beforeEach(async (context) => {
      context.mainPool = mainPool;
      context.rateLimiterPool = rateLimiterPool;
      context.testUserId = testUserId;
      context.anotherUserId = anotherUserId;

        const cache = tokenCache();
        if (typeof cache.clear === 'function') {
          cache.clear();
        } else {
          if (typeof cache.keys === 'function') {
            for (const k of cache.keys()) {
              cache.delete(k);
            }
          }
        }
  });
  
  afterEach( async (context) => {
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE 1=1');
});

