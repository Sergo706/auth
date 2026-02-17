import { cleanupTestDatabase, createTestUser, setupTestConfiguration } from "./testConfig";
import { afterAll, afterEach, beforeAll, beforeEach, TestContext } from 'vitest';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache';
import { getConfiguration } from '../../src/jwtAuth/config/configuration';

interface CustomTestContext extends TestContext {
  testUserId: number;
  anotherUserId: number;
}

let testUserId: number;
let anotherUserId: number;

beforeAll(async () => {
  setupTestConfiguration();
  const uniq = `${Date.now()}_${Math.random().toString(36).slice(2)}`;
  testUserId = await createTestUser(`test${uniq}@example.com`);
  anotherUserId = await createTestUser(`another${uniq}@example.com`);
});

afterAll(async () => {
  await cleanupTestDatabase();
  const config = getConfiguration();
  if (config.store.main) await config.store.main.end();
  if (config.store.rate_limiters_pool?.store) config.store.rate_limiters_pool.store.end();
});

beforeEach(async (context: CustomTestContext) => {
  context.testUserId = testUserId;
  context.anotherUserId = anotherUserId;
  tokenCache().clear();
});

afterEach(async () => {
  await getConfiguration().store.main.execute('DELETE FROM refresh_tokens WHERE 1=1');
});
