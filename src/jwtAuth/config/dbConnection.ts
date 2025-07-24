import type { Pool as PromisePool } from 'mysql2/promise';
import type { Pool as CallbackPool } from 'mysql2';
import { getConfiguration } from './configuration.js';


let mainPool: PromisePool | undefined;
let limiterPool: CallbackPool | undefined;

/**
 * Returns the main promise-based MySQL pool used by the auth lib.
 * This pool must be injected via `configuration({ store: { main: ... } })`.
 */
export function getPool(): PromisePool {
  if (mainPool) return mainPool;

  const { store } = getConfiguration();

  if (!store?.main) {
    throw new Error('Auth lib: store.main (MySQL pool) must be provided in configuration()');
  }

  mainPool = store.main;
  console.log('Auth lib connected to main DB pool');
  return mainPool;
}

export function poolForLibrary(): CallbackPool {
  if (limiterPool) return limiterPool;

  const { store } = getConfiguration();

  if (!store?.rate_limiters_pool?.store) {
    throw new Error('Auth lib: store.rate_limiters_pool.store must be provided for limiter support');
  }

  limiterPool = store.rate_limiters_pool.store as CallbackPool;
  console.log('Auth lib connected to limiter pool');
  return limiterPool;
}
