import type { Configuration, ConfigurationInput }  from "../types/configSchema.js";
import { configurationSchema } from "../types/configSchema.js";
import { createConfigManager } from "@riavzon/utils";
import { getRoot, resolvePath } from '@riavzon/utils/server';
import { type EmailListRecord } from "@riavzon/shield-base";
import { open, RootDatabase } from 'lmdb';
import { fileURLToPath } from "url";
import path from "path";
import type { Pool as PromisePool } from 'mysql2/promise';
import type { Pool as CallbackPool } from 'mysql2';
import mysql from 'mysql2';
import mysql2 from 'mysql2/promise';

let mainPool: PromisePool | undefined;
let limiterPool: CallbackPool | undefined;
let emailListDb: RootDatabase<EmailListRecord, string>  | undefined;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const {
  defineConfiguration,
  getConfiguration
} = createConfigManager<Configuration>(configurationSchema, "Auth");


// // @ts-check
// main routes and middlewares// The ones that make the lib usable, the "Default"
/**
 * @description
 * The JWT auth library’s configuration object.
 * Contains the core configuration to make the library usable.
 *  
 * @module jwtAuth/config
 * @see {@link ./jwtAuth/types/configSchema.js}
 */

export async function configuration(config: ConfigurationInput): Promise<void>  {

  const initMainPoolTask = () => {
    if (!mainPool) {
         mainPool = mysql2.createPool(config.store.main)
    }
    if (mainPool) console.log("Auth: Main DB pool ready");
  };

  const initEmailListTask = () => {
     if (!emailListDb) {
        const path = resolvePath('disposable-emails.mdb', [
            'email-db',
            'dist/email-db', 
            'src/jwtAuth/email-db'
        ], [], getRoot(__dirname))

        const listDb = open<EmailListRecord, string>({
            path,
            name: 'email',
            compression: true,
            readOnly: true,
            useVersions: true,
            sharedStructuresKey: Symbol.for('structures'),
            pageSize: 4096,
            cache: {
                validated: true
            },
            noReadAhead: true,
            maxReaders: 2024,
        });
        emailListDb = listDb;
        console.log("Auth: emailList DB ready");
     }
  }
  
  const initLimiterPoolTask = () => {
      if (!limiterPool) {
          limiterPool = mysql.createPool(config.store.rate_limiters_pool.store)
      }
      if (limiterPool) console.log("Auth: Limiter pool ready");
    };

  await defineConfiguration(config, [
    initMainPoolTask,
    initLimiterPoolTask,
    initEmailListTask
  ]);
}

export function getPool(): PromisePool {
  if (!mainPool) {
    console.trace("Premature getPool() call");
    throw new Error('Auth: Main DB pool not ready. Call configuration() first.');
  }
  return mainPool;
}

export function poolForLibrary(): CallbackPool {
  if (!limiterPool) {
    console.trace("Premature poolForLibrary() call");
    throw new Error('Auth: Limiter pool not ready. Call configuration() first.');
  }
  return limiterPool;
}

export function getDisposableEmailList(): RootDatabase<EmailListRecord, string> {
   if (!emailListDb) {
       console.trace('Premature getDisposableEmailList() call')
       throw new Error('Auth: emailList not ready. Call configuration() first.');
   }
   return emailListDb;
}

export { getConfiguration };
