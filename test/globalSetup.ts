import { configuration } from "../src/jwtAuth/config/configuration.js";
import { config, dbConfig } from './configs/config.js';
import mysql2 from 'mysql2/promise';
import { makeTables } from "~~/models/schema.js";
import { createTables, getDb, defineConfiguration, BotDetectorConfigInput } from "@riavzon/bot-detector";
import { configBotDetector } from "~~/config/botDetectorConfig.js";
import { run } from "@riavzon/utils/server";
import type { TestProject } from 'vitest/node'
import { createTestUser } from "./test-utils/testUser.js";
import 'vitest';
import { spawn } from "child_process";



let testUserId: number;
let anotherUserId: number;
declare module 'vitest' {
  export interface ProvidedContext {
      testUserId: number;
      anotherUserId: number;
  }
}

async function waitForDatabase() {
  const maxRetries = 30;
  const retryInterval = 3000;
  
  for (let i = 0; i < maxRetries; i++) {
      try {
          const connection = await mysql2.createConnection(dbConfig);
          await connection.end();
          return;
        } catch (err) {
            console.log(`Waiting for database... (attempt ${i + 1}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, retryInterval));
        }
    }
    throw new Error('Database failed to start in time');
}
let botDb;

export async function setup(project: TestProject) {
    try {
        await run ('rm -rf auth-logs')
        await run('docker compose -f docker-compose.test.yml up -d mysql-test')
        await waitForDatabase();
        await configuration(config)

        if (!process.env.CI && process.stdout.isTTY) {
            console.log('Running @riavzon/bot-detector init')
            await run('npx @riavzon/bot-detector init --contact="Riavzon - contact@riavzon.com"')
            console.log('@riavzon/bot-detector init completed')
        }

        const botConfig = configBotDetector(true) as BotDetectorConfigInput;
        await defineConfiguration(botConfig)
        console.log('Creating bot detector tables')
        botDb = getDb();
        await createTables(botDb);
        console.log('Created bot detector tables')

        console.log('Creating tables')
        await makeTables();
        console.log('Created tables')

        await run('docker compose -f docker-compose.test.yml up -d')
        const uniq = `${Date.now()}_${Math.random().toString(36).slice(2)}`;

        console.log('Creating users')
        testUserId = await createTestUser(`test${uniq}@example.com`);
        anotherUserId = await createTestUser(`another${uniq}@example.com`);
        console.log('Created users')
        
        project.provide('testUserId', testUserId )
        project.provide('anotherUserId', anotherUserId)
        
    } catch (err) {
        console.error('Test setup failed:', err);
        throw err;
    }
}

export async function teardown() {
    console.log('tearing down')
    await run('docker compose -f docker-compose.test.yml down -v')
    const db = getDb();
    if (db) await db.dispose();
    process.exit(0);
}