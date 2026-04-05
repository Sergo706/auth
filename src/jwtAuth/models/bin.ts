#!/usr/bin/env node

import { getDisposableEmailLmdbList } from "@riavzon/shield-base";
import { makeTables } from "./schema.js";
import { createTables, getDb } from "@riavzon/bot-detector";
import { configuration } from "../config/configuration.js";
import { configBotDetector } from "../config/botDetectorConfig.js";
import { defineConfiguration } from "@riavzon/bot-detector";
import fs from "node:fs/promises";
import { ConfigurationInput } from "~~/types/configSchema.js";

export async function initAuthData(config: ConfigurationInput) {

    await configuration(config);

    const botConfig = configBotDetector(config.botDetector?.enableBotDetector && config.botDetector.settings ? false : true);
    if (botConfig) await defineConfiguration(botConfig);

    await makeTables()
    await createTables(getDb())
    await getDisposableEmailLmdbList('./dist')
}

if (process.argv[1]?.endsWith('bin.mjs') || process.argv[1]?.endsWith('bin.ts')) {
    (async () => {
        const configPath = process.argv[2] || process.env.CONFIG_PATH || './config.json';
        const data = await fs.readFile(configPath, 'utf-8')
        const config = JSON.parse(data) as ConfigurationInput;
        await initAuthData(config);
    })();
}