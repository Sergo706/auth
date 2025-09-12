import express from 'express'
import cookieParser from "cookie-parser";
import { hmacAuth } from './jwtAuth/middleware/HmacAuth.js';
import { httpLogger } from './jwtAuth/middleware/httpLogger.js';
import { ApiResponse, loadUaPatterns, warmUp, initBotDetector } from '@riavzon/botdetector';
import { configBotDetector } from './jwtAuth/config/botDetectorConfig.js'
import fs from 'node:fs/promises';
import { access, constants } from 'node:fs';
import type { Configuration } from './jwtAuth/types/configSchema.js';
import mysqlPromise from 'mysql2/promise';
import { authenticationRoutes, configuration, magicLinks, tokenRotationRoutes } from './main.js';

const configPath = process.env.CONFIG_PATH || '/app/config.json';

async function startServer() {
      console.log(`Starting server...`)

      
      try {
        access(configPath, constants.F_OK, (err) => {
            if (err) {
            throw new Error(`[FATAL] Configuration file not found at ${configPath}. \n
                Please mount a configuration file or set the CONFIG_PATH environment variable.
                `);
            }
     });
       console.log(`Loading configuration from ${configPath}...`);
       const configContent = await fs.readFile(configPath, 'utf-8');
       const config: Configuration = await JSON.parse(configContent);
       console.log(`Parsing configuration...`);
       const mainPool = mysqlPromise.createPool(config.store.main);
       const rateLimiterPool = config.store.rate_limiters_pool.store;
       configuration({
        ...config,
        store: {
            main: mainPool,
            rate_limiters_pool: {
                store: rateLimiterPool,
                dbName: config.store.rate_limiters_pool.dbName,
            }
        },
       })
        console.log('Authentication library configured. setting up server.');
        const app = express();
        const port = config.service?.port ?? 10000;
        const server = config.service?.ipAddress ?? '0.0.0.0';

        if (config.service?.proxy.trust) {
            app.set("trust proxy", (ip: string) => {
                if (ip === `${config.service?.proxy.server ?? server}` || ip === `${config.service?.proxy.ipToTrust}`) return true;
                return false
            })
        }
        initBotDetector(configBotDetector);
        app.use(httpLogger)
        if (config.service?.Hmac) {
            app.use(hmacAuth);
        };
        app.use(express.json());
        app.use(cookieParser());
        app.use(ApiResponse);  
        app.use(authenticationRoutes)
        app.use(tokenRotationRoutes)
        app.use(magicLinks)

        await warmUp();
        await loadUaPatterns();
        app.get('/health', (req, res) => res.status(200).send('OK'));

        app.listen(port, server, () => {
            console.log(`Service is running at ${server}:${port}`)
        })
    } catch(error) {
       console.error('Failed to start the service:', error);
       process.exit(1);
    } finally {
        try {
            console.log(`Removing configuration file from container filesystem: ${configPath}`);
            await fs.unlink(configPath);
        } catch(error) {
            console.warn(`Could not remove config file: ${error}`);
        }
    }
}
startServer();