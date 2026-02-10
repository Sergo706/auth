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
import mysql from 'mysql2'
import { authenticationRoutes, configuration, configureOauthProviders, magicLinks, tokenRotationRoutes } from './main.js';
import helmet from './jwtAuth/middleware/helmet.js';
import { validateIp } from './jwtAuth/middleware/isIpValid.js';
import { headers } from './jwtAuth/middleware/serviceHeaders.js';
import { notFoundHandler } from './jwtAuth/middleware/notFound.js';
import allowBff from "./jwtAuth/routes/allowBffAccessRoute.js"
import { finalUnHandledErrors } from './jwtAuth/middleware/finalErrorHandler.js';
import { sendOperationalConfig } from './jwtAuth/controllers/sendOprConfig.js';

const configPath = process.env.CONFIG_PATH || '/run/app/config.json';

/**
 * Bootstraps and starts the HTTP service.
 *
 * - Loads configuration from `CONFIG_PATH` and initializes DB pools.
 * - Configures OAuth providers, security middleware and request guards.
 * - Registers authentication, token rotation and BFF routes.
 * - Adds health check, `notFoundHandler`, and `finalUnHandledErrors` handlers.
 * - Starts listening on the configured address and port.
 */
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
       const rateLimiterPool = mysql.createPool(config.store.main);
       
    if (config.providers && config.providers.length > 0) {
      const providers = configureOauthProviders(config.providers);
      console.log(`Configured ${providers.length} OAuth providers: ${providers.map(p => p.provider.name).join(', ')}`);
    }
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
        app.get('/health', (req, res) => res.status(200).send('OK'));
            const defaultConfig = configBotDetector(true);

            const hasSettings = config.botDetector.enableBotDetector && config.botDetector.settings;
            
            if (defaultConfig && !hasSettings) {
                initBotDetector(defaultConfig);
            }

            if (hasSettings) {
               const userSettings = configBotDetector(false)!
                initBotDetector(userSettings);
            }   

        app.use(httpLogger)
        app.disable('x-powered-by')
        app.use(helmet)
        app.use(headers)
        app.use(validateIp)
        if (config.service?.Hmac) {
            app.use(hmacAuth);
        };
        app.use(express.json());
        app.use(cookieParser());
        app.use(ApiResponse);  
        app.use(authenticationRoutes)
        app.use(tokenRotationRoutes)
        app.use(magicLinks)
        app.use(allowBff)
        app.use('/operational/config', sendOperationalConfig)
        await warmUp();
        await loadUaPatterns();
        app.use(notFoundHandler);
        app.use(finalUnHandledErrors);
        if (process.env.SKIP_CONFIG_UNLINK !== 'true') {
            try {
                 await fs.unlink(configPath);
                 console.log(`Config file deleted`)
                } catch (error) {
                    console.error(`Failed to delete config file`);
                    process.exit(1)
            }
        } else {
            console.log(`SKIP_CONFIG_UNLINK is set, keeping config file at ${configPath}`);
        }
        app.listen(port, server, () => {
            console.log(`Service is running at ${server}:${port}`)
        })
    } catch(error) {
       console.error('Failed to start the service:', error);
       process.exit(1);
    }
}
startServer();