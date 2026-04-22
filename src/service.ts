import express from 'express'
import cookieParser from "cookie-parser";
import { hmacAuth } from './jwtAuth/middleware/HmacAuth.js';
import { httpLogger } from './jwtAuth/middleware/httpLogger.js';
import { ApiResponse, warmUp, defineConfiguration, createTables, getDb } from '@riavzon/bot-detector';
import { configBotDetector } from './jwtAuth/config/botDetectorConfig.js'
import { makeTables } from './jwtAuth/models/schema.js'
import type { Configuration, ConfigurationInput } from './jwtAuth/types/configSchema.js';
import { getProviders as configureOauthProviders }  from './jwtAuth/utils/newOauthProvider.js';
import tokenRotationRoutes from './jwtAuth/routes/TokenRotations.js';
import magicLinks from './jwtAuth/routes/magicLinks.js';
import authenticationRoutes from './jwtAuth/routes/auth.js';
import { configuration } from '~~/config/configuration.js';
import helmet from './jwtAuth/middleware/helmet.js';
import { validateIp } from './jwtAuth/middleware/isIpValid.js';
import { headers } from './jwtAuth/middleware/serviceHeaders.js';
import { notFoundHandler } from './jwtAuth/middleware/notFound.js';
import allowBff from "./jwtAuth/routes/allowBffAccessRoute.js"
import { finalUnHandledErrors } from './jwtAuth/middleware/finalErrorHandler.js';
import { sendOperationalConfig } from './jwtAuth/controllers/sendOprConfig.js';
import fs, { access, constants } from 'node:fs/promises';
import { refreshData } from '~~/utils/refreshData.js';

export async function bootstrapApp(config: ConfigurationInput) { 

    if (config.providers && config.providers.length > 0) {
      const providers = configureOauthProviders(config.providers);
      console.log(`Configured ${providers.length} OAuth providers: ${providers.map(p => p.provider.name).join(', ')}`);
    }

    await configuration({
            ...config,
            store: {
                main: config.store.main,
                rate_limiters_pool: {
                    store: config.store.rate_limiters_pool.store,
                    dbName: config.store.rate_limiters_pool.dbName,
                }
            },
    })
    console.log('Authentication library configured. setting up server.');
    const app = express();
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
        await defineConfiguration(defaultConfig);
    }

    if (hasSettings) {
       const userSettings = configBotDetector(false)!
        await defineConfiguration(userSettings);
    }
    
    await createTables(getDb());
    await makeTables();
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
    app.use(notFoundHandler);
    app.use(finalUnHandledErrors);

    return app;
}

const configPath = process.env.CONFIG_PATH || '/run/app/config.json';

export async function startServer() {
    console.log(`Starting server...`)
    try {

        try {
            await access(configPath, constants.F_OK);
        } catch {
            throw new Error(`[FATAL] Configuration file not found at ${configPath}. \n
                            Please mount a configuration file or set the CONFIG_PATH environment variable.
                        `);
        }

        console.log(`Loading configuration from ${configPath}...`);
        const configContent = await fs.readFile(configPath, 'utf-8');
        const config: Configuration = await JSON.parse(configContent);
        console.log(`Parsing configuration...`);

        const port = config.service?.port ?? 10000;
        const server = config.service?.ipAddress ?? '0.0.0.0';
        const app = await bootstrapApp(config)

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
            refreshData(
                1000 * 60 * 60 * 24,
                1000 * 60 * 60 * 24 * 3,
                1000 * 60 * 60 * 24 * 7,
                config.store.main
            )
        })

    } catch(error) {
       console.error('Failed to start the service:', error);
       process.exit(1);
    }
}

if (process.env.NODE_ENV !== 'test') {
    (async () => {
        await startServer();
    })();
}