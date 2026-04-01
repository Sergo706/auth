import { ConfigurationInput } from "~~/types/configSchema.js";

export const dbConfig = { 
    host: '127.0.0.1',
    port: 3309,
    user: 'sergio',
    password: 'test',
    database: 'auth_tests',
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0,
    timezone: '+00:00',
}

export const config: ConfigurationInput = {
    store: {
        main: dbConfig,
        rate_limiters_pool: {
            store: dbConfig,
            dbName: 'auth_tests'
        }
    },
    service: {
        Hmac: {
            sharedSecret: '1234567890',
            clientId: '1234',
            maxClockSkew: 300000
        },
        proxy: {
            trust: true,
            ipToTrust: '172.29.20.1',
            server: "172.29.20.1"
        },
        port: 10002,
        ipAddress: '0.0.0.0',
        clientIp: '172.29.20.1'
    },
    password: {
        pepper: 'secure',
        hashLength: 50,
        timeCost: 4,
        memoryCost: 262144
    },
    botDetector: {
        enableBotDetector: true
    },
    htmlSanitizer: {
        maxAllowedInputLength: 50000,
        IrritationCount: 50
    },
    magic_links: {
        jwt_secret_key: "super_long_secret",
        expiresIn: "20m",
        domain: "http://localhost:10002",
        notificationEmail: {
            privacyPolicyLink: 'http://localhost:10002/link',
            contactPageLink: 'http://localhost:10002/link',
            changePasswordPageLink: 'http://localhost:10002/link',
            loginPageLink: 'http://localhost:10002/link'
        }
    },
    providers: [
        {
            name: 'google',
            fields: {
                iss: "safeString?",
                azp: "safeString?",
                sub: "string",
                email: "safeString",
                email_verified: "boolean",
                name: "safeString",
                given_name: "safeString",
                picture: "safeString",
                family_name: "safeString?",
                locale: "safeString?"
            },
        },

        {
            name: "github",
            useStandardProfile: true
        },
        {
            name: "x",
            useStandardProfile: true
        },
        {
            name: "linkedin",
            useStandardProfile: true
        }
    ],
    jwt: {
        jwt_secret_key: "super_long_secret",
        access_tokens: {
            expiresIn: "15m",
            expiresInMs: 900000,
            algorithm: "HS512"
        },
        refresh_tokens: {
            rotateOnEveryAccessExpiry: false,
            refresh_ttl: 259200000,
            domain: "localhost",
            MAX_SESSION_LIFE: 2592000000,
            maxAllowedSessionsPerUser: 5,
            byPassAnomaliesFor: 10800000
        }
    },
    email: {
        resend_key: "1234",
        email: "noreply@riavzon.com"
    },
    logLevel: "debug"
}