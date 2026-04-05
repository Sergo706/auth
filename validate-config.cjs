const fs = require('fs');

const CONFIG_FILE = fs.existsSync('./config.dev.json') ? './config.dev.json' : './config.json';


console.log('JWT Auth Library Configuration Validator\n');

if (!CONFIG_FILE) {
    console.error(`𐄂 Configuration file not found: ${CONFIG_FILE}`);
    console.log('\n Create a configuration file by copying the example:');
    console.log('   cp config.json config.json');
    console.log('   # Edit config.json with your actual settings');
    process.exit(1);
}

let config;
try {
    const configContent = fs.readFileSync(CONFIG_FILE, 'utf8');
    config = JSON.parse(configContent);
    console.log('✓ Configuration file is valid JSON\n');
} catch (error) {
    console.error(`𐄂 Failed to parse configuration file: ${error.message}`);
    process.exit(1);
}

function validateRequired(obj, path, field) {
    if (!obj || obj[field] === undefined || obj[field] === null) {
        console.error(`𐄂 Missing required field: ${path}.${field}`);
        return false;
    }
    return true;
}

function validateOptional(obj, path, field, defaultValue) {
    if (!obj || obj[field] === undefined) {
        console.log(`⚠  Optional field not set: ${path}.${field} (will use default: ${defaultValue})`);
        return false;
    }
    return true;
}

let isValid = true;

// ============================================
// Database Configuration
// ============================================
console.log('⌬⌬⌬ Database Configuration');
if (config.store && config.store.main) {
    const db = config.store.main;
    isValid &= validateRequired(db, 'store.main', 'host');
    isValid &= validateRequired(db, 'store.main', 'user');
    isValid &= validateRequired(db, 'store.main', 'password');
    isValid &= validateRequired(db, 'store.main', 'database');
    
    if (db.host) console.log(`   Host: ${db.host}:${db.port || 3306}`);
    if (db.user) console.log(`   User: ${db.user}`);
    if (db.database) console.log(`   Database: ${db.database}`);
    
    if (config.store.rate_limiters_pool) {
        isValid &= validateRequired(config.store.rate_limiters_pool, 'store.rate_limiters_pool', 'dbName');
    } else {
        console.error('𐄂 Missing: store.rate_limiters_pool configuration');
        isValid = false;
    }
} else {
    console.error('𐄂 Missing: store.main database configuration');
    isValid = false;
}

// ============================================
// JWT Configuration
// ============================================
console.log('\n JWT Configuration');
if (config.jwt) {
    isValid &= validateRequired(config.jwt, 'jwt', 'jwt_secret_key');
    
    if (config.jwt.jwt_secret_key) {
        const secretLength = config.jwt.jwt_secret_key.length;
        if (secretLength < 32) {
            console.error(`𐄂 JWT secret too short: ${secretLength} characters (minimum 32 recommended)`);
            isValid = false;
        } else {
            console.log(`   JWT Secret: ${secretLength} characters ✓`);
        }
    }
    
    if (config.jwt.access_tokens) {
        console.log(`   Access Token Expiry: ${config.jwt.access_tokens.expiresIn || '15m'}`);
        console.log(`   Algorithm: ${config.jwt.access_tokens.algorithm || 'HS256'}`);
        validateOptional(config.jwt.access_tokens, 'jwt.access_tokens', 'audience', 'none');
        validateOptional(config.jwt.access_tokens, 'jwt.access_tokens', 'issuer', 'none');
    }
    
    if (config.jwt.refresh_tokens) {
        isValid &= validateRequired(config.jwt.refresh_tokens, 'jwt.refresh_tokens', 'refresh_ttl');
        isValid &= validateRequired(config.jwt.refresh_tokens, 'jwt.refresh_tokens', 'domain');
        isValid &= validateRequired(config.jwt.refresh_tokens, 'jwt.refresh_tokens', 'MAX_SESSION_LIFE');
        isValid &= validateRequired(config.jwt.refresh_tokens, 'jwt.refresh_tokens', 'maxAllowedSessionsPerUser');
        isValid &= validateRequired(config.jwt.refresh_tokens, 'jwt.refresh_tokens', 'byPassAnomaliesFor');
        
        console.log(`   Refresh Token TTL: ${config.jwt.refresh_tokens.refresh_ttl}ms`);
        console.log(`   Max Sessions per User: ${config.jwt.refresh_tokens.maxAllowedSessionsPerUser}`);
        console.log(`   Max Session Life: ${config.jwt.refresh_tokens.MAX_SESSION_LIFE}ms`);
        console.log(`   Bypass Anomalies For: ${config.jwt.refresh_tokens.byPassAnomaliesFor}ms`);
    } else {
        console.error('𐄂 Missing: jwt.refresh_tokens configuration');
        isValid = false;
    }
} else {
    console.error('𐄂 Missing: jwt configuration');
    isValid = false;
}

// ============================================
// Email Configuration
// ============================================
console.log('\nEmail Configuration');
if (config.email) {
    isValid &= validateRequired(config.email, 'email', 'resend_key');
    isValid &= validateRequired(config.email, 'email', 'email');
    
    if (config.email.resend_key) {
        if (config.email.resend_key.startsWith('re_')) {
            console.log('   Resend API Key: Valid format ✓');
        } else {
            console.log('   Resend API Key: May be test key ⚠');
        }
    }
    
    if (config.email.email) {
        console.log(`   From Email: ${config.email.email}`);
    }
} else {
    console.error('𐄂 Missing: email configuration');
    isValid = false;
}

// ============================================
// Password Security
// ============================================
console.log('\nPassword Security');
if (config.password) {
    isValid &= validateRequired(config.password, 'password', 'pepper');
    
    if (config.password.pepper) {
        const pepperLength = config.password.pepper.length;
        if (pepperLength < 32) {
            console.error(`𐄂 Password pepper too short: ${pepperLength} characters (minimum 32 recommended)`);
            isValid = false;
        } else {
            console.log(`   Password Pepper: ${pepperLength} characters ✓`);
        }
    }
    
    console.log(`   Hash Length: ${config.password.hashLength || 32}`);
    console.log(`   Time Cost: ${config.password.timeCost || 3}`);
    console.log(`   Memory Cost: ${config.password.memoryCost || 65536}`);
} else {
    console.error('𐄂 Missing: password configuration');
    isValid = false;
}

// ============================================
// Magic Links Configuration
// ============================================
console.log('\n★★★ Magic Links Configuration');
if (config.magic_links) {
    isValid &= validateRequired(config.magic_links, 'magic_links', 'jwt_secret_key');
    isValid &= validateRequired(config.magic_links, 'magic_links', 'domain');
    
    if (config.magic_links.jwt_secret_key) {
        const secretLength = config.magic_links.jwt_secret_key.length;
        if (secretLength < 32) {
            console.error(`𐄂 Magic links secret too short: ${secretLength} characters`);
            isValid = false;
        } else {
            console.log(`   Magic Links Secret: ${secretLength} characters ✓`);
        }
    }
    
    if (config.magic_links.domain) {
        if (config.magic_links.domain.startsWith('https://')) {
            console.log(`   Domain: ${config.magic_links.domain} ✓`);
        } else {
            console.log(`   Domain: ${config.magic_links.domain} ⚠ (should use HTTPS in production)`);
        }
    }
    
    console.log(`   Expiry: ${config.magic_links.expiresIn || '15m'}`);
    validateOptional(config.magic_links, 'magic_links', 'maxCacheEntries', 1000);
} else {
    console.error('𐄂 Missing: magic_links configuration');
    isValid = false;
}

// ============================================
// Service Configuration
// ============================================
console.log('\n Service Configuration');
if (config.service) {
    console.log(`   Port: ${config.service.port || 10000}`);
    console.log(`   IP Address: ${config.service.ipAddress || '0.0.0.0'}`);
    
    if (config.service.proxy) {
        isValid &= validateRequired(config.service.proxy, 'service.proxy', 'trust');
        isValid &= validateRequired(config.service.proxy, 'service.proxy', 'ipToTrust');
        console.log(`   Proxy Trust: ${config.service.proxy.trust}`);
        if (config.service.proxy.ipToTrust) {
            console.log(`   Trusted IP: ${config.service.proxy.ipToTrust}`);
        }
    }
    
    if (config.service.Hmac) {
        console.log('HMAC Authentication: Enabled ✓');
        isValid &= validateRequired(config.service.Hmac, 'service.Hmac', 'sharedSecret');
        isValid &= validateRequired(config.service.Hmac, 'service.Hmac', 'clientId');
        isValid &= validateRequired(config.service.Hmac, 'service.Hmac', 'maxClockSkew');
    } else {
        console.log('   HMAC Authentication: Disabled');
    }
} else {
    console.log('   Using default service configuration');
}

// ============================================
// Telegram Integration
// ============================================
console.log('\n Telegram Integration');
if (config.telegram) {
    isValid &= validateRequired(config.telegram, 'telegram', 'token');
    
    if (config.telegram.token) {
        console.log('   Telegram Bot: Configured ✓');
        console.log(`   Chat ID: ${config.telegram.chatID || 'Not set (notifications disabled)'}`);
        validateOptional(config.telegram, 'telegram', 'allowedUser', 'none');
    }
} else {
    console.error('𐄂 Missing: telegram configuration');
    isValid = false;
}

// ============================================
// Bot Detector Configuration
// ============================================
console.log('\n🤖 Bot Detector Configuration');
if (config.botDetector) {
    if (config.botDetector.enableBotDetector === true) {
        console.log('   Bot Detector: Enabled ✓');
        if (config.botDetector.settings) {
            console.log('   Custom Settings: Configured');
        } else {
            console.log('   Custom Settings: Using defaults');
        }
    } else if (config.botDetector.enableBotDetector === false) {
        console.log('   Bot Detector: Disabled ⚠');
    } else {
        console.error('𐄂 Invalid botDetector.enableBotDetector value (must be true or false)');
        isValid = false;
    }
} else {
    console.error('𐄂 Missing: botDetector configuration');
    isValid = false;
}

// ============================================
// HTML Sanitizer Configuration
// ============================================
console.log('\n🧹 HTML Sanitizer Configuration');
if (config.htmlSanitizer) {
    console.log(`   Irritation Count: ${config.htmlSanitizer.IrritationCount || 50}`);
    console.log(`   Max Allowed Input Length: ${config.htmlSanitizer.maxAllowedInputLength || 50000}`);
} else {
    console.error('𐄂 Missing: htmlSanitizer configuration');
    isValid = false;
}

// ============================================
// Trust User Device On Auth
// ============================================
console.log('\n🔐 Trust User Device On Auth');
if (config.trustUserDeviceOnAuth !== undefined) {
    console.log(`   Trust User Device On Auth: ${config.trustUserDeviceOnAuth}`);
} else {
    console.log('   Trust User Device On Auth: true (default)');
}

// ============================================
// OAuth Providers Configuration
// ============================================
console.log('\n🔗 OAuth Providers Configuration');
if (config.providers && Array.isArray(config.providers)) {
    if (config.providers.length > 0) {
        console.log(`   Configured Providers: ${config.providers.length}`);
        config.providers.forEach((provider, i) => {
            console.log(`     ${i + 1}. ${provider.name || 'Unknown'}`);
        });
    } else {
        console.log('   No OAuth providers configured');
    }
} else {
    console.log('   OAuth Providers: Not configured (optional)');
}

// ============================================
// Rate Limiting Configuration
// ============================================
console.log('\n⚡ Rate Limiting Configuration');
if (config.rate_limiters) {
    const limiters = Object.keys(config.rate_limiters);
    console.log(`   Configured Limiters: ${limiters.join(', ')}`);
    
    const allLimiters = [
        'linkVerificationLimiter',
        'loginLimiters', 
        'oauthLimiters',
        'signupLimiters', 
        'tempPostRoutesLimiters',
        'tokenLimiters', 
        'initPasswordResetLimiters', 
        'emailMfaLimiters'
    ];
    
    allLimiters.forEach(limiter => {
        if (config.rate_limiters[limiter]) {
            console.log(`   ${limiter}: ✓`);
        } else {
            console.log(`   ${limiter}: ⚠ (using defaults)`);
        }
    });
} else {
    console.log('   Rate Limiters: Using all defaults ⚠');
}

// ============================================
// Log Level
// ============================================
console.log('\n📝 Logging Configuration');
const validLogLevels = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];
if (config.logLevel) {
    if (validLogLevels.includes(config.logLevel)) {
        console.log(`   Log Level: ${config.logLevel} ✓`);
    } else {
        console.error(`𐄂 Invalid log level: ${config.logLevel} (must be one of: ${validLogLevels.join(', ')})`);
        isValid = false;
    }
} else {
    console.log('   Log Level: info (default)');
}

// ============================================
// Security Checklist
// ============================================
console.log('\nSecurity Checklist');
const secrets = [
    { name: 'JWT Secret', value: config.jwt?.jwt_secret_key },
    { name: 'Magic Links Secret', value: config.magic_links?.jwt_secret_key },
    { name: 'Password Pepper', value: config.password?.pepper },
    { name: 'Database Password', value: config.store?.main?.password },
    { name: 'HMAC Shared Secret', value: config.service?.Hmac?.sharedSecret },
];

secrets.forEach(secret => {
    if (secret.value) {
        if (secret.value.includes('test') || secret.value.includes('dev') || secret.value.includes('example')) {
            console.error(`𐄂 ${secret.name}: Contains test/dev keywords (not for production!)`);
            isValid = false;
        } else if (secret.value.length < 16) {
            console.error(`𐄂 ${secret.name}: Too short for production use`);
            isValid = false;
        } else {
            console.log(`   ${secret.name}: Appears secure ✓`);
        }
    }
});

// ============================================
// Final Summary
// ============================================
console.log('\n' + '='.repeat(50));
if (isValid) {
    console.log('✓ Configuration validation passed!');
    console.log('\n Your configuration is ready for deployment.');
    console.log('\nNext steps:');
    console.log('1. Ensure your MySQL database is running and accessible');
    console.log('2. Create the required database tables: npm run build:createTables');
    console.log('3. Deploy using Docker: ./start.sh');
    console.log('4. Test the service: curl http://localhost:10000/health');
} else {
    console.log('𐄂 Configuration validation failed!');
    console.log('\n Please fix the errors above before deployment.');
    console.log('\n Documentation:');
    console.log('   • Configuration Guide: CONFIGURATION.md');
    console.log('   • Deployment Guide: DEPLOYMENT.md');
    console.log('   • Development Setup: DEVELOPMENT.md');
    process.exit(1);
}

console.log('\nConfiguration Summary:');
console.log(`   Database: ${config.store?.main?.database} @ ${config.store?.main?.host}`);
console.log(`   Service Port: ${config.service?.port || 10000}`);
console.log(`   Bot Detector: ${config.botDetector?.enableBotDetector ? 'Enabled' : 'Disabled'}`);
console.log(`   Trust Device On Auth: ${config.trustUserDeviceOnAuth ?? true}`);
console.log(`   Log Level: ${config.logLevel || 'info'}`);
console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
