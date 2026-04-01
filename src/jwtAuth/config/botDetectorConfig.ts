import { getConfiguration } from "./configuration.js"
import type { BotDetectorConfigInput } from "@riavzon/bot-detector"

export function configBotDetector(useDefault: boolean): void | BotDetectorConfigInput {
    const config = getConfiguration()

    const defaultSettings: BotDetectorConfigInput = {
        store: { 
            main: { 
            driver: 'mysql-pool',
            ...config.store.main 
           } 
        },
        
        banScore: 100,
        maxScore: 100,
        restoredReputationPoints: 10,
        setNewComputedScore: false,
        logLevel: 'info',
        whiteList: ["172.18.0.1", "172.29.20.1", "172.21.10.1", "127.0.0.1", "172.20.5.4", "172.21.10.4", "::ffff:127.0.0.1"],
        checksTimeRateControl: {
            checkEveryRequest: true, 
            checkEvery: 1000 * 60 * 5,
        },

        checkers: {
            enableGeoChecks:  { 
                enable: true, 
                bannedCountries: ["bangladesh","algeria","bahrain","belarus","ukraine","russia","china","india","pakistan","vietnam","chad","brazil","nigeria","iran","germany"], 
            },
            honeypot: { 
                enable: true, 
                paths: [] 
            },
        },

    }
    
 const passiveMode: BotDetectorConfigInput = {
     store: { 
        main: { 
            driver: 'mysql-pool', 
            ...config.store.main 
        } 
    },
     banScore: 100,
     maxScore: 300,
     restoredReputationPoints: 1,
     setNewComputedScore: false,
     whiteList: ["172.18.0.1", "172.29.20.1", "172.21.10.1", "127.0.0.1", "172.20.5.4", "172.21.10.4", "::ffff:127.0.0.1"],
     checksTimeRateControl: { checkEveryRequest: true, checkEvery: 1000 * 60 * 5 },
     logLevel: 'warn',
     checkers: {
         enableIpChecks: { enable: false },
         enableGoodBotsChecks: { enable: false },
         enableBehaviorRateCheck: { enable: false },
         enableProxyIspCookiesChecks: { enable: false },
         enableUaAndHeaderChecks: { enable: false },
         enableBrowserAndDeviceChecks: { enable: false },
         enableGeoChecks: { enable: false },
         localeMapsCheck: { enable: false },
         enableTimezoneConsistency: { enable: false },
         knownBadUserAgents: { enable: false },
         enableKnownThreatsDetections: { enable: false },
         enableAsnClassification: { enable: false },
         enableTorAnalysis: { enable: false },
         honeypot: { enable: false },
         enableSessionCoherence: { enable: false },
         enableVelocityFingerprint: { enable: false },
         enableKnownBadIpsCheck: { enable: false },
     }
 }

    if (!config.botDetector.enableBotDetector) return passiveMode;
    const botDetectorSettings = config.botDetector.settings

    if (!useDefault) return botDetectorSettings;
    
    return defaultSettings;
}
