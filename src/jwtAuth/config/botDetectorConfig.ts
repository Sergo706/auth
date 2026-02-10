import { getConfiguration } from "./configuration.js"
import { BotDetectorConfig }from "@riavzon/botdetector"

export  function configBotDetector(useDefault: boolean): void |  BotDetectorConfig{
    const config = getConfiguration()


    const defaultSettings: BotDetectorConfig = {
        storeAndTelegram: {
                store: {
                    main: config.store.main
                },
                telegram: {
                    enableTelegramLogger: false
                }
        },
        banScore: 10,
        maxScore: 30,
        proxy: true,
        restoredReputaionPoints: 1,
        setNewComputedScore: false,
        banUnlistedBots: true,
        whiteList: ["172.18.0.1", "172.29.20.1", "172.21.10.1", "127.0.0.1", "172.20.5.4", "172.21.10.4", "::ffff:127.0.0.1"],
       checksTimeRateControl: {
            checkEveryReqest: true,
            checkEvery: 1000 * 60 * 5, 
        },
        penalties: {
            ipInvalid: 10,
            behaviorTooFast: {
                behaviorPenalty: 8,
                behavioural_window: 60_000, //ms
                behavioural_threshold: 30 //hits
            },
            headerOptions: {
                weightPerMustHeader: 2,
                postManOrInsomiaHeaders: 8,
                AJAXHeaderExists: 3,
                ommitedAcceptLanguage: 3,
                connectionHeaderIsClose: 2,
                originHeaderIsNULL: 2,
                originHeaderMissmatch: 3,

             acceptHeader: {
                ommitedAcceptHeader: 3,
                shortAcceptHeader: 4,
                acceptIsNULL: 3,
                },

                hostMismatchWeight: 4,
                },
            pathTraveler: {
                maxIterations: 3,
                maxPathLength: 2048,
                pathLengthToLong: 10,
                longDecoding: 10,
            },    
            bannedCountries: [
                "bangladesh",
                "algeria",
                "bahrain",
                "belarus",
                "ukraine",
                "russia",
                "china",
                "india",
                "pakistan",
                "vietnam",
                "chad",
                "brazil",
                "nigeria",
                "iran",
                "germany",
                ],
            headlessBrowser: 10,
            shortUserAgent: 8,
            cliOrLibrary: 10,
            internetExplorer: 10,
            kaliLinuxOS: 4,
            cookieMissing: 8, 
            countryUnknown: 2,
            proxyDetected: 4,
            hostingDetected: 4,
            timezoneUnknown: 1,
            ispUnknown: 1,
            regionUnknown: 1,
            latLonUnknown: 1,
            orgUnknown: 1,
            desktopWithoutOS: 1,
            deviceVendorUnknown: 1,
            browserTypeUnknown: 1,
            browserVersionUnknown: 1,
            districtUnknown: 0.5,
            cityUnknown: 0.5,
            browserNameUnknown: 1,
            noModel: 0.5,
            localeMismatch: 4,
            tzMismatch: 3,
            tlsCheckFailed: 6,
            metaUaCheckFailed: 0, 
            badGoodbot: 10,   
        },
    checks: {
      enableIpChecks: true,
      enableGoodBotsChecks: true,
      enableBehaviorRateCheck: true,
      enableProxyIspCookiesChecks: true,
      enableUaAndHeaderChecks: true,
      enableBrowserAndDeviceChecks: true,
      enableGeoChecks: true,
      enableLocaleMapsCheck: true,
      enableTimeZoneMapper: true
    },
    punishmentType: {
        enableFireWallBan: false
    },
    logLevel: 'info'

    }

    const passiveMode: BotDetectorConfig = {
        storeAndTelegram: {
            store: {
                    main: config.store.main
            },
            telegram: {
                    enableTelegramLogger: false
            }
        },
        banScore: 100,
        maxScore: 300,
        proxy: true,
        restoredReputaionPoints: 1,
        setNewComputedScore: false,
        banUnlistedBots: true,
        whiteList: ["172.18.0.1","172.29.20.1", "172.21.10.1", "127.0.0.1", "172.20.5.4", "172.21.10.4", "::ffff:127.0.0.1"],
       checksTimeRateControl: {
            checkEveryReqest: true,
            checkEvery: 1000 * 60 * 5, 
        },
        penalties: {
            ipInvalid: 0,
            behaviorTooFast: {
                behaviorPenalty: 0,
                behavioural_window: 60_000, 
                behavioural_threshold: 30
            },
            headerOptions: {
                weightPerMustHeader: 2,
                postManOrInsomiaHeaders: 8,
                AJAXHeaderExists: 3,
                ommitedAcceptLanguage: 3,
                connectionHeaderIsClose: 2,
                originHeaderIsNULL: 2,
                originHeaderMissmatch: 3,

             acceptHeader: {
                ommitedAcceptHeader: 3,
                shortAcceptHeader: 4,
                acceptIsNULL: 3,
                },

                hostMismatchWeight: 4,
                },
            pathTraveler: {
                maxIterations: 3,
                maxPathLength: 2048,
                pathLengthToLong: 10,
                longDecoding: 10,
            },    
            bannedCountries: [],
            headlessBrowser: 10,
            shortUserAgent: 8,
            cliOrLibrary: 10,
            internetExplorer: 10,
            kaliLinuxOS: 4,
            cookieMissing: 8, 
            countryUnknown: 2,
            proxyDetected: 4,
            hostingDetected: 4,
            timezoneUnknown: 1,
            ispUnknown: 1,
            regionUnknown: 1,
            latLonUnknown: 1,
            orgUnknown: 1,
            desktopWithoutOS: 1,
            deviceVendorUnknown: 1,
            browserTypeUnknown: 1,
            browserVersionUnknown: 1,
            districtUnknown: 0.5,
            cityUnknown: 0.5,
            browserNameUnknown: 1,
            noModel: 0.5,
            localeMismatch: 4,
            tzMismatch: 3,
            tlsCheckFailed: 6,
            metaUaCheckFailed: 0, 
            badGoodbot: 10,   
        },
    checks: {
      enableIpChecks: false,
      enableGoodBotsChecks: false,
      enableBehaviorRateCheck: false,
      enableProxyIspCookiesChecks: false,
      enableUaAndHeaderChecks: false,
      enableBrowserAndDeviceChecks: false,
      enableGeoChecks: false,
      enableLocaleMapsCheck: false,
      enableTimeZoneMapper: false
    },
    punishmentType: {
        enableFireWallBan: false
    },
        logLevel: 'warn'
    }

    if (!config.botDetector.enableBotDetector) return passiveMode;
    const botDetectorSettings = config.botDetector.settings?.botDetectorConfig

    if (!useDefault) return botDetectorSettings;
    
    return defaultSettings;
}
