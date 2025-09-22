import { getConfiguration } from "./configuration.js"

export  function configBotDetector(db: any) {
    const config = getConfiguration()
    
    return {
        store: {
            main: db
        },
        telegram: {
            token: config.telegram.token!,
            allowedUser: config.telegram.allowedUser,
            chatID: config.telegram.chatID
        },
        logLevel: config.logLevel
    }
}
