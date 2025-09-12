import { getConfiguration } from "./configuration.js"

export  function configBotDetector() {
    const config = getConfiguration()
    return {
        store: {
            main: config.store.main
        },
        telegram: {
            token: config.telegram.token!,
            allowedUser: config.telegram.allowedUser,
            chatID: config.telegram.chatID
        },
        logLevel: config.logLevel
    }
}
