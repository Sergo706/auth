import pino from "pino"

export async function waitSomeTime(time: number, log: pino.Logger): Promise<void> {
    log.info(`Starting time enumration...`)
    setTimeout(() => {log.info(`Time enumration completed.`)}, time)
}