import pino from "pino"
/**
 * @description
 * Pauses execution for a given number of milliseconds.
 * @param {number} time
 * @param {pino.Logger} log
 * @returns {Promise<void>}
 * @see {@link ./timeEnum.js}
 * @example
 * await timeEnumeration(1000); // wait 1 second
 */
export async function waitSomeTime(time: number, log: pino.Logger): Promise<void> {
    log.info(`Starting time enumration...`);
    return new Promise(resolve => {
        setTimeout(() => {
            log.info(`Time enumration completed.`);
            resolve();
        }, time);
    });
}
