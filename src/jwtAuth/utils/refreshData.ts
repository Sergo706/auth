import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export function scheduleTask(name: string, cmd: string, args: string[], interval: number) {
    setTimeout(async () => {
        try {
            await execFileAsync('nice', ['-n', '19', cmd, ...args], { 
                maxBuffer: 10 * 1024 * 1024
            });
            console.log(`[Background] ${name} completed successfully.`);
        } catch (err) {
            console.error(`[Background] ${name} error:`, err);
        }

        scheduleTask(name, cmd, args, interval);
    }, interval);
}

export function refreshData(dataSourceInterval: number, generatorInterval: number, disposableEmailList: number) {
    scheduleTask('bot-detector refresh', './node_modules/.bin/bot-detector', ['refresh'], dataSourceInterval);
    scheduleTask('bot-detector generate', './node_modules/.bin/bot-detector', ['generate'], generatorInterval);
    scheduleTask('shield-base email', './node_modules/.bin/shield-base', ['--email', '--path=dist'], disposableEmailList);
}