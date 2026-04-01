import { config } from '~/test/configs/config.js';
import { ConfigurationInput } from '~~/types/configSchema.js';

export  function newConfig(overides: Partial<ConfigurationInput>) {

    const newConf: ConfigurationInput = {
        ...config,
        ...overides
    }

    return newConf;
}