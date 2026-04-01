import { beforeAll } from 'vitest'
import { configuration } from '~~/config/configuration.js';
import { config } from '../configs/config.js';


beforeAll(async () => {
       await configuration(config)
})