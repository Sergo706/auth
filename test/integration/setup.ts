import { beforeAll } from 'vitest'
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { config } from '../configs/config.js';


beforeAll(async () => {
      await configuration(config)
})