// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ["test/**/*.{test,spec}.ts"],
    setupFiles: ['dotenv/config', './test/setup/test.setup.ts'], 
    globals: true,
    testTimeout: 30_000,
    hookTimeout: 30_000,
    fileParallelism: false,
    // maxWorkers: 2,
    // minWorkers: 1,
    pool: 'threads',
    sequence: {
      hooks: 'list',
      setupFiles: 'list'
    },
     coverage: {
      enabled: true,
      reporter: ['html'],
    },
      poolOptions: {
      threads: {
        singleThread: true
      }
    },
    exclude: ["test/setup/**", "node_modules/**", "dist/**"],
  },
});
