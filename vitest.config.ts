import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: "auth",
    coverage: {
      enabled: true,
      reporter: ['html'],
      cleanOnRerun: true,
      all: true,
      include: ['src/**/*'],
    },
    environment: 'node',
    include: ["test/**/*.{test,spec}.ts"],
    setupFiles: ['./test/setup/test.setup.ts'], 
    env: {
      DOTENV_CONFIG_PATH: '.env.test',
    },
    testTimeout: 30_000,
    hookTimeout: 30_000,
    fileParallelism: false,
    pool: 'threads',
    sequence: {
      hooks: 'list',
      setupFiles: 'list'
    },
      poolOptions: {
      threads: {
        singleThread: true
      }
    },
    exclude: ["test/setup/**", "node_modules/**", "dist/**"],
  },
});

