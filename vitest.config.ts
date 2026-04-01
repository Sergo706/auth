import path from 'path';
import { defineConfig } from 'vitest/config';

const alias = {
    '@utils': path.resolve(__dirname, 'src/jwtAuth/utils'),
    '~~': path.resolve(__dirname, 'src/jwtAuth'),
    '~': path.resolve(__dirname, './'),
};

const sharedTest = {
    environment: 'node' as const,
    globalSetup: ['./test/globalSetup.ts'],
    hookTimeout: 60000 * 25,
    testTimeout: 15000,
};

export default defineConfig({
  test: {
    coverage: {
      enabled: true,
      reporter: ['html'],
      cleanOnRerun: true,
      include: ['src/**/*'],
      exclude: [
        'src/**/*.ejs', 
        'src/**/*.mdb', 
        'src/**/*.mdb-lock',
        'src/**/*.d.ts'
      ],
    },
    watch: false,
    projects: [
      {
       resolve: { alias },
        test: {
          name: 'units',
          include: ['test/units/**/*.{test,spec}.ts'],
          setupFiles: ['test/units/setup.ts'],
          ...sharedTest,
        },
      },
      {
        resolve: { alias },
        test: {
          name: 'integration',
          include: ["test/integration/**/*.{test,spec}.ts"],
          setupFiles: ['test/integration/setup.ts'],
          fileParallelism: false,
          pool: 'threads',
          maxConcurrency: 2,
          ...sharedTest,
        }
      }
    ]
  },
});

