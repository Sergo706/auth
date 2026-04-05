import { defineConfig, type UserConfig } from 'tsdown'

const shared: UserConfig = {
  target: 'node18',
  tsconfig: 'tsconfig.prod.json',
  treeshake: true,
  sourcemap: true,
  minify: false,
  clean: true,
  failOnWarn: true,
  copy: { from : 'src/jwtAuth/emails', to: 'dist/' },
    deps: {
    skipNodeModulesBundle: true,
  },
};

export default defineConfig([
  {
    ...shared,
    entry: ['./src/main.ts'],
    dts: true,
    format: ['esm', 'cjs'],
    publint: {
      level: 'error',
      strict: true,
    },
    attw: {
      level: 'error',
      profile: 'node16'
    },
  },
  {
    ...shared,
    entry: ['./src/service.ts'],
    dts: true,
    format: ['esm', 'cjs'],
  },
  {
    ...shared,
    entry: ['./src/jwtAuth/models/bin.ts'],
    dts: false,
    format: ['esm'],
  },
])

