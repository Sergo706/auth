import 'vitest';

declare module 'vitest' {
  export interface TestContext {
    testUserId: number;
    anotherUserId: number;
  }
}
