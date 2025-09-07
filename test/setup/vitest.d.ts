import 'vitest'
import type mysql2 from 'mysql2/promise'
import type mysql from 'mysql2'

declare module 'vitest' {
  export interface TestContext {
    testUserId: number
    anotherUserId: number
    mainPool: mysql2.Pool
    rateLimiterPool: mysql.Pool
  }
}
