import crypto from 'crypto'
import { makeConsecutiveCache } from './limiters/utils/consecutiveCache.js';

export interface PwnedResponse {
    pwned: boolean,
    count: number,
    date: string,
}
const resCache = makeConsecutiveCache<PwnedResponse>(1000, 1000 * 60 * 15)
const prefixCache = makeConsecutiveCache<Map<string, number>>(1000, 1000 * 60 * 60 * 48)

export async function isPwned(password: string): Promise<PwnedResponse> {

   const sha1 = crypto.createHash('sha1').update(password, 'utf-8').digest('hex').toUpperCase()
   const prefix: string = sha1.slice(0, 5) 
   const suffix: string = sha1.slice(5) 
   const date = new Date().toISOString()
   
   const exists = resCache.get(suffix)
   if (exists) return exists;


   let suffixMap: Map<string, number> | undefined = prefixCache.get(prefix)

   if (!suffixMap) {
       const res: Response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: {
            'Add-Padding': 'true'
        }
       })

       if (!res.ok) {
           const result: PwnedResponse = { pwned: false, count: 0, date }
           resCache.set(suffix, result)
           return result
        }

        suffixMap = new Map<string, number>()
        const body: string = await res.text()

        for (const line of body.split('\r\n')) {
            const [hashSuffix, countStr] = line.split(':')
            const count: number = parseInt(countStr, 10)
            if (count > 0) suffixMap.set(hashSuffix, count)
        }
        prefixCache.set(prefix, suffixMap)
   } 

    const count: number = suffixMap.get(suffix) ?? 0
    const result: PwnedResponse = {
        pwned: count > 0,
        count,
        date
    }
    resCache.set(suffix, result)
    return result
  }
  