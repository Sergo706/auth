import crypto from 'crypto'
import { makeConsecutiveCache } from './limiters/utils/consecutiveCache.js';

export interface PwnedResponse {
    pwned: boolean,
    count: number,
    date: string,
}

const cache = makeConsecutiveCache<PwnedResponse>(500, 1000 * 60 * 15)

export async function isPwned(password: string): Promise<PwnedResponse> {
    
   const sha1 = crypto.createHash('sha1').update(password, 'utf-8').digest('hex').toUpperCase()
   const prefix: string = sha1.slice(0, 5) 
   const suffix: string = sha1.slice(5) 
   const exists = cache.get(suffix)
   
   if (exists) return exists;

   const res: Response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: {
        'Add-Padding': 'true'
    }
   })
    if (!res.ok) {
        cache.set(suffix, {
            pwned: false,
            count: 0,
            date: new Date().toISOString()
        })

        return {
            pwned: false,
            count: 0,
            date: new Date().toISOString()
        }
    }

    const body: string = await res.text();
    const data = body.split('\r\n')

    for (const line of data) {
        const [hashSuffix, countStr] = line.split(':');
        const count: number = parseInt(countStr, 10);

        if (hashSuffix === suffix && count > 0) {
                cache.set(suffix, {
                    pwned: true,
                    count,
                    date: new Date().toISOString()
                })
                return {
                    pwned: true,
                    count,
                    date: new Date().toISOString()
                }
        }
    }

   cache.set(suffix, {
        pwned: false,
        count: 0,
        date: new Date().toISOString()
    })
    return {
        pwned: false,
        count: 0,
        date: new Date().toISOString()
    }
}   