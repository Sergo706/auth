import { deleteApiToken } from "~/test/test-utils/deleteApiToken.js";
import { createApiKey, generateChecksum, verifyApiKey, revokeApiKey, rotateApiKey } from '~/src/apiTokens.js'
import { beforeAll, describe, expect, it, inject } from "vitest";
import { getToken } from "~/test/test-utils/getApiTokenRow.js";
import { toDigestHex } from "~~/utils/hashChecker.js";

let user: number;
beforeAll(() => {
    user = inject('testUserId');
})


describe('revoke', () => {
    it('revokes a valid token successfully', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) {
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(true)
            
            const revoke = await revokeApiKey(token.data.rawApiKey!, 'demo')
            expect(revoke.ok).toBe(true)

            if (revoke.ok) {
                expect(revoke.data).toHaveProperty('msg', 'Token invalided successfully')
                expect(revoke.data).toHaveProperty('userId', user)
                const tokenId = (await getToken(token.data.rawApiKey!)).id;
                expect(revoke.data).toHaveProperty('invalidedTokenId', tokenId)
            }

            const anotherVerify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(anotherVerify.ok).toBe(false)

            if (!anotherVerify.ok) {
                expect(anotherVerify.reason).toBe('Invalid key')
                expect(anotherVerify.date).toBeTruthy()
            }
            await deleteApiToken(token.data.rawApiKey!)
        }
    })

    it('should return successful response if token is invalid', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) { 
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(true)
            
            const revoke = await revokeApiKey(token.data.rawApiKey!, 'full')
            expect(revoke.ok).toBe(true)

            if (revoke.ok) {
                expect(revoke.data).not.toHaveProperty('msg', 'Token invalided successfully')
                expect(revoke.data).not.toHaveProperty('userId', user)
                const tokenId = (await getToken(token.data.rawApiKey!)).id;
                expect(revoke.data).not.toHaveProperty('invalidedTokenId', tokenId)
                expect(revoke.data).toBe('Token invalided successfully')
            }
            await deleteApiToken(token.data.rawApiKey!)
        }
    })
})


describe('rotation', () => {
    it('rotates a token successfully', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) { 
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(true)

            const rotate = await rotateApiKey(token.data.rawApiKey!, 'demo', 'test', false)
            expect(rotate.ok).toBe(true)
            if(rotate.ok) {
                expect(rotate.data.msg).toBe('Successfully rotated an api key')
                expect(rotate.data.newExpiry).toBeFalsy()
                expect(rotate.data.newRawToken).not.toBe(token.data.rawApiKey)
                expect(rotate.data.newRawToken).toBeDefined()

                const rawPrevToken = await getToken(token.data.rawApiKey!)
                const prevHashed = await toDigestHex(token.data.rawApiKey!)
                expect(rawPrevToken.api_token).toBe(prevHashed.input)
                expect(rawPrevToken.valid).toBeOneOf([false, 0])

                const newRawToken = await getToken(rotate.data.newRawToken!)
                expect(newRawToken.user_id).toBe(user)

                const newHashed = await toDigestHex(rotate.data.newRawToken!)
                expect(newRawToken.api_token).toBe(newHashed.input)
                await deleteApiToken(rotate.data.newRawToken!)

            }

            await deleteApiToken(token.data.rawApiKey!)
        }
    })
    it('deletes the prev token when deleteOnRotation is true', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) { 
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(true)
            const rotate = await rotateApiKey(token.data.rawApiKey!, 'demo', 'test', true)
            expect(rotate.ok).toBe(true)

            if(rotate.ok) {
                expect(rotate.data.msg).toBe('Successfully rotated an api key')
                expect(rotate.data.newExpiry).toBeFalsy()
                expect(rotate.data.newRawToken).not.toBe(token.data.rawApiKey)
                expect(rotate.data.newRawToken).toBeDefined()

                const prev = await getToken(token.data.rawApiKey!)
                expect(prev).toBeOneOf([null, undefined, []])

                const newRawToken = await getToken(rotate.data.newRawToken!)
                expect(newRawToken.user_id).toBe(user)

                const newHashed = await toDigestHex(rotate.data.newRawToken!)
                expect(newRawToken.api_token).toBe(newHashed.input)
                await deleteApiToken(rotate.data.newRawToken!)
            }
        }
    })

    it('does not rotate invalid tokens', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) { 
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(true)

            const [ prefix, random, checksum ] = token.data.rawApiKey!.split("_")
            const malformed = `${prefix}1_${random}_${checksum}`;

            const rotate = await rotateApiKey(malformed, 'demo', 'test', true)
            expect(rotate.ok).toBe(false)
            if(!rotate.ok) {
                expect(rotate.reason).toBeOneOf(['Token cannot be rotated this time', 'Cannot rotate revoked token'])
            }

            const rotate2 = await rotateApiKey(token.data.rawApiKey!, 'full', 'test', false)
            expect(rotate2.ok).toBe(false)
            if(!rotate2.ok) {
                expect(rotate2.reason).toBeOneOf(['Token cannot be rotated this time', 'Cannot rotate revoked token'])
            }
             await deleteApiToken(token.data.rawApiKey!)
        }

        // exp
        const expiredToken = await createApiKey(user, 'demo', 'test', undefined, 1000 * 5)
        expect(expiredToken.ok).toBe(true)

        if (expiredToken.ok) {
            const verify = await verifyApiKey(expiredToken.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(true)

            await new Promise(resolve => setTimeout(resolve, 5000))

            const expRotate = await rotateApiKey(expiredToken.data.rawApiKey!, 'demo', 'test', true);
            expect(expRotate.ok).toBe(false)

            if(!expRotate.ok) {
                expect(expRotate.reason).toBeOneOf(['Token cannot be rotated this time', 'Cannot rotate revoked token'])
            }
             await deleteApiToken(expiredToken.data.rawApiKey!)
        }
    })

    it('updates new attributes, while reserving prev privileges', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) { 
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(true)

            const rotate = await rotateApiKey(token.data.rawApiKey!, 'custom', '1234', true)
            expect(rotate.ok).toBe(false)
            if(!rotate.ok) {
                expect(rotate.reason).toBeOneOf(['Token cannot be rotated this time', 'Cannot rotate revoked token'])
            }

            const rotate2 = await rotateApiKey(token.data.rawApiKey!, 'demo', '1234', true, ["1.2.3.4"], 1000 * 60, 'new')
            expect(rotate2.ok).toBe(true)

            if(rotate2.ok) {
                expect(rotate2.data.msg).toBe('Successfully rotated an api key')
                expect(rotate2.data.newExpiry).toBeTruthy()
                expect(rotate2.data.newRawToken).not.toBe(token.data.rawApiKey)
                expect(rotate2.data.newRawToken).toBeDefined()

                const newRawToken = await getToken(rotate2.data.newRawToken!)

                const hashed = await toDigestHex(rotate2.data.newRawToken!)
                expect(newRawToken.api_token).toBe(hashed.input)
                expect(newRawToken.name).toBe("1234")
                expect(newRawToken.privilege_type).toBe("demo")
                expect(newRawToken.prefix).toBe("new")

                const net = JSON.parse(newRawToken.restricted_to_ip_address) as string[]
                expect(net).toStrictEqual(["1.2.3.4"])

                await deleteApiToken(rotate2.data.newRawToken!)
            }

        }
    })
})