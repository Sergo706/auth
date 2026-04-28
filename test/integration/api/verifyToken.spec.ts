import { deleteApiToken } from "~/test/test-utils/deleteApiToken.js";
import { createApiKey, generateChecksum, verifyApiKey, revokeApiKey } from '~/src/apiTokens.js'
import { beforeAll, describe, expect, it, inject } from "vitest";
import { getToken } from "~/test/test-utils/getApiTokenRow.js";
import { toDigestHex } from "~~/utils/hashChecker.js";
import { randomBytes } from "crypto";

let user: number;
beforeAll(() => {
    user = inject('testUserId');
})

describe('verification', () => {

    it('verify a valid api token', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)
        if (token.ok) {
            expect(token.data.rawApiKey).toBeTruthy()
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false);

            expect(verify.ok).toBe(true);

            if (verify.ok) {
                const rawToken = await getToken(token.data.rawApiKey!)
                expect(rawToken.public_identifier).toBe(token.data.rawPublicId)

                expect(verify.data.name).toBe('test')
                expect(verify.data.providedPrivilege).toBe('demo')
                expect(verify.data.usageCount).toBe(1)
                expect(verify.data.expiresAt).toBeFalsy()
                expect(verify.data.userId).toBe(user)
                expect(verify.data.tokenId).toBe(rawToken.id)


                const lastUsed = new Date(verify.data.lastUsed).getTime()
                const now = Date.now()
                expect(Math.abs(lastUsed - now)).toBeLessThanOrEqual(15)
                expect(verify.data.createdAt).toStrictEqual(rawToken.created_at)
                await deleteApiToken(token.data.rawApiKey!)
            }

        }
    })

    it('reject invalid structure - prefix, providedRandomPart, providedChecksum', async () => {
         const token = await createApiKey(user, 'demo', 'test')
         expect(token.ok).toBe(true)

        if (token.ok) {
            expect(token.data.rawApiKey).toBeTruthy()
            const [prefix, providedRandomPart, providedChecksum] = token.data.rawApiKey!.split('_')
            const invalid = `${prefix}444_${providedRandomPart}_123${providedChecksum}111`;

            const verify = await verifyApiKey(invalid, false, 'demo', false, false);
            expect(verify.ok).toBe(false);
            if (!verify.ok) {
                expect(verify.reason).toBe('Invalid key')
                expect(verify.date).toBeTruthy()
            }

            const missingStructure = `${providedRandomPart}_${providedChecksum}`;
            const malformed = `secure_${providedRandomPart}_${providedChecksum}`;

            const verifyMissing = await verifyApiKey(missingStructure, false, 'demo', false, false)
            expect(verifyMissing.ok).toBe(false);

            if (!verifyMissing.ok) {
                expect(verifyMissing.reason).toBe('Invalid key')
                expect(verifyMissing.date).toBeTruthy()
            }

            const verifyMalformed = await verifyApiKey(malformed, false, 'demo', false, false)
            expect(verifyMalformed.ok).toBe(false);

            if (!verifyMalformed.ok) {
                expect(verifyMalformed.reason).toBe('Invalid key')
                expect(verifyMalformed.date).toBeTruthy()
            }

            const invalidChecksum = generateChecksum('random_checksome');
            const malformedChecksum = `${prefix}_${providedRandomPart}_${invalidChecksum}`;
            const verifyMalformedChecksum = await verifyApiKey(malformedChecksum, false, 'demo', false, false)

            expect(verifyMalformedChecksum.ok).toBe(false)
            if (!verifyMalformedChecksum.ok) {
                expect(verifyMalformedChecksum.reason).toBe('Invalid key')
                expect(verifyMalformedChecksum.date).toBeTruthy()
            }

            const malformedRandomPart = `${prefix}_${randomBytes(64).toString('hex')}_${providedChecksum}`;
            const verifyMalformedRandom  = await verifyApiKey(malformedRandomPart, false, 'demo', false, false)
            expect(verifyMalformedRandom.ok).toBe(false)

            if (!verifyMalformedRandom.ok) {
                expect(verifyMalformedRandom.reason).toBe('Invalid key')
                expect(verifyMalformedRandom.date).toBeTruthy()
            }

            await deleteApiToken(token.data.rawApiKey!)
        }
    })

    it('reject revoked tokens', async () => {
         const token = await createApiKey(user, 'demo', 'test')
         expect(token.ok).toBe(true)

        if (token.ok) { 
            const revoke = await revokeApiKey(token.data.rawApiKey!, 'demo')
            expect(revoke.ok).toBe(true)
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)

            expect(verify.ok).toBe(false)
            if (!verify.ok) {
                expect(verify.reason).toBe('Invalid key')
                expect(verify.date).toBeTruthy()
            }
            await deleteApiToken(token.data.rawApiKey!)
        }
    })

    it('rejects non existing tokens and insufficient privileges', async () => {
         const token = await createApiKey(user, 'demo', 'test')
         expect(token.ok).toBe(true)

        if (token.ok) { 
            await deleteApiToken(token.data.rawApiKey!)
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(false)
            if (!verify.ok) {
                expect(verify.reason).toBe('Invalid key')
                expect(verify.date).toBeTruthy()
            }
        }

        // privileges

        const anotherToken = await createApiKey(user, 'demo', 'test')
        expect(anotherToken.ok).toBe(true)

        if (anotherToken.ok) {
            const badPrivgVerify = await verifyApiKey(anotherToken.data.rawApiKey!, false, 'full', false, false)
            expect(badPrivgVerify.ok).toBe(false)

            if (!badPrivgVerify.ok) {
                expect(badPrivgVerify.reason).toBe('Invalid key')
                expect(badPrivgVerify.date).toBeTruthy()
            }
            await deleteApiToken(anotherToken.data.rawApiKey!)
        }
    })

    it('rejects/allows only tokens from a configured hosts', async () => {
        const token = await createApiKey(user, 'demo', 'test', undefined, undefined, ["1.2.3.4", "1.1.1.1"])
        expect(token.ok).toBe(true)

        if (token.ok) {
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false, "1.2.3.4")
            expect(verify.ok).toBe(true)
            const secVerify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false, "1.1.1.1")
            expect(secVerify.ok).toBe(true)

            const noIp = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(noIp.ok).toBe(false)

            if (!noIp.ok) {
                expect(noIp.reason).toBe('Invalid Host')
                expect(noIp.date).toBeTruthy()
            }

            const invalidIp = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false, "1.2.3.5")
            expect(invalidIp.ok).toBe(false)

            if (!invalidIp.ok) {
                expect(invalidIp.reason).toBe('Invalid Host')
                expect(invalidIp.date).toBeTruthy()
            }
            await deleteApiToken(token.data.rawApiKey!)
        }

    })


    it('rejects expired tokens', async () => {
        const token = await createApiKey(user, 'demo', 'test', undefined, 1000 * 5)
        expect(token.ok).toBe(true)

        if (token.ok) {
            await new Promise(resolve => setTimeout(resolve, 5000))
            const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verify.ok).toBe(false)

            if (!verify.ok) {
                expect(verify.reason).toBe("Token expired")
                expect(verify.date).toBeTruthy()
            }

            // should be invalided
            const rawTokenData = await getToken(token.data.rawApiKey!)
            expect(rawTokenData.valid).toBeOneOf([false, 0])

            // second attempt should not be founded in the db
            const verifyAgain = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verifyAgain.ok).toBe(false)

            if (!verifyAgain.ok) {
                expect(verifyAgain.reason).toBe('Invalid key')
                expect(verifyAgain.date).toBeTruthy()
            }

            await deleteApiToken(token.data.rawApiKey!)
        }
    })

    describe('verification skipping logic', () => {
        it('skip signature and checksum when isInternalHash true', async () => {
                const token = await createApiKey(user, 'demo', 'test')
                expect(token.ok).toBe(true)

                if (token.ok) {
                    const { input: hash } = await toDigestHex(token.data.rawApiKey!)

                    const verify = await verifyApiKey(hash, false, 'demo', false, false)
                    expect(verify.ok).toBe(false)

                    if(!verify.ok) {
                         expect(verify.reason).toBe('Invalid key')
                         expect(verify.date).toBeTruthy()
                    }

                    const skipHash = await verifyApiKey(hash, false, 'demo', false, true)
                    expect(skipHash.ok).toBe(true)
                    await deleteApiToken(token.data.rawApiKey!)
                }
        })

        it('skips ip verification when byPassIpCheck is true', async () => {
                const token = await createApiKey(user, 'demo', 'test', undefined, undefined, ["1.1.1.1"])
                expect(token.ok).toBe(true)

                if (token.ok) {
                    const verify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
                    expect(verify.ok).toBe(false)
                    if(!verify.ok) {
                        expect(verify.reason).toBe('Invalid Host')
                        expect(verify.date).toBeTruthy()
                    }

                    const anotherVerify = await verifyApiKey(token.data.rawApiKey!, false, 'demo', true, false)
                    expect(anotherVerify.ok).toBe(true)
                    await deleteApiToken(token.data.rawApiKey!)
                }
        })

        it("skips usage_count and last_used updates when skipCountUpdates is true", async () => {
                const token = await createApiKey(user, 'demo', 'test')
                expect(token.ok).toBe(true)

                if(token.ok) {
                    const verify = await verifyApiKey(token.data.rawApiKey!, true, 'demo', false, false)
                    expect(verify.ok).toBe(true)

                    if(verify.ok) {
                        const rawData = await getToken(token.data.rawApiKey!)
                        expect(verify.data.usageCount).toBe(rawData.usage_count)
                        expect(verify.data.lastUsed).toStrictEqual(rawData.last_used)
                        expect(verify.data.tokenId).toBe(rawData.id)
                    }

                    await deleteApiToken(token.data.rawApiKey!)
                }
        })

    })
})