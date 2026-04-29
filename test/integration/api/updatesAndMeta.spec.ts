import { deleteApiToken } from "~/test/test-utils/deleteApiToken.js";
import { createApiKey, verifyApiKey, getUserApiKeysMetaData, updateRestriction, updatePrivileges, getAllValidTokensList } from '~/src/apiTokens.js'
import { beforeAll, describe, expect, it, inject } from "vitest";
import { getToken } from "~/test/test-utils/getApiTokenRow.js";

let user: number;
let anotherUser: number
beforeAll(() => {
    user = inject('testUserId');
    anotherUser = inject('anotherUserId')
})


describe("getUserApiKeysMetaData", () => {
    it('gets metadata and token counts for valid hashed api keys without updating usage counts', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)
        if (token.ok) {

            const data = await getUserApiKeysMetaData(token.data.rawApiKey!, 'demo')
            expect(data.ok).toBe(true)

            if(data.ok) {
                const { counts } = data.data
                expect(counts.total).toBe(1)
                expect(counts.totalInvalidTokens).toBe(0)
                expect(counts.totalValidTokens).toBe(1)

                const { tokenMeta } = data.data;

                expect(tokenMeta.name).toBe('test')
                expect(tokenMeta.providedPrivilege).toBe('demo')
                expect(tokenMeta.expiresAt).toBeFalsy()
                expect(tokenMeta.usageCount).toBe(0)

                const rawTokenData = await getToken(token.data.rawApiKey!)
                expect(tokenMeta.createdAt).toStrictEqual(rawTokenData.created_at)
                expect(tokenMeta.lastUsed).toStrictEqual(rawTokenData.last_used)
                expect(tokenMeta.tokenId).toBe(rawTokenData.id)
                expect(tokenMeta.userId).toBe(rawTokenData.user_id)
                await deleteApiToken(token.data.rawApiKey!)
            }
        }
    })
    it('fails to get metadata for expired token', async () => {
        const token = await createApiKey(user, 'demo', 'test', undefined, 1000 * 5)
        expect(token.ok).toBe(true)
        
        if (token.ok) { 
            await new Promise(reject => setTimeout(reject, 5000))
            const data = await getUserApiKeysMetaData(token.data.rawApiKey!, 'demo')
            expect(data.ok).toBe(false)
            if (!data.ok) {
                expect(data.reason).toBe("Token expired")
                expect(data.date).toBeTruthy()
                await deleteApiToken(token.data.rawApiKey!)
            }
        }
    })
    it('fails to get metadata for invalid or un existed token', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) {
            const data1 = await getUserApiKeysMetaData("1234", 'demo')
            expect(data1.ok).toBe(false)

            const [pre, random, checksum] = token.data.rawApiKey!.split("_")
            const malformedToken = `${pre}1_${random}_${checksum}`
            const data2 = await getUserApiKeysMetaData(malformedToken, 'demo')
            expect(data2.ok).toBe(false)

            const data3 = await getUserApiKeysMetaData(token.data.rawApiKey!, 'full')
            expect(data3.ok).toBe(false)
            await deleteApiToken(token.data.rawApiKey!)
        }
    })
    it('should still get metadata when ip restriction is in place', async () => {
        const token = await createApiKey(user, 'demo', 'test', undefined, undefined, ["1.1.1.1"])
        expect(token.ok).toBe(true)

        if(token.ok) {
            const data = await getUserApiKeysMetaData(token.data.rawApiKey!, 'demo')
            expect(data.ok).toBe(true)
            await deleteApiToken(token.data.rawApiKey!)
        }
    })
})

describe("update ip restrictions", () => {

    it("updates/removes ip restrictions", async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) {
            const update = await updateRestriction(user, token.data.rawApiKey!, ["1.1.1.1"])
            expect(update.ok).toBe(true)
            if (update.ok) {
                expect(update.data.msg).toBe('Restriction updated successfully')
            }

            const rawTokenData = await getToken(token.data.rawApiKey!)
            const net = JSON.parse(rawTokenData.restricted_to_ip_address) as string[];
            expect(net[0]).toBe("1.1.1.1")
            expect(net.length).toBe(1)

            // remove 
            const update2 = await updateRestriction(user, token.data.rawApiKey!, null)
            expect(update2.ok).toBe(true)

            const rawTokenData2 = await getToken(token.data.rawApiKey!);
            expect(rawTokenData2.restricted_to_ip_address).toBeOneOf([null, undefined])
            await deleteApiToken(token.data.rawApiKey!)
        }
    })

    it('fails when invalid user or un existed token is presented', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)
        const tokenOfAnotherUser = await createApiKey(anotherUser, 'demo', 'test')
        expect(tokenOfAnotherUser.ok).toBe(true)

        if (tokenOfAnotherUser.ok && token.ok) {

            // update user 1 token with another user id
            const update = await updateRestriction(anotherUser, token.data.rawApiKey!, ["1.1.1.1"])
            expect(update.ok).toBe(false)

            // update user 2 token with user 1 id
            const update2 = await updateRestriction(user, tokenOfAnotherUser.data.rawApiKey!, ["1.1.1.1"])
            expect(update2.ok).toBe(false)

            const [pre, random, checksum] = token.data.rawApiKey!.split("_")
            const malformedToken = `${pre}1_${random}_${checksum}`
            const update3 = await updateRestriction(user, malformedToken, ["1.1.1.1"])
            expect(update3.ok).toBe(false)
            await deleteApiToken(token.data.rawApiKey!)
        }
    })
})

describe('update privileges', () => {

    it('should update privilege', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)

        if (token.ok) {
            const update = await updatePrivileges(user, token.data.rawApiKey!, 'full')
            expect(update.ok).toBe(true)
            if (update.ok) {
                expect(update.data.msg).toBe('Privileges updated successfully')
            }

            const rawTokenData = await getToken(token.data.rawApiKey!)
            const newPriv = rawTokenData.privilege_type;
            expect(newPriv).toBe("full")

            const verifyTest = await verifyApiKey(token.data.rawApiKey!, false, 'full', false, false)
            expect(verifyTest.ok).toBe(true)

            const verifyTest2 = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verifyTest2.ok).toBe(false)

            await deleteApiToken(token.data.rawApiKey!)
        }

    })

    it('fails when invalid user or un existed token is presented', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)
        const tokenOfAnotherUser = await createApiKey(anotherUser, 'demo', 'test')
        expect(tokenOfAnotherUser.ok).toBe(true)

        if (tokenOfAnotherUser.ok && token.ok) {

            // update user 1 token with another user id
            const update = await updatePrivileges(anotherUser, token.data.rawApiKey!, 'full')
            expect(update.ok).toBe(false)

            // update user 2 token with user 1 id
            const update2 = await updatePrivileges(user, tokenOfAnotherUser.data.rawApiKey!, 'full')
            expect(update2.ok).toBe(false)

            const [pre, random, checksum] = token.data.rawApiKey!.split("_")
            const malformedToken = `${pre}1_${random}_${checksum}`
            const update3 = await updatePrivileges(user, malformedToken, 'full')
            expect(update3.ok).toBe(false)
            await deleteApiToken(token.data.rawApiKey!)
        }
    })
})

describe("getAllValidTokensList", () => {
    it('returns user specific metadata of all tokens', async () => {
        const token = await createApiKey(user, 'demo', 'test')
        const token2 = await createApiKey(user, 'demo', 'test')
        expect(token.ok).toBe(true)
        expect(token2.ok).toBe(true)

        if(token.ok && token2.ok) {
            const data = await getAllValidTokensList(user)
            expect(data.ok).toBe(true)

            if(data.ok) {
                expect(data.data.total).toBe(2)
                expect(data.data.totalInvalidTokens).toBe(0)
                expect(data.data.totalValidTokens).toBe(2)
                const { tokenList } = data.data;

                expect(tokenList).toBeDefined()
                expect(tokenList?.length).toBe(2)

                if (tokenList) {
                    const rawTokDataOne = await getToken(token.data.rawApiKey!);
                    const rawTokDataTwo = await getToken(token2.data.rawApiKey!);

                    const rawByPub = new Map<string, any>([
                        [rawTokDataOne.public_identifier, rawTokDataOne],
                        [rawTokDataTwo.public_identifier, rawTokDataTwo],
                    ]);

                    
                    for (const item of tokenList) {
                        expect(item.name).toBe('test')
                        expect(item.privilege_type).toBe('demo')
                        expect(item.restricted_to_ip_address).toBeFalsy()
                        expect(item.expires_at).toBeFalsy()
                        expect(item.usage_count).toBe(0)

                        const expected = rawByPub.get(item.public_identifier)
                        expect(expected).toBeDefined()

                        if (expected) {
                            expect(item.public_identifier).toBe(expected.public_identifier)
                            expect(item.created_at).toStrictEqual(expected.created_at)
                            expect(item.id).toBe(expected.id)
                        }

                    }

                }
            }
            await deleteApiToken(token.data.rawApiKey!)
            await deleteApiToken(token2.data.rawApiKey!)
        }
    })
})