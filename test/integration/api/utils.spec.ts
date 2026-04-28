import { deleteApiToken } from "~/test/test-utils/deleteApiToken.js";
import {createApiKey, totalUserTokensCount, revokeApiKey, isSame, generateChecksum, validateChecksumPublicIdent, getAllValidTokensList } from '~/src/apiTokens.js'
import { beforeAll, describe, expect, it, inject } from "vitest";
import { fakeLogger } from "~~/utils/fakeLogger.js";

const hex = (value: string) => {
    const buffer = Buffer.from(value, 'utf8');
    return buffer.toString('hex');
}

let user: number;

beforeAll(async () => {
    user = inject('testUserId')
})

describe('totalUserTokensCount', () => {
    

    it('should return 0 on all counts when no tokens exists', async () => {
        const counts = await totalUserTokensCount(user);

        expect(counts).toHaveProperty('userId')
        expect(counts.total).toBe(0)
        expect(counts.totalInvalidTokens).toBe(0)
        expect(counts.totalValidTokens).toBe(0)
    })

    it('should count total valid right', async () => {
        const token = await createApiKey(user, 'demo', 'test', 'tests')
        expect(token.ok).toBe(true)

        const counts = await totalUserTokensCount(user);
        expect(counts).toHaveProperty('userId')
        expect(counts.total).toBe(1)
        expect(counts.totalInvalidTokens).toBe(0)
        expect(counts.totalValidTokens).toBe(1)
        // @ts-ignore
        await deleteApiToken(token.data!.rawApiKey)
    })

    it('should count invalid tokens', async () => {
        const token = await createApiKey(user, 'demo', 'test', 'tests')
        expect(token.ok).toBe(true)
        // @ts-ignore
        const revoke = await revokeApiKey(token.data!.rawApiKey, 'demo')
        expect(revoke.ok).toBe(true)

        const counts = await totalUserTokensCount(user);

        expect(counts).toHaveProperty('userId')
        expect(counts.total).toBe(1)
        expect(counts.totalInvalidTokens).toBe(1)
        expect(counts.totalValidTokens).toBe(0)
        // @ts-ignore

       await deleteApiToken(token.data!.rawApiKey)
    })
})

describe('isSame, checksum, validateChecksumPublicIdent', () => {
    it('compares hexes successfully', async () => {
        const a = hex("1234")
        const b = hex("1234")

        const same = isSame(a, b)
        expect(same).toBe(true)
        const c = hex("12345")
        const d = hex("1234")
        const same2 = isSame(c, d)
        expect(same2).toBe(false)
    })

    it('generate a checksum', () => {
        const a = generateChecksum("1234")
        const b = generateChecksum("1234")
        expect(a.length).toBe(8)
        expect(b.length).toBe(8)
        expect(isSame(a,b)).toBe(true)
    })

    it('validates a valid publicId checksum successfully', async () => {
        const token = await createApiKey(user, 'demo', 'test', 'tests')
        // @ts-ignore
        const res = validateChecksumPublicIdent(token.data?.rawPublicId!, fakeLogger)
        expect(res).toBe(true)

        const dataRes = await getAllValidTokensList(user)
        expect(dataRes.ok).toBe(true)

        if (dataRes.ok) {
            // @ts-ignore
            const datas = dataRes.data.tokenList?.filter(a => a.public_identifier === token.data?.rawPublicId)
            expect(datas?.length).toBeGreaterThan(0)
        // @ts-ignore
            expect(datas![0].public_identifier).toBe(token.data?.rawPublicId)
            const newRes = validateChecksumPublicIdent(datas![0].public_identifier, fakeLogger)
            expect(newRes).toBe(true)
        }
        // @ts-ignore
        await deleteApiToken(token.data!.rawApiKey)
    })

})