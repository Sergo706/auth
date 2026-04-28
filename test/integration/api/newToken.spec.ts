import { deleteApiToken } from "~/test/test-utils/deleteApiToken.js";
import {createApiKey, isSame, generateChecksum } from '~/src/apiTokens.js'
import { beforeAll, describe, expect, it, inject } from "vitest";
import { getToken } from "~/test/test-utils/getApiTokenRow.js";
import { toDigestHex } from "~~/utils/hashChecker.js";
import { range } from "@riavzon/utils";
import { getConfiguration } from "~~/config/configuration.js";

let user: number;

beforeAll(async () => {
    user = inject('testUserId')
})

describe('new tokens', () => {
    it('generate a valid token' , async () => {
        // @ts-ignore
        const { ok, data } = await createApiKey(user, 'demo', 'test', 'randomprefix', 1000 * 60 * 60, ["1.1.1.1"])

        expect(ok).toBe(true)
        expect(data!.expiresAt).toBeDefined()

        const r = data!.expiresAt!.getTime()
        const e = Date.now() + 1000 * 60 * 60
        expect(Math.abs(r - e)).toBeLessThanOrEqual(5)

        expect(data!.rawPublicId).toBeDefined()

        const [prefix, providedRandomPart, providedChecksum] = data!.rawApiKey.split('_');
        expect(prefix).toBe('randomprefix')
        
        const calculatedChecksum = generateChecksum(providedRandomPart);

        const same = isSame(providedChecksum, calculatedChecksum)
        expect(same).toBe(true);

        const datas = await getToken(data!.rawApiKey)
        expect(datas.privilege_type).toBe('demo')
        const net = JSON.parse(datas.restricted_to_ip_address) as string[];

        expect(net[0]).toBe("1.1.1.1")
        const dbEx = (datas.expires_at as Date).getTime()

        expect(Math.abs(dbEx - r)).toBeLessThanOrEqual(1000)
        expect(datas.name).toBe("test")
        expect(datas.user_id).toBe(user)
        expect(datas.prefix).toBe('randomprefix')
        expect(datas.valid).toBeTruthy()
        expect(datas.usage_count).toBe(0)
        expect(datas.public_identifier).toBe(data!.rawPublicId)
        const { input: hash } = await toDigestHex(data!.rawApiKey)
        expect(datas.api_token).toBe(hash)

        await deleteApiToken(data!.rawApiKey)
    })

    it('generates tokens without net or expiry', async () => {
        // @ts-ignore
        const { ok, data } = await createApiKey(user, 'demo', 'test', 'randomprefix')

        expect(ok).toBe(true)
        expect(data!.expiresAt).toBeFalsy()
        expect(data!.rawApiKey).toBeTruthy()
        expect(data!.rawPublicId).toBeTruthy()

        const datas = await getToken(data!.rawApiKey)

        expect(datas.public_identifier).toBe(data!.rawPublicId)
        expect(datas.expires_at).toBeFalsy()
        expect(datas.valid).toBeTruthy()

        const net = JSON.parse(datas.restricted_to_ip_address) as string[];
        expect(net).toBeNull()
        await deleteApiToken(data!.rawApiKey)

    })

    it('automatically prefix "api" when prefix omitted', async () => {
        // @ts-ignore
        
        const { ok, data } = await createApiKey(user, 'demo', 'test')
        expect(ok).toBe(true)
        expect(data!.expiresAt).toBeFalsy()
        expect(data!.rawApiKey).toBeTruthy()
        expect(data!.rawPublicId).toBeTruthy()

        const [prefix, providedRandomPart, providedChecksum] = data!.rawApiKey.split('_');
        expect(prefix).toBe('api')

        const datas = await getToken(data!.rawApiKey)
        expect(datas.prefix).toBe('api')
        await deleteApiToken(data!.rawApiKey)

    })

    it("rejects when max allowed limits per user exceeded", async () => {
        const result = [];
        const config = getConfiguration().apiTokens.limitTokensPerUser

        
        const createdTokens: string[] = []
        for (const b of range(0, config + 1)) {
             const results = await createApiKey(user, 'demo', 'test')
             result.push(results)

             if (results.ok && results.data?.rawApiKey) 
                    createdTokens.push(results.data.rawApiKey);

        }

        for (const t of createdTokens) await deleteApiToken(t)
        const countValid = result.filter(v => v.ok === true)
        const countinValid = result.filter(v => v.ok === false)

        expect(countValid.length).toBe(config);
        expect(countinValid.length).toBe(1);
    })
})