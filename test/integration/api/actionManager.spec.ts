import { deleteApiToken } from "~/test/test-utils/deleteApiToken.js";
import { createApiKey, verifyApiKey, privateActionManager, generateChecksum } from '~/src/apiTokens.js'
import { beforeAll, describe, expect, it, inject } from "vitest";
import { getToken } from "~/test/test-utils/getApiTokenRow.js";
import { randomBytes } from "crypto";


let user: number;
let anotherUser: number;

beforeAll(() => {
    user = inject('testUserId');
    anotherUser = inject('anotherUserId')
})


describe('privateActionManager', () => {

 it('successfully perform an action', async () => {
      const token = await createApiKey(user, 'demo', 'test');
      expect(token.ok).toBe(true) 
      
      if (token.ok) {
        const data = await getToken(token.data.rawApiKey!)

        const revoke = await privateActionManager(user, data.id, token.data.rawPublicId, 'test', {
            action: 'revoke'
        });

        expect(revoke.ok).toBe(true)
        if(revoke.ok) {
            expect(typeof revoke.data === 'object' && 'invalidedTokenId' in revoke.data).toBe(true)
            // @ts-ignore
            expect(revoke.data.msg).toBe('Token invalided successfully')
            // @ts-ignore
            expect(revoke.data.invalidedTokenId).toBe(data.id)
            // @ts-ignore
            expect(revoke.data.userId).toBe(data.user_id)

            const verifyTest = await verifyApiKey(token.data.rawApiKey!, false, 'demo', false, false)
            expect(verifyTest.ok).toBe(false)
        }
        await deleteApiToken(token.data.rawApiKey!)
      }
 })

  it('refuses to perform actions when attributes are invalid', async () => {
      const token = await createApiKey(user, 'demo', 'test');
      const anotherUserToken = await createApiKey(anotherUser, 'demo', 'test');

      expect(token.ok).toBe(true) 
      expect(anotherUserToken.ok).toBe(true) 

      
      if (token.ok && anotherUserToken.ok) { 
           const data = await getToken(token.data.rawApiKey!)
           // invalid name
           const revoke = await privateActionManager(user, data.id, token.data.rawPublicId, 'demo', {
                action: 'revoke'
            });
            expect(revoke.ok).toBe(false)
            // @ts-ignore
            expect(revoke.reason).toBe('Bad Request')               

            // another user id
            const revoke2 = await privateActionManager(anotherUser, data.id, token.data.rawPublicId, 'test', {
                action: 'revoke'
            });

            expect(revoke2.ok).toBe(false)
            // @ts-ignore
            expect(revoke2.reason).toBe('Bad Request')            


           //  token id of another user
            const data2 = await getToken(anotherUserToken.data.rawApiKey!)
            const revoke3 = await privateActionManager(user, data2.id, token.data.rawPublicId, 'test', {
                action: 'revoke'
            });

            expect(revoke3.ok).toBe(false)
            // @ts-ignore
            expect(revoke3.reason).toBe('Bad Request')    

           //  token id of different token
            const token2 = await createApiKey(user, 'demo', 'test');
            expect(token2.ok).toBe(true)
            // @ts-ignore
            const data3 = await getToken(token2.data.rawApiKey!)
            const revoke4 = await privateActionManager(user, data3.id, token.data.rawPublicId, 'test', {
                action: 'revoke'
            });
            expect(revoke4.ok).toBe(false)
            // @ts-ignore
            expect(revoke4.reason).toBe('Bad Request')    
            await deleteApiToken(token.data.rawApiKey!)
            // @ts-ignore
            await deleteApiToken(token2.data.rawApiKey!)
            await deleteApiToken(anotherUserToken.data.rawApiKey!)
      }
  })

  it('refuse to perform action on invalid publicIdentifier', async () => {
      const token = await createApiKey(user, 'demo', 'test');
      expect(token.ok).toBe(true) 
      
      if (token.ok) {
           const data = await getToken(token.data.rawApiKey!)

           const revoke = await privateActionManager(user, data.id, "1234", 'test', {
                action: 'revoke'
           });
           expect(revoke.ok).toBe(false)
           if (!revoke.ok) {
                expect(revoke.reason).toBe('Invalid identity')
           }

           const randomPublic = randomBytes(64).toString('hex');
           const invalidPubId = `${randomPublic}_${generateChecksum(randomPublic)}`; 

           const malformedRevoke = await privateActionManager(user, data.id, invalidPubId, 'test', {
                action: 'revoke'
           });

           expect(malformedRevoke.ok).toBe(false)
            // @ts-ignore
           expect(malformedRevoke.reason).toBe('Bad Request')

           const [a,b] = token.data.rawPublicId.split("_")
           const malformedPubId = `${a}_1${b}`;

           const anotherMalformedRevoke = await privateActionManager(user, data.id, malformedPubId, 'test', {
                action: 'revoke'
           });

           expect(anotherMalformedRevoke.ok).toBe(false)
            // @ts-ignore
           expect(anotherMalformedRevoke.reason).toBe('Invalid identity')
          await deleteApiToken(token.data.rawApiKey!)
      }
  })

  it('reserves the same attributes on rotation', async () => {
       const token = await createApiKey(user, 'restricted', 'test', 'testing', 1000 * 60 * 60, ["1.1.1.1", "2.2.2.2"])
       expect(token.ok).toBe(true)

       if(token.ok) {
            const data = await getToken(token.data.rawApiKey!)

           const rotate = await privateActionManager(user, data.id, token.data.rawPublicId, 'test', {
                action: 'rotate'
           });

           expect(rotate.ok).toBe(true)

           if(rotate.ok) {
                 // @ts-ignore
                expect(rotate.data.msg).toBe('Successfully rotated an api key')
                 // @ts-ignore
                const newExpiry = rotate.data.newExpiry ? new Date(rotate.data.newExpiry) : null;
                expect(newExpiry).toBeTruthy();

                if (newExpiry) {
                    const diffMs = Math.abs(newExpiry.getTime() - new Date(data.expires_at!).getTime());
                    expect(diffMs).toBeLessThan(2000); // allow 2s drift
                }
                
                 // @ts-ignore
                const newTokenData = await getToken(rotate.data.newRawToken)

                expect(newTokenData.user_id).toBe(data.user_id)
                expect(newTokenData.name).toBe('test')
                expect(newTokenData.privilege_type).toBe('restricted')
                const newNet = JSON.parse(newTokenData.restricted_to_ip_address) as string[];
                expect(newNet).toEqual(["1.1.1.1", "2.2.2.2"]);
                expect(newNet.length).toBe(2);
                expect(newTokenData.prefix).toBe('testing')

                // @ts-ignore
                await deleteApiToken(rotate.data.newRawToken)
           }
            await deleteApiToken(token.data.rawApiKey!)
       }
  })

})

