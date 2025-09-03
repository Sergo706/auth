import {expect, test, it, describe} from 'vitest'
import { generateAccessToken } from '../src/accessTokens.js';
import crypto from 'node:crypto'
import {AccessTokenPayload} from '../src/accessTokens.js';
import { Buffer } from 'node:buffer';

const user: AccessTokenPayload = {
    id: 3, 
    visitor_id: 155,
    jti: crypto.randomUUID()
}

describe('generateAccessToken', () => {
    test('Should generate a new signed access token')
    const token = generateAccessToken(user);
    const signature = token.split(".");
    const decoded = Buffer.from(signature[1], 'base64url').toString('utf-8');
    const claims = JSON.parse(decoded);
    expect(
       claims.id === user.id && claims.visitor_id === user.visitor_id && claims.jti === user.jti  
    ).toBe(true)
})


//
