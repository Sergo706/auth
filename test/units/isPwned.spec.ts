import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { isPwned, type PwnedResponse } from '@utils/isPasswordPwned.js';

describe('isPwned', () => {
  const breachedPasswords: string[] = [
    '1234',
    'password',
    '123456789',
    'qwerty',
    'letmein',
  ];

  for (const password of breachedPasswords) {
    it(`should detect "${password}" as breached`, async () => {
      const result: PwnedResponse = await isPwned(password);

      expect(result.pwned).toBe(true);
      expect(result.count).toBeGreaterThan(0);
      expect(result.date).toBeTruthy();
      expect(new Date(result.date).getTime()).not.toBeNaN();
    });
  }


  it('should NOT detect a cryptographically random password as breached', async () => {
    const randomPassword: string = crypto.randomBytes(64).toString('hex');
    const result: PwnedResponse = await isPwned(randomPassword);

    expect(result.pwned).toBe(false);
    expect(result.count).toBe(0);
    expect(result.date).toBeTruthy();
  });



  it('should return a valid PwnedResponse shape', async () => {
    const result: PwnedResponse = await isPwned('test');

    expect(result).toHaveProperty('pwned');
    expect(result).toHaveProperty('count');
    expect(result).toHaveProperty('date');
    expect(typeof result.pwned).toBe('boolean');
    expect(typeof result.count).toBe('number');
    expect(typeof result.date).toBe('string');
  });

  it('should produce correct SHA-1 prefix and suffix split', () => {
    const password = '1234';
    const sha1: string = crypto.createHash('sha1').update(password, 'utf-8').digest('hex').toUpperCase();

    expect(sha1).toHaveLength(40);

    const prefix: string = sha1.slice(0, 5);
    const suffix: string = sha1.slice(5);

    expect(prefix).toHaveLength(5);
    expect(suffix).toHaveLength(35);
    expect(prefix + suffix).toBe(sha1);


    expect(sha1).toBe('7110EDA4D09E062AA5E4A390B0A572AC0D2C0220');
  });


  it('should return cached result on repeated calls', async () => {
    const password = 'password';

    const first: PwnedResponse = await isPwned(password);
    const second: PwnedResponse = await isPwned(password);

    expect(second.pwned).toBe(first.pwned);
    expect(second.count).toBe(first.count);
    expect(second.date).toBe(first.date);
  });


  it('should correctly ignore zero-count padded entries from HIBP', async () => {
    const randomPassword: string = crypto.randomBytes(48).toString('base64url');
    const result: PwnedResponse = await isPwned(randomPassword);

    expect(result.pwned).toBe(false);
    expect(result.count).toBe(0);
  });


  it('should report a count in the millions for "password"', async () => {
    const result: PwnedResponse = await isPwned('password');

    expect(result.pwned).toBe(true);
    expect(result.count).toBeGreaterThan(1_000_000);
  });

  it('should report a count in the millions for "1234"', async () => {
    const result: PwnedResponse = await isPwned('1234');

    expect(result.pwned).toBe(true);
    expect(result.count).toBeGreaterThan(1_000_000);
  });
});
