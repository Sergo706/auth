import { vi, it, describe,afterAll, beforeAll,expect, beforeEach } from "vitest";
import { sendTempPasswordResetLink } from "~~/utils/changePassword.js";
import { createTestUser, deleteUser } from "../test-utils/testUser.js";
import { resetPasswordEmail } from '../../src/jwtAuth/utils/systemEmailMap.js';
import { verifyTempJwtLink } from "~/src/tempLinks.js";

vi.mock('../../src/jwtAuth/utils/systemEmailMap.js', () => ({
  resetPasswordEmail: vi.fn().mockResolvedValue(undefined),
}));

describe('sendTempPasswordResetLink', () => {
    const testEmail = "passwordreset123@test.com";
    beforeEach(() => {
    vi.clearAllMocks(); 
  });
    afterAll(async () => {
        await deleteUser(undefined, testEmail)
    })

    beforeAll(async () => {
        await createTestUser(testEmail)
    })

  it('should generate a valid link and call the email utility with the correct URL', async () => {
    const result = await sendTempPasswordResetLink(testEmail);
    expect(result.valid).toBe(true);
    expect(resetPasswordEmail).toHaveBeenCalled();

    const callArgs = vi.mocked(resetPasswordEmail).mock.calls[0];
    const sentUrl = new URL(callArgs[2]);
    
    expect(sentUrl.searchParams.get('visitor')).toBeTruthy();
    expect(sentUrl.searchParams.get('reason')).toBe('PASSWORD_RESET');
    expect(sentUrl.searchParams.get('random')).toBeTruthy();
    const token = verifyTempJwtLink(sentUrl.searchParams.get('token') as string);
    
    expect(token.valid).toBe(true)
    expect(token.payload?.visitor).toBe(sentUrl.searchParams.get('visitor'))
  });

  it('should return error if user does not exist', async () => {
    const result = await sendTempPasswordResetLink('nonexistent@example.com');
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('No email found');
    expect(resetPasswordEmail).not.toHaveBeenCalled();
  });

})