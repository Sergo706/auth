import { getConfiguration } from '../config/configuration.js';
import { EmailData, EmailMetaDataOTP } from '../types/Emails.js';
import { sendSystemEmail } from "./systemEmails.js";


export async function mfaEmail(code: number, email: string, url: string, meta: EmailMetaDataOTP): Promise<void> {
  const { device, location, browser } = meta  
const emailData: EmailData = {
    link: url,
    code: code,
    device: device ?? "Unknown Device",
    location: location ?? "Unknown Location",
    date: new Date().toLocaleString(),
    cta: "Verify Here",
    browser: browser ?? "Unknown Browser"
  }
 await sendSystemEmail(email, `Security Code - ${code}`, emailData, 'OTP/index')
}

export async function resetPasswordEmail(userName: string, email: string, url: string) {
 const {magic_links} = getConfiguration()
const emailData: EmailData = {
    title: "Password Reset Request",
    action: "Please reset your password",
    subject: "Reset your password",
    username: userName,
    message: `We received a request to reset your password. If you didn't make this request, you can safely ignore this email.`,
    cta_link: magic_links.domain,
    cta: "Change Password",
    websiteName: "Auth Service",
    privacy_link: `<a href="#">Privacy Policy</a>`,
    website_link: `<a href="#">Auth Service</a>`
  }
 await sendSystemEmail(email, `Password Reset Request`, emailData, 'nottifications/index')
}

export async function sendEmailNotification(email: string,userName: string, vars: Partial<EmailData>) {
 const {magic_links} = getConfiguration()
  
  const defaults: EmailData = {
    title: "Password Reset Request",
    action: "Please reset your password",
    subject: "Reset your password",
    username: userName,
    message: `We received a request to reset your password. If you didn't make this request, you can safely ignore this email.`,
    cta: "Change Password",
    cta_link: magic_links.domain,
    websiteName: "Auth Service",
    privacy_link: `<a href="#">Privacy Policy</a>`,
    website_link: `<a href="#">Auth Service</a>`,
    ...vars
  }
  await sendSystemEmail(email, defaults.subject, defaults, 'nottifications/index')
}