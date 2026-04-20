import { getConfiguration } from '../config/configuration.js';
import { EmailData, EmailMetaDataOTP } from '../types/Emails.js';
import { sendSystemEmail } from "./systemEmails.js";


export async function mfaEmail(code: number, email: string, url: string, meta: EmailMetaDataOTP): Promise<void> {
  const { device, location, browser } = meta  
  const { magic_links } = getConfiguration();
  const { bannerImage, date_image, device_image, location_image } = magic_links.emailImages.otp;

const emailData: EmailData = {
    link: url,
    code: code,
    device: device ?? "Unknown Device",
    location: location ?? "Unknown Location",
    date: new Date().toLocaleString(),
    cta: "Verify Here",
    browser: browser ?? "Unknown Browser",
    link_to_reset_password: magic_links.linkToResetPasswordPage,
    banner_image: bannerImage,
    date_image,
    device_image,
    location_image
  }
 await sendSystemEmail(email, `Security Code - ${code}`, emailData, 'OTP/index')
}

export async function resetPasswordEmail(userName: string, email: string, url: string) {
 const {magic_links} = getConfiguration()
 const { notificationBanner } = magic_links.emailImages
 const { websiteName, privacyPolicyLink, contactPageLink } = magic_links.notificationEmail;

const emailData: EmailData = {
    title: "Password Reset Request",
    action: "Please reset your password",
    subject: "Reset your password",
    username: userName,
    message: `We received a request to reset your password. If you didn't make this request, you can safely ignore this email.`,
    cta_link: url,
    cta: "Change Password",
    websiteName: websiteName,
    privacy_link: privacyPolicyLink,
    contact_link: contactPageLink,
    main_image: notificationBanner
  }
 await sendSystemEmail(email, `Password Reset Request`, emailData, 'nottifications/index')
}

export async function sendEmailNotification(email: string,userName: string, vars: Partial<EmailData>) {
 const {magic_links} = getConfiguration()
 const { notificationBanner } = magic_links.emailImages
 const { websiteName, privacyPolicyLink, changePasswordPageLink, contactPageLink } = magic_links.notificationEmail;
  const defaults: EmailData = {
    title: "Password Reset Request",
    action: "Please reset your password",
    subject: "Reset your password",
    username: userName,
    message: `We received a request to reset your password. If you didn't make this request, you can safely ignore this email.`,
    cta: "Change Password",
    cta_link: changePasswordPageLink,
    websiteName: websiteName,
    privacy_link: privacyPolicyLink,
    contact_link: contactPageLink,
    main_image: notificationBanner,
    ...vars
  }
  await sendSystemEmail(email, defaults.subject, defaults, 'nottifications/index')
}