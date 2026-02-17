export interface OTPEmails {
  /**
   * The URL the button points to
   */
  link: string,
  /**
   * The 7-digit OTP code	
   */
  code: string | number,
  /**
   * OS string
   */
  device: string,
  /**
   * Browser
   */
  browser: string,
  /**
   * IP-based location
   */
  location: string,
  /**
   * 	Formatted timestamp
   */
  date: string,
  /**
   * Button Label
   */
  cta: string,
  banner_image: string,
  device_image: string,
  location_image: string,
  date_image: string,
  link_to_reset_password: string
}
export interface NotificationEmails {
  /**
   * The big header text
   */
  title: string
  /**
   * Sub-header / Instruction (e.g. "Please login to your email account again")
   */
  action: string
  /**
   * Email subject line (appears in body)
   */
  subject: string,
  /**
   * User's display name
   */
  username: string,
  /**
   * The main body text (supports HTML)
   */
  message: string,
  /**
   * Button Label
   */
  cta: string,
  /**
   * CTA link
   */
  cta_link: string,
  /**
   * Name in signature (e.g. "Auth Service Team")
   */
  websiteName: string,
  /**
   * Link to privacy policy
   */
  privacy_link: string,
  /**
   * Link to contact page
   */
  contact_link: string,
  main_image: string,
}
export type EmailData = OTPEmails | NotificationEmails;
export interface EmailMetaDataOTP {
    device: string,
    browser: string,
    location: string
}