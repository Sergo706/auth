import { Resend } from 'resend';
import ejs from "ejs";
import { getConfiguration } from '../config/configuration.js';
import { getLogger } from './logger.js';
import { EmailData } from '../types/Emails.js';
import { getRoot, resolvePath } from '@riavzon/utils/server';
import { fileURLToPath } from 'url';
import path from 'path';


const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = getRoot(__dirname)
/**
 * @description
 * Sends emails via your SMTP provider.
 *
 * @param {string | string[]} recipients
 *   One or more recipient email addresses.
 * @param {string} subject
 *   The subject line for the email.
 * @param {import('./systemEmails.js').EmailData} userData
 *   The data to populate the email template (see `EmailData` in `systemEmails.js`).
 * @param {string} template
 *   The name of the email template to use.
 *
 * @returns {Promise<void>}
 *   Resolves when the email has been sent (or throws on failure).
 *
 * @see {@link ./systemEmails.js}
 *
 * @example
 * import { EmailData } from './systemEmails.js';
 *
 * const data: EmailData = {
 *   name: 'Alice',
 *   resetLink: 'https://example.com/reset?token=xyz'
 * };
 *
 * await sendSystemEmail(
 *   ['alice@example.com', 'bob@example.com'],
 *   'Welcome to Our Service!',
 *   data,
 *   'welcomeTemplate'
 * );
 */
export async function sendSystemEmail(
    recipients: string[] | string,
     subject: string, 
     userData: EmailData, 
     template: string,
    ): Promise<void> {
    const log = getLogger().child({service: 'auth', branch: 'utils', type: 'sendSystemEmail'})
    let html: string;
    const toField = Array.isArray(recipients) ? recipients : [recipients];
    const { email } = getConfiguration();
    const resend = new Resend(email.resend_key);
    const renderData = {
        ...userData
    }
    const templateFile = `${template}.ejs`;

 try {
      const filePath = resolvePath(templateFile, [
            'emails',
            'dist/emails', 
            'src/jwtAuth/emails'
        ], [], root);
        html = await ejs.renderFile(filePath, renderData)
   } catch(err) {
         log.error({err},`Failed to render template '${templateFile}'`);
         throw err;
   }

  const { data, error } = await resend.emails.send({
    from: email.email,
    to: toField,
    subject: subject,
    html: html,
  });

  if (error) {
    return log.error( {error} );
  }

  log.info( {data}, " Email sent");
}





