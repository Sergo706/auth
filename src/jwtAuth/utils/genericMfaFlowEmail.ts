import { EmailData } from "./systemEmails.js";
import { sendSystemEmail } from "./systemEmails.js";

export async function sendGenericMfaEmail(userName: string, code: number, email: string, url: string): Promise<void> {
    
const emailData: EmailData = {
    userName: userName,
    code: code,
    message: `If you didn't requested a code, Please change your password immediately,
     and enable multi-factor authentication if you haven't already.`,
    headers: {
        headerOne: 'Security Code',
        headerTwo: 'To continue please enter the code below',
    },
    link: [
        {
        label: `Verify Here`,
        path: url
        }
    ],
       images: [
        {
        path: 'https://media.riavzon.com/image-2.png',
        name: 'auth',
        alt: 'authentication',
       }
]
  }
 await sendSystemEmail(email, `Security alert`, emailData, 'system')
}
