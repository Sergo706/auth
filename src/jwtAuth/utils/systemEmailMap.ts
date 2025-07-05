import { EmailData } from "./systemEmails.js";
import { sendSystemEmail } from "./systemEmails.js";

export async function mfaEmail(userName: string, code: number, email: string, url: string): Promise<void> {
    
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
 await sendSystemEmail(email, `Securtiy alert`, emailData, 'system')
}

export async function resetPasswordEmail(userName: string, email: string, url: string) {

const emailData: EmailData = {
    userName: userName,
    message: `If you didn't requested to change your password, Please ignore this email, 
    and enable multi-factor authentication if you haven't already.`,
    headers: {
        headerOne: 'Password Reset',
        headerTwo: 'To Change your password click the button below.',
    },
    link: [
        {
        label: `Change Password`,
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
 await sendSystemEmail(email, `Securtiy alert`, emailData, 'system')
}
