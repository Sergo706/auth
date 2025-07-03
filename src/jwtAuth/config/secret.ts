import dotenv from 'dotenv'
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

export const config = {
  db: {
    host: process.env.DATABASE_HOST,
    port: process.env.DATABASE_PORT,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_SECRET,
    name: process.env.DATABASE_NAME,
  },

  telegram: {
    token: process.env.BOT_TOKEN,
    allowedUser: process.env.ALLOWED_USER_ID,
    chatID: process.env.LOG_CHAT_ID
  },

  cookies: { 
  cannary: process.env.cannary_id
  },

  auth: {
    userAuth: {
      pepper: process.env.PEPPER
    },
    jwt: {
      jwt_secret: process.env.JWT_SECRET,
      refresh_ttl: 1000 * 60 * 60 * 24 * 3,
      domain: 'testing.com',
      magicLinks: process.env.JWT_LINKS,
      MAX_SESSION_LIFE: 14 * 24 * 60 * 60 * 1000
    }
  },
      email: {
      resend: process.env.EMAIL
    },
    logs: 'debug'
};
