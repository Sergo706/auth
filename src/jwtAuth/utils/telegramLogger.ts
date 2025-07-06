  import { Telegraf } from 'telegraf';
  import { getConfiguration } from '../config/configuration.js';


  type TgCtx = {
  bot: Telegraf;
  allowed: number;
  logChatId: number;
};

  let tg: TgCtx | undefined;  

  function getTelegram(): TgCtx {
    if (tg) return tg;
   const { telegram } = getConfiguration(); 
   const bot = new Telegraf(telegram.token!);
   const ALLOWED = Number(telegram.allowedUser);
   const LOG_CHAT_ID = Number(telegram.chatID);

   bot.use((ctx, next) => {
     if (ctx.from?.id !== ALLOWED) return;
     return next();
   });
   
  
   bot.command('id', ctx => {
     ctx.reply(`Chat ID: ${ctx.chat.id}`);
   });

  tg = {
    bot,
    allowed: Number(telegram.allowedUser),
    logChatId: Number(telegram.chatID)
  };
  return tg;

  }
  

 

  function escapeHtml(input: unknown): string {
    const text = input == null ? '' : String(input);
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }
/**
 * @description
 * Logs a message to your configured Telegram chat.
 *
 * @param {string} title
 *   A brief title or subject for the log message.
 * @param {string} message
 *   The detailed content of the log message to send.
 *
 * @returns {Promise<void>}
 *   Resolves when the message has been sent, or throws on failure.
 *
 * @see {@link ./telegramLogger.js}
 *
 * @example
 * await sendLog(
 *   'User signed up',
 *   'A new user has just signed up with email alice@example.com'
 * );
 */
  export async function sendLog(title: string, message: string) {
    const { bot, logChatId } = getTelegram();  
    try { 
    const header    = '<b>New Event Occurred</b>';
    const boldTitle = `<b>${escapeHtml(title)}</b>`;
    const body      = `<pre>${escapeHtml(message)}</pre>`;
  
    const text = [header, boldTitle, '', body].join('\n');
  
    return bot.telegram
      .sendMessage(logChatId, text, { parse_mode: 'HTML' })
    }catch(err) {
      console.log('Telegram Logger Error:', err)
    };
      
  }

