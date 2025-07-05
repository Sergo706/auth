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

