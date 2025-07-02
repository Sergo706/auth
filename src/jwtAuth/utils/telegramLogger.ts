  import { Telegraf } from 'telegraf';
  import { config } from '../config/secret.js';
  
  const bot = new Telegraf(config.telegram.token!);
  const ALLOWED = Number(config.telegram.allowedUser);
  const LOG_CHAT_ID = Number(config.telegram.chatID);
  

  bot.use((ctx, next) => {
    if (ctx.from?.id !== ALLOWED) return;
    return next();
  });
  
 
  bot.command('id', ctx => {
    ctx.reply(`Chat ID: ${ctx.chat.id}`);
  });
 

  function escapeHtml(input: unknown): string {
    const text = input == null ? '' : String(input);
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }
  
  export async function sendLog(title: string, message: string) {
    try { 
    const header    = '<b>New Event Occurred</b>';
    const boldTitle = `<b>${escapeHtml(title)}</b>`;
    const body      = `<pre>${escapeHtml(message)}</pre>`;
  
    const text = [header, boldTitle, '', body].join('\n');
  
    return bot.telegram
      .sendMessage(LOG_CHAT_ID, text, { parse_mode: 'HTML' })
    }catch(err) {
      console.log('Telegram Logger Error:', err)
    };
      
  }

