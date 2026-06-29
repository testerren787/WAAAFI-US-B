#!/usr/bin/env node
require('dotenv').config();
const https = require('https');

const MAX_USERS = parseInt(process.env.MAX_USERS) || 10;

function deleteWebhook(botToken, userName) {
  return new Promise((resolve, reject) => {
    const url = `https://api.telegram.org/bot${botToken}/deleteWebhook?drop_pending_updates=true`;
    
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.ok) {
            console.log(`✅ ${userName}: Old connections closed`);
            resolve(true);
          } else {
            console.log(`⚠️  ${userName}: ${result.description}`);
            resolve(false);
          }
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

async function cleanupAllBots() {
  console.log('🧹 Cleaning up old bot connections...');
  
  for (let i = 1; i <= MAX_USERS; i++) {
    const botToken = process.env[`TELEGRAM_BOT_TOKEN_${i}`];
    const userName = process.env[`USER_NAME_${i}`] || `User ${i}`;
    
    if (botToken) {
      await deleteWebhook(botToken, userName);
      await new Promise(resolve => setTimeout(resolve, 500)); // Rate limit protection
    }
  }
  
  console.log('✅ Cleanup complete!');
}

cleanupAllBots().catch(console.error);