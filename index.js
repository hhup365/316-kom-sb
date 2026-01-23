#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

// ----------------------------------------------------------------------
// 配置区域
// ----------------------------------------------------------------------
const WORK_DIR = path.resolve(process.env.DATA_PATH || './sbata');
if (!fs.existsSync(WORK_DIR)) fs.mkdirSync(WORK_DIR, { recursive: true });

const ENV = {
    // Ports
    RSPT: (process.env.RSPT || "").trim(),
    HSPT: (process.env.HSPT || "").trim(),
    TSPT: (process.env.TSPT || "").trim(),
    ASPT: (process.env.ASPT || "").trim(),
    SSPT: (process.env.SSPT || "").trim(),
    WEB: parseInt(process.env.WEBPT || 3000),
    // Credentials
    R_ID: (process.env.RUDPS || "").trim(),
    H_PS: (process.env.HSPS || "").trim(),
    H_OB: (process.env.HSBPS || "").trim(),
    T_ID: (process.env.TUDPS || "").trim(),
    T_PS: (process.env.TSPS || "").trim(),
    A_ID: (process.env.AUDPS || "").trim(),
    S_US: (process.env.SSNAME || "").trim(),
    S_PS: (process.env.SSPS || "").trim(),
    // Config
    PATH: (process.env.LINK_PATH || "/api/data").trim(),
    RE_PATH: "/api/re",
    SNI: (process.env.RSIN || "bunny.net").trim(),
    DEST: (process.env.RDEST || "bunny.net:443").trim(),
    TAG: process.env.PNAME || "ABC",
    // Remote
    KM: (process.env.KMHOST || "").trim(),
    KA: (process.env.KMAUTH || "").trim(),
    // Certs
    CU: (process.env.CERURL || "").trim(),
    KU: (process.env.KEYURL || "").trim(),
    DOM: (process.env.CERDN || "").trim(),
    // Toggles
    OB_EN: (process.env.SBFS || "false").trim()
};

const FILES = {
    REG: path.join(WORK_DIR, 'sys_reg.dat'),
    DB: path.join(WORK_DIR, 'security.db'),
    PAIR: path.join(WORK_DIR, 'transport.bin'),
    CRT: path.join(WORK_DIR, 'server.crt'),
    KEY: path.join(WORK_DIR, 'server.key'),
    CFG: path.join(WORK_DIR, 'config.json'),
    BLOB: path.join(WORK_DIR, 'blob.dat')
};

let coreChild = null;
let sideChild = null;
let isReloading = false;

// ----------------------------------------------------------------------
// 自签证书 (RSA 2048)
// ----------------------------------------------------------------------
const SELF_CRT = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIUWjY6/j2lJ0iH0n4qX8yQz5dF7q0wDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUUGxhaWNlaG9sZGVyIFNlcnZpY2UwHhcNMjQwMTAxMDAw
MDAwWhcNcjkxMjMxMjM1OTU5WjAfMR0wGwYDVQQDDBRQbGFpY2Vob2xkZXIgU2Vy
dmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM+X8yQz5dF7q3wX
8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz
5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7
q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX
8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz
5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wCAwEAAaNTMFEwHQYDVR0OBBYEFM+X8yQz
5dF7q3wX8yQz5dF7q3wXMB8GA1UdIwQYMBaAFM+X8yQz5dF7q3wX8yQz5dF7q3wX
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAM+X8yQz5dF7q3wX
8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz
5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7
q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX
8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz
5dF7q3w=
-----END CERTIFICATE-----`;

const SELF_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPl/MkM+XRe6t8
F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/Mk
M+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XR
e6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8
F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/Mk
M+XRe6t8AgMBAAECggEBAJ/qjXfWjG8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3
wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8y
Qz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5d
F7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3
wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wX8yQz5dF7q3wQEC
gYEA/l/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t
8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/M
kM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8ECgYEA0ZfzJDP10Xurf
BfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJ
DP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10
XurfBfzJDP10XurfBfzJDP10XurfBAKBgQCf6o131oxvMkM+XRe6t8F/MkM+XRe6
t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/
MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+
XRe6t8ECgYEA15fzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfz
JDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP1
0XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBfzJDP10XurfBAKBgQDPl/M
kM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+X
Re6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t
8F/MkM+XRe6t8F/MkM+XRe6t8F/MkM+XRe6t8A==
-----END PRIVATE KEY-----`;

// ----------------------------------------------------------------------
// 核心工具
// ----------------------------------------------------------------------
const log = (scope, msg) => console.log(`[${new Date().toISOString().slice(11, 19)}] [${scope}] ${msg}`);
const save = (f, d, m = 0o644) => {
    const tmp = f + `.${Date.now()}.swp`;
    try { fs.writeFileSync(tmp, d, { mode: m }); fs.renameSync(tmp, f); } 
    catch (e) { try { fs.unlinkSync(tmp); } catch (x) {} }
};

function fetch(url) {
    return new Promise((resolve, reject) => {
        const proto = url.startsWith('https') ? https : http;
        const req = proto.get(url, { timeout: 10000, rejectUnauthorized: false }, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location)
                return fetch(res.headers.location).then(resolve).catch(reject);
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => resolve(data));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
}

function pull(url, dest) {
    if (!url) return Promise.resolve(false);
    return new Promise((resolve) => {
        const tmp = dest + `.${Date.now()}.dl`;
        const proto = url.startsWith('https') ? https : http;
        const file = fs.createWriteStream(tmp);
        const req = proto.get(url, { timeout: 15000, rejectUnauthorized: false }, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                file.close(); return pull(res.headers.location, dest).then(resolve);
            }
            res.pipe(file);
            file.on('finish', () => {
                file.close(() => {
                    try { fs.renameSync(tmp, dest); resolve(true); } 
                    catch (e) { fs.unlink(tmp, () => {}); resolve(false); }
                });
            });
        });
        req.on('error', () => { file.close(); fs.unlink(tmp, () => {}); resolve(false); });
    });
}

// ----------------------------------------------------------------------
// 业务逻辑
// ----------------------------------------------------------------------
function genString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let res = '';
    for (let i = 0; i < length; i++) res += chars.charAt(crypto.randomInt(chars.length));
    return res;
}

function getCreds(bin) {
    let db = {};
    try { db = JSON.parse(fs.readFileSync(FILES.DB, 'utf8')); } catch (e) {}
    const get = (key, envVal, genFunc) => {
        if (envVal) return envVal;
        if (db[key]) return db[key];
        const v = genFunc(); db[key] = v; return v;
    };
    const c = {};
    c.id_r = get('id_r', ENV.R_ID, () => crypto.randomUUID());
    c.ps_h = get('ps_h', ENV.H_PS, () => genString(32));
    c.ob_h = get('ob_h', ENV.H_OB, () => genString(32));
    c.id_t = get('id_t', ENV.T_ID, () => crypto.randomUUID());
    c.ps_t = get('ps_t', ENV.T_PS, () => genString(32));
    c.id_a = get('id_a', ENV.A_ID, () => crypto.randomUUID());
    c.us_s = get('us_s', ENV.S_US, () => genString(8));
    c.ps_s = get('ps_s', ENV.S_PS, () => genString(32));

    if (ENV.RSPT && bin) {
        if (!fs.existsSync(FILES.PAIR)) {
            try { save(FILES.PAIR, execSync(`"${bin}" generate reality-keypair`).toString()); } catch (e) {}
        }
        try {
            const raw = fs.readFileSync(FILES.PAIR, 'utf8');
            c.pk_r = raw.match(/PrivateKey:\s*(\S+)/)[1];
            c.pb_r = raw.match(/PublicKey:\s*(\S+)/)[1];
            c.si_r = get('si_r', null, () => crypto.randomBytes(4).toString('hex'));
        } catch (e) {}
    }
    save(FILES.DB, JSON.stringify(db, null, 2));
    return c;
}

async function loadBin(alias) {
    const regFile = FILES.REG;
    let reg = {};
    try { reg = JSON.parse(fs.readFileSync(regFile, 'utf8')); } catch (e) {}
    const arch = { x64: 'amd64', arm64: 'arm64' }[os.arch()];
    if (!arch) return null;
    const SRC = {
        core: { amd64: "https://rt.jp.eu.org/nucleusp/S/Samd", arm64: "https://rt.jp.eu.org/nucleusp/S/Sarm" },
        side: { amd64: "https://rt.jp.eu.org/nucleusp/K/Kamd", arm64: "https://rt.jp.eu.org/nucleusp/K/Karm" }
    };
    const url = alias === 'core' ? SRC.core[arch] : SRC.side[arch];
    const prefix = alias === 'core' ? 'S_' : 'K_';
    if (reg[alias] && fs.existsSync(path.join(WORK_DIR, reg[alias]))) return path.join(WORK_DIR, reg[alias]);

    log('Sys', `Updating [${alias}]...`);
    const name = `${prefix}${crypto.randomBytes(4).toString('hex')}`;
    const local = path.join(WORK_DIR, name);
    if (await pull(url, local)) {
        fs.chmodSync(local, 0o755);
        reg[alias] = name;
        save(regFile, JSON.stringify(reg));
        try { fs.readdirSync(WORK_DIR).forEach(f => { if(f.startsWith(prefix) && f !== name) fs.unlinkSync(path.join(WORK_DIR, f)); }); } catch(e){}
        return local;
    }
    return null;
}

// 证书准备逻辑：返回 isSelfSigned 状态
async function prepareCerts(needsCert) {
    if (!needsCert) return false;

    // 1. 强制下载尝试
    if (ENV.CU && ENV.KU) {
        const [cOk, kOk] = await Promise.all([ pull(ENV.CU, FILES.CRT), pull(ENV.KU, FILES.KEY) ]);
        if (!cOk || !kOk) log('Cert', 'Download failed, checking local/fallback...');
    }

    // 2. 检查本地是否存在
    let exists = fs.existsSync(FILES.CRT) && fs.existsSync(FILES.KEY);

    // 3. 判断是否为自签 (如果本地文件内容与内置自签一致)
    let isSelf = false;
    if (exists) {
        try {
            const currentCrt = fs.readFileSync(FILES.CRT, 'utf8');
            // 简单的内容比对，判断是否是内置的 Self Cert
            if (currentCrt.includes('MIIDXTCCAkWgAwIBAgIUWjY6/j2lJ0iH0n4qX8yQz5dF7q0wDQYJKoZIhvcNAQEL')) {
                isSelf = true;
            }
        } catch(e) {}
    } else {
        // 不存在，写入自签
        log('Cert', 'Using built-in self-signed certs.');
        try {
            fs.writeFileSync(FILES.CRT, SELF_CRT);
            fs.writeFileSync(FILES.KEY, SELF_KEY);
            exists = true;
            isSelf = true;
        } catch(e) {
            log('ERR', 'Failed to write certs');
        }
    }
    
    return isSelf;
}

async function setup(bin, listenAddr) {
    const creds = getCreds(bin);
    const needsCert = !!(ENV.HSPT || ENV.TSPT || ENV.ASPT);
    
    // 获取证书状态
    const isSelfSigned = await prepareCerts(needsCert);

    const inbounds = [];
    const tlsBase = { enabled: true, certificate_path: FILES.CRT, key_path: FILES.KEY };
    const listen = listenAddr;

    // 1. Reality
    if (ENV.RSPT && creds.pk_r) {
        const [dHost, dPort] = ENV.DEST.split(':');
        inbounds.push({
            type: "vless", tag: "in-01", listen, listen_port: +ENV.RSPT,
            users: [{ uuid: creds.id_r, flow: "xtls-rprx-vision" }],
            tls: {
                enabled: true, server_name: ENV.SNI,
                reality: { enabled: true, handshake: { server: dHost, server_port: +(dPort || 443) }, private_key: creds.pk_r, short_id: [creds.si_r] }
            }
        });
    }

    // 2. Hysteria2
    if (ENV.HSPT) {
        const hy = {
            type: "hysteria2", tag: "in-02", listen, listen_port: +ENV.HSPT,
            users: [{ password: creds.ps_h }], 
            masquerade: "https://bing.com", // 自签模式下伪装
            tls: tlsBase, ignore_client_bandwidth: false
        };
        if (ENV.OB_EN === "true") hy.obfs = { type: "salamander", password: creds.ob_h };
        inbounds.push(hy);
    }

    // 3. Tuic
    if (ENV.TSPT) {
        inbounds.push({
            type: "tuic", tag: "in-03", listen, listen_port: +ENV.TSPT,
            users: [{ uuid: creds.id_t, password: creds.ps_t }],
            congestion_control: "bbr", tls: { ...tlsBase, alpn: ["h3"] }
        });
    }

    // 4. AnyTLS
    if (ENV.ASPT) {
        inbounds.push({
            type: "anytls", tag: "in-04", listen, listen_port: +ENV.ASPT,
            users: [{ password: creds.id_a }], padding_scheme: [], tls: tlsBase
        });
    }

    if (ENV.SSPT) {
        inbounds.push({
            type: "socks", tag: "in-05", listen, listen_port: +ENV.SSPT,
            users: [{ username: creds.us_s, password: creds.ps_s }]
        });
    }

    if (inbounds.length === 0) return { creds, hasProxy: false, isSelfSigned: false };

    save(FILES.CFG, JSON.stringify({
        log: { disabled: true, level: "error", timestamp: true },
        inbounds, outbounds: [{ type: "direct", tag: "direct" }]
    }, null, 2));

    return { creds, hasProxy: true, isSelfSigned };
}

function fork(name, bin, args, env) {
    const p = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], env });
    const h = (d) => {
        if (isReloading) return;
        const s = d.toString();
        if (s.match(/panic|fatal/i)) log('ERR', `[${name}] ${s.slice(0, 50)}...`);
    };
    p.stdout.on('data', h); p.stderr.on('data', h);
    p.on('exit', (code, signal) => {
        if (isReloading || signal === 'SIGTERM') return;
        setTimeout(() => {
            if (name === 'Core' && coreChild === null) return;
            if (name === 'Side' && sideChild === null) return;
            const newProc = fork(name, bin, args, env);
            if (name === 'Core') coreChild = newProc; else sideChild = newProc;
        }, 5000);
    });
    return p;
}

// ----------------------------------------------------------------------
// 启动程序
// ----------------------------------------------------------------------
async function boot() {
    isReloading = true;
    if (coreChild) { coreChild.kill('SIGTERM'); coreChild = null; }
    if (sideChild) { sideChild.kill('SIGTERM'); sideChild = null; }

    await new Promise(r => setTimeout(r, 5000));
    isReloading = false;

    let detectedIPs = [];
    let listenAddr = "0.0.0.0";
    const [v4, v6] = await Promise.allSettled([ fetch('https://api.ipify.org'), fetch('https://api64.ipify.org') ]);

    if (v4.status === 'fulfilled' && v4.value.match(/^\d+\.\d+\.\d+\.\d+$/)) detectedIPs.push(v4.value.trim());
    if (v6.status === 'fulfilled' && v6.value.includes(':')) {
        detectedIPs.push(v6.value.trim());
        listenAddr = "::";
    }
    if (detectedIPs.length === 0) detectedIPs.push("127.0.0.1");
    else detectedIPs = [...new Set(detectedIPs)];

    log('Net', `Detected IPs: ${detectedIPs.join(', ')}`);

    const coreBin = await loadBin('core');
    const { creds, hasProxy, isSelfSigned } = await setup(coreBin, listenAddr);

    if (hasProxy && coreBin) {
        coreChild = fork('Core', coreBin, ['run', '-c', FILES.CFG], { ...process.env, GOGC: "50" });
        log('Sys', 'Core Started');
    }

    if (ENV.KM) {
        const sideBin = await loadBin('side');
        if (sideBin) {
            sideChild = fork('Side', sideBin, ['-e', ENV.KM.startsWith('http')?ENV.KM:`https://${ENV.KM}`, '-t', ENV.KA], {});
            log('Sys', 'Side Started');
        }
    }

    let links = "";
    const P = ENV.TAG;
    
    for (const ip of detectedIPs) {
        const isV6 = ip.includes(':');
        const safeIP = isV6 ? `[${ip}]` : ip;
        const suffix = isV6 ? `(v6)` : ``;

        if (ENV.RSPT)
            links += `vless://${creds.id_r}@${safeIP}:${ENV.RSPT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${ENV.SNI}&fp=firefox&pbk=${creds.pb_r}&sid=${creds.si_r}&type=tcp#${P}-Reality${suffix}\n`;
        
        if (ENV.HSPT) {
            const hSni = isSelfSigned ? "www.bing.com" : ENV.DOM;
            const hIns = isSelfSigned ? 1 : 0;
            links += `hysteria2://${creds.ps_h}@${safeIP}:${ENV.HSPT}/?sni=${hSni}&insecure=${hIns}`;
            if (ENV.OB_EN === "true") links += `&obfs=salamander&obfs-password=${creds.ob_h}`;
            links += `#${P}-Hy2${suffix}\n`;
        }

        if (ENV.TSPT) {
            const tSni = isSelfSigned ? "www.bing.com" : ENV.DOM;
            const tIns = isSelfSigned ? 1 : 0;
            links += `tuic://${creds.id_t}:${creds.ps_t}@${safeIP}:${ENV.TSPT}?sni=${tSni}&alpn=h3&congestion_control=bbr&allowInsecure=${tIns}#${P}-Tuic${suffix}\n`;
        }

        if (ENV.ASPT) {
            const aSni = isSelfSigned ? "" : `&sni=${ENV.DOM}`;
            const aIns = isSelfSigned ? 1 : 0;
            links += `anytls://${creds.id_a}@${safeIP}:${ENV.ASPT}?security=tls${aSni}&insecure=${aIns}&allowInsecure=${aIns}&type=tcp#${P}-Any${suffix}\n`;
        }

        if (ENV.SSPT)
            links += `socks5://${creds.us_s}:${creds.ps_s}@${safeIP}:${ENV.SSPT}#${P}-Socks${suffix}\n`;
    }

    const b64 = Buffer.from(links).toString('base64');
    save(FILES.BLOB, b64);

    if (hasProxy) {
        console.log('\n' + '='.repeat(10) + ' TOKEN ' + '='.repeat(10));
        console.log(b64);
        console.log('='.repeat(27) + '\n');
    }
}

boot();

http.createServer(async (req, res) => {
    const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-cache', 'Server': 'nginx/1.25.1' };
    if (req.url === ENV.PATH) {
        if (fs.existsSync(FILES.BLOB)) {
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            fs.createReadStream(FILES.BLOB).pipe(res);
        } else { res.writeHead(404, headers); res.end(JSON.stringify({ code: 404, msg: "Not Found" })); }
        return;
    }
    if (req.url === ENV.RE_PATH) {
        res.writeHead(200, headers); res.end(JSON.stringify({ code: 0, msg: "Reloading..." }));
        try { if (fs.existsSync(FILES.CRT)) fs.unlinkSync(FILES.CRT); if (fs.existsSync(FILES.KEY)) fs.unlinkSync(FILES.KEY); } catch (e) {}
        await boot(); return;
    }
    res.writeHead(200, headers); res.end(JSON.stringify({ code: 0, msg: "ok", data: { version: "3.2.0", status: "operational", ts: Date.now() } }));
}).listen(ENV.WEB, () => {});
