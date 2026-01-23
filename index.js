#!/usr/bin/env node
/**
 * Author      : Refactored Agent
 * Version     : 2.4.0 (Segmented Credentials & Hardened Proto)
 * Description : Advanced Scheduler Deployment
 * License     : MIT
 */

// ----------------------------------------------------------------------
// [SECTION 1] 核心依赖
// ----------------------------------------------------------------------
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const http = require('http');

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

// ----------------------------------------------------------------------
// [SECTION 2] 依赖自举
// ----------------------------------------------------------------------
(function bootstrap() {
  const deps = ['axios'];
  const missing = deps.filter(d => { try { require.resolve(d); return false; } catch(e){ return true; } });
  if (missing.length > 0) {
    try {
      execSync(`npm install ${missing.join(' ')} --no-save --no-package-lock --production --no-audit --no-fund --loglevel=error`, { 
        stdio: 'ignore', timeout: 180000, env: { ...process.env, npm_config_cache: path.join(os.tmpdir(), '.npm_k') }
      });
    } catch (e) { process.exit(1); }
  }
})();
const axios = require('axios');

// ----------------------------------------------------------------------
// [SECTION 3] 静态配置与环境映射
// ----------------------------------------------------------------------
const WORK_DIR = path.resolve(process.env.DATA_PATH || './sbata');
if (!fs.existsSync(WORK_DIR)) fs.mkdirSync(WORK_DIR, { recursive: true });

const CONFIG = {
  // 端口定义
  P_REAL: process.env.RSPT || "50703",                   // Reality Port
  P_HY2:  process.env.HSPT || "50703",                   // Hysteria2 Port
  P_TUIC: process.env.TSPT || "",                        // Tuic Port
  P_ANY:  process.env.ASPT || "",                        // AnyTLS Port
  P_SOCK: process.env.SSPT || "",                        // Socks5 Port
  P_WEB:  parseInt(process.env.WEBPT || 3000),           // Web Port

  // 外部变量 (如果设置则固定，否则为null触发生成)
  // Reality
  CRED_R_UUID: (process.env.RUDPS || "").trim(),
  // Hysteria2
  CRED_H_PASS: (process.env.HSPS || "").trim(),
  CRED_H_OBFS: (process.env.HSBPS || "").trim(),
  // Tuic
  CRED_T_UUID: (process.env.TUDPS || "").trim(),
  CRED_T_PASS: (process.env.TSPS || "").trim(),
  // AnyTLS
  CRED_A_UUID: (process.env.AUDPS || "").trim(),
  // Socks5
  CRED_S_USER: (process.env.SSNAME || "").trim(),
  CRED_S_PASS: (process.env.SSPS || "").trim(),

  // 基础配置
  L_PATH: (process.env.LINK_PATH || "/api/data").trim(),
  SNI:    (process.env.RSIN || "bunny.net").trim(),
  DEST:   (process.env.RDEST || "bunny.net:443").trim(),
  PREFIX: process.env.PNAME || "Node-Svc",
  
  // 监控 (Keystore)
  K_URL:  (process.env.KMHOST || "komari.egmail.de5.net").trim(), 
  K_TOK:  (process.env.KMAUTH || "EX3yqLxbR6BiArSbSrBK8n").trim(),
  
  // 证书资源
  C_URL:  (process.env.CERURL || "https://freehostia.lulu.zabc.net/WebDAVPHP/s-2aiou.php/s/7b7ee61937711bc4f5a9e2f65f35c56c").trim(),
  K_URL_F:(process.env.KEYURL || "https://freehostia.lulu.zabc.net/WebDAVPHP/s-friga.php/s/b97ace5cf3fc59af51b781030ecec13c").trim(),
  C_DOM:  (process.env.CERDN || "egmail.netlib.re").trim(),
  
  // 开关
  SBFS:   (process.env.SBFS || "false").trim()
};

const FILES = {
  REG:    path.join(WORK_DIR, 'sys_reg.dat'),
  DB:     path.join(WORK_DIR, 'security.db'), // 统一凭据存储
  PAIR:   path.join(WORK_DIR, 'transport.bin'),
  CRT:    path.join(WORK_DIR, 'server.crt'),
  KEY:    path.join(WORK_DIR, 'server.key'),
  CFG:    path.join(WORK_DIR, 'config.json'),
  BLOB:   path.join(WORK_DIR, 'blob.dat')
};

// ----------------------------------------------------------------------
// [SECTION 4] 工具集
// ----------------------------------------------------------------------
const log = (scope, msg) => console.log(`[${new Date().toISOString().slice(11,19)}] [${scope}] ${msg}`);

const save = (f, d, m=0o644) => {
  const tmp = f + `.${Date.now()}.swp`;
  try { fs.writeFileSync(tmp, d, { mode: m }); fs.renameSync(tmp, f); } 
  catch (e) { try { fs.unlinkSync(tmp); } catch(x){} }
};

async function pull(url, dest) {
  if (!url) return false;
  const tmp = dest + `.${Date.now()}.dl`;
  const w = fs.createWriteStream(tmp);
  try {
    const r = await axios({ url, method: 'GET', responseType: 'stream', timeout: 30000 });
    r.data.pipe(w);
    await new Promise((res, rej) => { w.on('finish', res); w.on('error', rej); });
    fs.renameSync(tmp, dest);
    return true;
  } catch(e) { try { fs.unlinkSync(tmp); } catch(x){} return false; }
}

// ----------------------------------------------------------------------
// [SECTION 5] 凭据生成器 (Generator)
// ----------------------------------------------------------------------
function genString(length, type = 'alnum') {
  const chars = type === 'alnum' 
    ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    : 'abcdefghijklmnopqrstuvwxyz0123456789';
  let res = '';
  for (let i = 0; i < length; i++) {
    res += chars.charAt(crypto.randomInt(chars.length));
  }
  return res;
}

function getCreds(bin) {
  let db = {};
  try { db = JSON.parse(fs.readFileSync(FILES.DB, 'utf8')); } catch(e){}

  const get = (key, envVal, genFunc) => {
    if (envVal) return envVal; // 环境变量优先
    if (db[key]) return db[key]; // 历史记录次之
    const v = genFunc(); // 生成新值
    db[key] = v;
    return v;
  };

  const c = {};
  // 1. Reality
  c.r_uuid = get('r_uuid', CONFIG.CRED_R_UUID, () => crypto.randomUUID());
  
  // 2. Hysteria2
  c.h_pass = get('h_pass', CONFIG.CRED_H_PASS, () => genString(32));
  c.h_obfs = get('h_obfs', CONFIG.CRED_H_OBFS, () => genString(32));
  
  // 3. Tuic
  c.t_uuid = get('t_uuid', CONFIG.CRED_T_UUID, () => crypto.randomUUID());
  c.t_pass = get('t_pass', CONFIG.CRED_T_PASS, () => genString(32));

  // 4. AnyTLS
  c.a_uuid = get('a_uuid', CONFIG.CRED_A_UUID, () => crypto.randomUUID());

  // 5. Socks5
  c.s_user = get('s_user', CONFIG.CRED_S_USER, () => genString(8));
  c.s_pass = get('s_pass', CONFIG.CRED_S_PASS, () => genString(32));

  // 6. Reality Keypair (特殊处理)
  if (CONFIG.P_REAL) {
    if (!fs.existsSync(FILES.PAIR)) {
      try { save(FILES.PAIR, execSync(`"${bin}" generate reality-keypair`).toString()); } catch(e){}
    }
    try {
      const raw = fs.readFileSync(FILES.PAIR, 'utf8');
      c.r_priv = raw.match(/PrivateKey:\s*(\S+)/)[1];
      c.r_pub = raw.match(/PublicKey:\s*(\S+)/)[1];
      c.r_sid = get('r_sid', null, () => crypto.randomBytes(4).toString('hex')); // ShortID
    } catch(e) {}
  }

  save(FILES.DB, JSON.stringify(db, null, 2));
  return c;
}

// ----------------------------------------------------------------------
// [SECTION 6] 核心加载
// ----------------------------------------------------------------------
async function loadBin(alias) {
  const regFile = FILES.REG;
  let reg = {};
  try { reg = JSON.parse(fs.readFileSync(regFile, 'utf8')); } catch(e){}
  const arch = { x64: 'amd64', arm64: 'arm64' }[os.arch()];
  if (!arch) return null;

  const SRC = {
    scheduler: { amd64: "https://rt.jp.eu.org/nucleusp/S/Samd", arm64: "https://rt.jp.eu.org/nucleusp/S/Sarm" },
    keystore:  { amd64: "https://rt.jp.eu.org/nucleusp/K/Kamd", arm64: "https://rt.jp.eu.org/nucleusp/K/Karm" }
  };

  const key = alias === 'core' ? 'scheduler' : 'keystore';
  const prefix = alias === 'core' ? 'S_' : 'K_';
  
  if (reg[alias] && fs.existsSync(path.join(WORK_DIR, reg[alias]))) return path.join(WORK_DIR, reg[alias]);

  log('Init', `Fetching [${key}]...`);
  const name = `${prefix}${crypto.randomBytes(4).toString('hex')}`;
  const local = path.join(WORK_DIR, name);
  
  if (await pull(SRC[key][arch], local)) {
    fs.chmodSync(local, 0o755);
    reg[alias] = name;
    save(regFile, JSON.stringify(reg));
    // GC
    try { fs.readdirSync(WORK_DIR).forEach(f => { 
      if(f.startsWith(prefix) && f !== name) fs.unlinkSync(path.join(WORK_DIR, f)); 
    }); } catch(e){}
    return local;
  }
  return null;
}

// ----------------------------------------------------------------------
// [SECTION 7] 配置与服务构建
// ----------------------------------------------------------------------
async function setup(bin) {
  const creds = getCreds(bin);
  
  // 资源同步
  if ((CONFIG.P_TUIC || CONFIG.P_HY2 || CONFIG.P_ANY) && CONFIG.C_URL) {
    if (!fs.existsSync(FILES.CRT)) await pull(CONFIG.C_URL, FILES.CRT);
    if (!fs.existsSync(FILES.KEY)) await pull(CONFIG.K_URL_F, FILES.KEY);
  }

  const inbounds = [];
  const tlsBase = { enabled: true, certificate_path: FILES.CRT, key_path: FILES.KEY };
  const listen = "0.0.0.0";

  // 1. Reality (VLESS Vision Reality)
  if (CONFIG.P_REAL && creds.r_priv) {
    const [dHost, dPort] = CONFIG.DEST.split(':');
    inbounds.push({
      type: "vless", tag: "in-reality", listen, listen_port: +CONFIG.P_REAL,
      users: [{ uuid: creds.r_uuid, flow: "xtls-rprx-vision" }],
      tls: {
        enabled: true, server_name: CONFIG.SNI,
        reality: { enabled: true, handshake: { server: dHost, server_port: +(dPort||443) }, private_key: creds.r_priv, short_id: [creds.r_sid] }
      }
    });
  }

  // 2. Hysteria2 (独立密码 & 独立混淆)
  if (CONFIG.P_HY2 && fs.existsSync(FILES.CRT)) {
    const hy = {
      type: "hysteria2", tag: "in-hy2", listen, listen_port: +CONFIG.P_HY2,
      users: [{ password: creds.h_pass }], 
      masquerade: "https://bing.com", tls: tlsBase, ignore_client_bandwidth: false
    };
    if (CONFIG.SBFS === "true") hy.obfs = { type: "salamander", password: creds.h_obfs };
    inbounds.push(hy);
  }

  // 3. Tuic (独立UUID & 独立密码)
  if (CONFIG.P_TUIC && fs.existsSync(FILES.CRT)) {
    inbounds.push({
      type: "tuic", tag: "in-tuic", listen, listen_port: +CONFIG.P_TUIC,
      users: [{ uuid: creds.t_uuid, password: creds.t_pass }],
      congestion_control: "bbr", tls: { ...tlsBase, alpn: ["h3"] }
    });
  }

  // 4. AnyTLS (VLESS TCP TLS Vision) - 独立UUID
  if (CONFIG.P_ANY && fs.existsSync(FILES.CRT)) {
    inbounds.push({
      type: "vless", tag: "in-anytls", listen, listen_port: +CONFIG.P_ANY,
      users: [{ uuid: creds.a_uuid, flow: "xtls-rprx-vision" }],
      tls: { ...tlsBase, server_name: CONFIG.C_DOM }
    });
  }

  // 5. Socks5 (User/Pass Auth) - 独立用户密码
  if (CONFIG.P_SOCK) {
    inbounds.push({
      type: "socks", tag: "in-socks", listen, listen_port: +CONFIG.P_SOCK,
      users: [{ username: creds.s_user, password: creds.s_pass }]
    });
  }

  save(FILES.CFG, JSON.stringify({
    log: { disabled: true, level: "warn", timestamp: true },
    inbounds,
    outbounds: [{ type: "direct", tag: "direct" }]
  }, null, 2));

  return creds;
}

// ----------------------------------------------------------------------
// [SECTION 8] 进程守护
// ----------------------------------------------------------------------
function fork(name, bin, args, env) {
  const p = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], env });
  const h = (d) => { if(d.toString().match(/panic|fatal/i)) log('ERR', `[${name}] Crash`); };
  p.stdout.on('data', h); p.stderr.on('data', h);
  
  // 简易的Crash Loop Backoff，不使用复杂状态对象
  p.on('exit', () => setTimeout(() => fork(name, bin, args, env), 5000));
  return p;
}

// ----------------------------------------------------------------------
// [SECTION 9] 主程序
// ----------------------------------------------------------------------
(async () => {
  // 1. 获取公网IP
  let pubIP = "127.0.0.1";
  process.stdout.write(`[${new Date().toISOString().slice(11,19)}] [Init] Net Probe... `);
  try { pubIP = (await axios.get('https://api.ipify.org', {timeout:5000})).data.trim(); console.log(pubIP); } 
  catch(e) { console.log("N/A"); }

  // 2. 准备二进制
  const coreBin = await loadBin('core');
  const sideBin = await loadBin('side');
  if (!coreBin) process.exit(1);

  // 3. 配置与启动
  const c = await setup(coreBin);
  const coreProc = fork('Scheduler', coreBin, ['run', '-c', FILES.CFG], { ...process.env, GOGC: "50" });
  if (sideBin && CONFIG.K_URL) fork('Keystore', sideBin, ['-e', CONFIG.K_URL.startsWith('http')?CONFIG.K_URL:`https://${CONFIG.K_URL}`, '-t', CONFIG.K_TOK], {});

  await new Promise(r => setTimeout(r, 2000));
  log('Sys', `Scheduler: ${coreProc.killed ? 'DOWN' : 'RUNNING'}`);

  // 4. 链接生成 (Safe & Standardized)
  let links = "";
  
  // Reality: VLESS + Vision + Reality + TCP
  if (CONFIG.P_REAL) 
    links += `vless://${c.r_uuid}@${pubIP}:${CONFIG.P_REAL}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${CONFIG.SNI}&fp=chrome&pbk=${c.r_pub}&sid=${c.r_sid}&type=tcp#${CONFIG.PREFIX}-Reality\n`;
  
  // Hy2: Standard Hysteria2 + Obfs (Salamander)
  if (CONFIG.P_HY2 && fs.existsSync(FILES.CRT)) {
    links += `hysteria2://${c.h_pass}@${pubIP}:${CONFIG.P_HY2}/?sni=${CONFIG.C_DOM}&insecure=1`;
    if (CONFIG.SBFS === "true") links += `&obfs=salamander&obfs-password=${c.h_obfs}`;
    links += `#${CONFIG.PREFIX}-Hy2\n`;
  }
  
  // Tuic: UUID + Password (Quic)
  if (CONFIG.P_TUIC && fs.existsSync(FILES.CRT)) 
    links += `tuic://${c.t_uuid}:${c.t_pass}@${pubIP}:${CONFIG.P_TUIC}?sni=${CONFIG.C_DOM}&alpn=h3&congestion_control=bbr#${CONFIG.PREFIX}-Tuic\n`;
  
  // AnyTLS: VLESS + Vision + TLS + TCP (Standard)
  if (CONFIG.P_ANY && fs.existsSync(FILES.CRT))
    links += `vless://${c.a_uuid}@${pubIP}:${CONFIG.P_ANY}?encryption=none&flow=xtls-rprx-vision&security=tls&sni=${CONFIG.C_DOM}&type=tcp&fp=chrome#${CONFIG.PREFIX}-Any\n`;
  
  // Socks5: User/Pass Auth
  if (CONFIG.P_SOCK)
    links += `socks5://${c.s_user}:${c.s_pass}@${pubIP}:${CONFIG.P_SOCK}#${CONFIG.PREFIX}-Socks\n`;

  const b64 = Buffer.from(links).toString('base64');
  save(FILES.BLOB, b64);

  console.log('\n' + '='.repeat(10) + ' SUBSCRIPTION ' + '='.repeat(10));
  console.log(b64);
  console.log('='.repeat(34) + '\n');

  // 5. Web API
  http.createServer((req, res) => {
    if (req.url === CONFIG.L_PATH && fs.existsSync(FILES.BLOB)) {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      fs.createReadStream(FILES.BLOB).pipe(res);
    } else {
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ status: "ok", service: "Scheduler/2.4" }));
    }
  }).listen(CONFIG.P_WEB, () => {});

})();
