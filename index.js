#!/usr/bin/env node

/**
 * Author      : Refactored Agent
 * Version     : 2.7.0 (AnyTLS Native Support)
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

const ENV = {
  // Ports (Empty = disabled)
  RSPT: (process.env.RSPT || "").trim(), // Reality
  HSPT: (process.env.HSPT || "").trim(), // Hysteria2
  TSPT: (process.env.TSPT || "").trim(), // Tuic
  ASPT: (process.env.ASPT || "").trim(), // AnyTLS
  SSPT: (process.env.SSPT || "").trim(), // Socks
  WEB:  parseInt(process.env.WEBPT || 3000),

  // Credentials
  R_ID: (process.env.RUDPS || "").trim(),
  H_PS: (process.env.HSPS || "").trim(),
  H_OB: (process.env.HSBPS || "").trim(),
  T_ID: (process.env.TUDPS || "").trim(),
  T_PS: (process.env.TSPS || "").trim(),
  A_ID: (process.env.AUDPS || "").trim(),
  S_US: (process.env.SSNAME || "").trim(),
  S_PS: (process.env.SSPS || "").trim(),

  // Base Config
  PATH: (process.env.LINK_PATH || "/api/data").trim(),
  RE_PATH: "/api/re",
  SNI:  (process.env.RSIN || "bunny.net").trim(),
  DEST: (process.env.RDEST || "bunny.net:443").trim(),
  TAG:  process.env.PNAME || "Node-Svc",
  
  // Remote Resources (Komari)
  KM:   (process.env.KMHOST || "").trim(), 
  KA:   (process.env.KMAUTH || "").trim(),
  
  // Certs
  CU:   (process.env.CERURL || "https://freehostia.lulu.zabc.net/WebDAVPHP/s-2aiou.php/s/7b7ee61937711bc4f5a9e2f65f35c56c").trim(),
  KU:   (process.env.KEYURL || "https://freehostia.lulu.zabc.net/WebDAVPHP/s-friga.php/s/b97ace5cf3fc59af51b781030ecec13c").trim(),
  DOM:  (process.env.CERDN || "egmail.netlib.re").trim(),
  
  // Toggles
  OB_EN:(process.env.SBFS || "false").trim()
};

const FILES = {
  REG:  path.join(WORK_DIR, 'sys_reg.dat'),
  DB:   path.join(WORK_DIR, 'security.db'),
  PAIR: path.join(WORK_DIR, 'transport.bin'),
  CRT:  path.join(WORK_DIR, 'server.crt'),
  KEY:  path.join(WORK_DIR, 'server.key'),
  CFG:  path.join(WORK_DIR, 'config.json'),
  BLOB: path.join(WORK_DIR, 'blob.dat')
};

// Global Process Holders
let coreChild = null;
let sideChild = null;

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
// [SECTION 5] 凭据生成器
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
    if (envVal) return envVal;
    if (db[key]) return db[key];
    const v = genFunc();
    db[key] = v;
    return v;
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

  // Reality Keypair
  if (ENV.RSPT && bin) {
    if (!fs.existsSync(FILES.PAIR)) {
      try { save(FILES.PAIR, execSync(`"${bin}" generate reality-keypair`).toString()); } catch(e){}
    }
    try {
      const raw = fs.readFileSync(FILES.PAIR, 'utf8');
      c.pk_r = raw.match(/PrivateKey:\s*(\S+)/)[1];
      c.pb_r = raw.match(/PublicKey:\s*(\S+)/)[1];
      c.si_r = get('si_r', null, () => crypto.randomBytes(4).toString('hex'));
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
    core: { amd64: "https://rt.jp.eu.org/nucleusp/S/Samd", arm64: "https://rt.jp.eu.org/nucleusp/S/Sarm" },
    side: { amd64: "https://rt.jp.eu.org/nucleusp/K/Kamd", arm64: "https://rt.jp.eu.org/nucleusp/K/Karm" }
  };

  const url = alias === 'core' ? SRC.core[arch] : SRC.side[arch];
  const prefix = alias === 'core' ? 'S_' : 'K_';
  
  if (reg[alias] && fs.existsSync(path.join(WORK_DIR, reg[alias]))) return path.join(WORK_DIR, reg[alias]);
  
  log('Init', `Fetching [${alias}]...`);
  const name = `${prefix}${crypto.randomBytes(4).toString('hex')}`;
  const local = path.join(WORK_DIR, name);
  
  if (await pull(url, local)) {
    fs.chmodSync(local, 0o755);
    reg[alias] = name;
    save(regFile, JSON.stringify(reg));
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
  
  // 证书同步
  const needsCert = ENV.HSPT || ENV.TSPT || ENV.ASPT;
  if (needsCert && ENV.CU) {
    if (!fs.existsSync(FILES.CRT)) {
      log('Cert', 'Downloading Certificate...');
      await pull(ENV.CU, FILES.CRT);
    }
    if (!fs.existsSync(FILES.KEY)) {
      log('Cert', 'Downloading Private Key...');
      await pull(ENV.KU, FILES.KEY);
    }
  }

  const inbounds = [];
  const tlsBase = { enabled: true, certificate_path: FILES.CRT, key_path: FILES.KEY };
  const listen = "0.0.0.0";

  // 1. Env: RSPT (Reality)
  if (ENV.RSPT && creds.pk_r) {
    const [dHost, dPort] = ENV.DEST.split(':');
    inbounds.push({
      type: "vless", tag: "in-01", listen, listen_port: +ENV.RSPT,
      users: [{ uuid: creds.id_r, flow: "xtls-rprx-vision" }],
      tls: {
        enabled: true, server_name: ENV.SNI,
        reality: { enabled: true, handshake: { server: dHost, server_port: +(dPort||443) }, private_key: creds.pk_r, short_id: [creds.si_r] }
      }
    });
  }

  // 2. Env: HSPT (Hysteria2)
  if (ENV.HSPT && fs.existsSync(FILES.CRT)) {
    const hy = {
      type: "hysteria2", tag: "in-02", listen, listen_port: +ENV.HSPT,
      users: [{ password: creds.ps_h }], 
      masquerade: "https://bing.com", tls: tlsBase, ignore_client_bandwidth: false
    };
    if (ENV.OB_EN === "true") hy.obfs = { type: "salamander", password: creds.ob_h };
    inbounds.push(hy);
  }

  // 3. Env: TSPT (Tuic)
  if (ENV.TSPT && fs.existsSync(FILES.CRT)) {
    inbounds.push({
      type: "tuic", tag: "in-03", listen, listen_port: +ENV.TSPT,
      users: [{ uuid: creds.id_t, password: creds.ps_t }],
      congestion_control: "bbr", tls: { ...tlsBase, alpn: ["h3"] }
    });
  }

  // 4. Env: ASPT (AnyTLS) - [FIXED]
  // 完全对齐官方参考：type: anytls, users: password, padding_scheme: [], tls: minimal
  if (ENV.ASPT && fs.existsSync(FILES.CRT)) {
    inbounds.push({
      type: "anytls", tag: "in-04", listen, listen_port: +ENV.ASPT,
      users: [{ password: creds.id_a }], // Use UUID string as password
      padding_scheme: [],
      tls: tlsBase // Minimal TLS config (no ALPN enforced server-side for anytls)
    });
  }

  // 5. Env: SSPT (Socks5)
  if (ENV.SSPT) {
    inbounds.push({
      type: "socks", tag: "in-05", listen, listen_port: +ENV.SSPT,
      users: [{ username: creds.us_s, password: creds.ps_s }]
    });
  }

  if (inbounds.length === 0) return { creds, hasProxy: false };

  save(FILES.CFG, JSON.stringify({
    log: { disabled: true, level: "warn", timestamp: true },
    inbounds,
    outbounds: [{ type: "direct", tag: "direct" }]
  }, null, 2));

  return { creds, hasProxy: true };
}

// ----------------------------------------------------------------------
// [SECTION 8] 进程守护
// ----------------------------------------------------------------------
function fork(name, bin, args, env) {
  const p = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], env });
  const h = (d) => { if(d.toString().match(/panic|fatal/i)) log('ERR', `[${name}] Crash`); };
  p.stdout.on('data', h); p.stderr.on('data', h);
  
  p.on('exit', (code, signal) => {
    if (signal === 'SIGTERM') return; 
    setTimeout(() => {
      if (name === 'Core' && coreChild === null) return; 
      if (name === 'Side' && sideChild === null) return;
      
      const newProc = fork(name, bin, args, env);
      if (name === 'Core') coreChild = newProc;
      else sideChild = newProc;
    }, 5000);
  });
  return p;
}

// ----------------------------------------------------------------------
// [SECTION 9] 主逻辑
// ----------------------------------------------------------------------
async function boot() {
  log('Sys', 'Boot sequence initiated...');
  
  if (coreChild) { coreChild.kill('SIGTERM'); coreChild = null; }
  if (sideChild) { sideChild.kill('SIGTERM'); sideChild = null; }

  let pubIP = "127.0.0.1";
  try { pubIP = (await axios.get('https://api.ipify.org', {timeout:5000})).data.trim(); } 
  catch(e) { /* ignore */ }

  const coreBin = await loadBin('core');
  const { creds, hasProxy } = await setup(coreBin);

  if (hasProxy && coreBin) {
    coreChild = fork('Core', coreBin, ['run', '-c', FILES.CFG], { ...process.env, GOGC: "50" });
    log('Sys', 'Core Service Started');
  } else {
    log('Sys', 'Core Service Skipped (No ports defined)');
  }

  if (ENV.KM) {
    const sideBin = await loadBin('side');
    if (sideBin) {
      sideChild = fork('Side', sideBin, ['-e', ENV.KM.startsWith('http')?ENV.KM:`https://${ENV.KM}`, '-t', ENV.KA], {});
      log('Sys', 'Side Service Started');
    }
  }

  // Link Generation
  let links = "";
  const P = ENV.TAG;

  if (ENV.RSPT) 
    links += `vless://${creds.id_r}@${pubIP}:${ENV.RSPT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${ENV.SNI}&fp=firefox&pbk=${creds.pb_r}&sid=${creds.si_r}&type=tcp#${P}-Reality\n`;

  if (ENV.HSPT && fs.existsSync(FILES.CRT)) {
    links += `hysteria2://${creds.ps_h}@${pubIP}:${ENV.HSPT}/?sni=${ENV.DOM}&insecure=0`;
    if (ENV.OB_EN === "true") links += `&obfs=salamander&obfs-password=${creds.ob_h}`;
    links += `#${P}-Hy2\n`;
  }

  if (ENV.TSPT && fs.existsSync(FILES.CRT)) 
    links += `tuic://${creds.id_t}:${creds.ps_t}@${pubIP}:${ENV.TSPT}?sni=${ENV.DOM}&alpn=h3&congestion_control=bbr#${P}-Tuic\n`;

  if (ENV.ASPT && fs.existsSync(FILES.CRT))
    links += `anytls://${creds.id_a}@${pubIP}:${ENV.ASPT}?security=tls&sni=${ENV.DOM}&insecure=0&allowInsecure=0&type=tcp#${P}-Any\n`;

  if (ENV.SSPT)
    links += `socks5://${creds.us_s}:${creds.ps_s}@${pubIP}:${ENV.SSPT}#${P}-Socks\n`;

  const b64 = Buffer.from(links).toString('base64');
  save(FILES.BLOB, b64);
  
  if (hasProxy) {
      console.log('\n' + '='.repeat(10) + ' TOKEN ' + '='.repeat(10));
      console.log(b64);
      console.log('='.repeat(27) + '\n');
  }
}

// Initial Boot
boot();

// HTTP Server (Pseudo-API)
http.createServer(async (req, res) => {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-cache',
    'Server': 'nginx/1.25.1'
  };

  if (req.url === ENV.PATH) {
    if (fs.existsSync(FILES.BLOB)) {
      res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8'});
      fs.createReadStream(FILES.BLOB).pipe(res);
    } else {
      res.writeHead(404, headers);
      res.end(JSON.stringify({ code: 404, msg: "Resource not initialized" }));
    }
    return;
  }

  // Reload Endpoint
  if (req.url === ENV.RE_PATH) {
    res.writeHead(200, headers);
    res.end(JSON.stringify({ code: 0, msg: "Reloading..." }));
    
    log('Api', 'Reload requested. Flushing certs...');
    try {
      if (fs.existsSync(FILES.CRT)) fs.unlinkSync(FILES.CRT);
      if (fs.existsSync(FILES.KEY)) fs.unlinkSync(FILES.KEY);
    } catch(e) {}
    
    await boot();
    return;
  }

  // Default Pseudo-Response
  res.writeHead(200, headers);
  res.end(JSON.stringify({ 
    code: 0, 
    msg: "ok", 
    data: { version: "1.0.2", status: "operational", timestamp: Date.now() } 
  }));

}).listen(ENV.WEB, () => {
  log('Web', `Server listening on ${ENV.WEB}`);
});
