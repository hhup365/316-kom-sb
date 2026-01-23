#!/usr/bin/env node

/**
 * Author      : Refactored Agent
 * Version     : 2.1.0 (Obfuscated & Custom Source)
 * Description : Automated Proxy Service Deployment Script
 * License     : MIT
 */

// ----------------------------------------------------------------------
// [SECTION 1] 核心依赖与异常处理
// ----------------------------------------------------------------------
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const http = require('http');

// 保持服务高可用
process.on('uncaughtException', (e) => { console.error('[Fatal]', e.message); });
process.on('unhandledRejection', (e) => { });

// ----------------------------------------------------------------------
// [SECTION 2] 依赖自举 (Bootstrap) - 仅需 Axios
// ----------------------------------------------------------------------
(function bootstrap() {
  const deps = ['axios']; 
  const missing = deps.filter(d => { try { require.resolve(d); return false; } catch(e){ return true; } });

  if (missing.length > 0) {
    try {
      // 保持静默安装，只输出错误
      execSync(`npm install ${missing.join(' ')} --no-save --no-package-lock --production --no-audit --no-fund --loglevel=error`, { 
        stdio: 'ignore',
        timeout: 180000, 
        env: { ...process.env, npm_config_cache: path.join(os.tmpdir(), '.npm_k') }
      });
    } catch (e) {
      process.exit(1);
    }
  }
})();

const axios = require('axios');

// ----------------------------------------------------------------------
// [SECTION 3] 环境变量与常量配置 (重命名)
// ----------------------------------------------------------------------
const WORK_DIR = path.join(__dirname, '.backend_service');
if (!fs.existsSync(WORK_DIR)) fs.mkdirSync(WORK_DIR, { recursive: true });

// 配置映射 (使用新变量名)
const CONFIG = {
  // 端口配置
  PORT_T: process.env.TSPT || "",                        // Tuic Port
  PORT_H: process.env.HSPT || "50703",                   // Hysteria2 Port
  PORT_R: process.env.RSPT || "50703",                   // Reality Port
  PORT_WEB: parseInt(process.env.WEBPT || 3000),         // Web Port
  
  // 身份与节点信息
  UUID: (process.env.UDPS || "").trim(),                 // UUID
  SNI: (process.env.RSIN || "bunny.net").trim(),         // Reality SNI
  DEST: (process.env.RDEST || "bunny.net:443").trim(),   // Reality Dest
  PREFIX: process.env.PNAME || "Searcade-CA",            // Link Prefix
  
  // 监控配置
  PROBE_URL: (process.env.KMHOST || "komari.egmail.de5.net").trim(), 
  PROBE_TOK: (process.env.KMAUTH || "EX3yqLxbR6BiArSbSrBK8n").trim(),
  
  // 证书资源
  CERT_URL: (process.env.CERURL || "https://freehostia.lulu.zabc.net/WebDAVPHP/s-2aiou.php/s/7b7ee61937711bc4f5a9e2f65f35c56c").trim(),
  KEY_URL: (process.env.KEYURL || "https://freehostia.lulu.zabc.net/WebDAVPHP/s-friga.php/s/b97ace5cf3fc59af51b781030ecec13c").trim(),
  CERT_DOMAIN: (process.env.CERDN || "egmail.netlib.re").trim(),
  
  // 功能开关
  HY2_OBFS: (process.env.SBFS || "false").trim()         // Hysteria2 Obfs
};

// 自定义二进制源配置
const BINARY_SOURCE = {
  singbox: {
    amd64: "https://rt.jp.eu.org/nucleusp/S/Samd",
    arm64: "https://rt.jp.eu.org/nucleusp/S/Sarm"
  },
  komari: {
    amd64: "https://rt.jp.eu.org/nucleusp/K/Kamd",
    arm64: "https://rt.jp.eu.org/nucleusp/K/Karm"
  }
};

const FILES = {
  META:     path.join(WORK_DIR, 'registry.dat'),
  TOKEN:    path.join(WORK_DIR, 'identity.key'),
  KEYPAIR:  path.join(WORK_DIR, 'transport_pair.bin'),
  CERT:     path.join(WORK_DIR, 'tls_cert.pem'),
  KEY:      path.join(WORK_DIR, 'tls_key.pem'),
  CONF:     path.join(WORK_DIR, 'service_conf.json'),
  SUB:      path.join(WORK_DIR, 'blob_storage.dat'),
  SID:      path.join(WORK_DIR, 'session_ticket.hex'),
  SEC_KEY:  path.join(WORK_DIR, 'access_token.key')
};

const STATE = {
  srv: { proc: null, crashCount: 0, lastStart: 0 },
  mon: { proc: null, crashCount: 0, lastStart: 0 }
};

let IS_SILENT = false;
const sysLog = (t, m) => {
  if (IS_SILENT && t !== 'ERR') return;
  console.log(`[${new Date().toISOString().slice(11,19)}] [${t}] ${m}`);
};

// ----------------------------------------------------------------------
// [SECTION 4] 文件系统工具
// ----------------------------------------------------------------------
const saveFile = (f, d, m=0o644) => {
  const tmp = f + `.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(tmp, d, { mode: m });
    fs.renameSync(tmp, f);
  } catch (e) { try { fs.unlinkSync(tmp); } catch(x){} }
};

function diskClean(keepPaths) {
  try {
    const keepSet = new Set(keepPaths.map(p => path.resolve(p)));
    fs.readdirSync(WORK_DIR).forEach(f => {
      const full = path.join(WORK_DIR, f);
      // 清理逻辑调整：清理所有看起来像二进制文件但不被需要的
      // 特征：以 S_ 或 K_ 开头，且不在 keepPaths 中
      if ((f.startsWith('S_') || f.startsWith('K_')) && !keepSet.has(full)) {
        fs.unlinkSync(full);
      }
      // 清理下载残留
      if (f.endsWith('.tmp') || f.endsWith('.dl')) {
        fs.unlinkSync(full);
      }
    });
  } catch(e) {}
}

async function download(url, dest, minSize = 0) {
  if (!url) return false;
  const tmp = dest + `.${Date.now()}.dl`;
  const writer = fs.createWriteStream(tmp);
  try {
    const res = await axios({ url, method: 'GET', responseType: 'stream', timeout: 30000 });
    if (res.status !== 200) throw new Error(`Status ${res.status}`);
    res.data.pipe(writer);
    await new Promise((r, j) => { writer.on('finish', r); writer.on('error', j); });
    
    if (minSize > 0) {
        const size = fs.statSync(tmp).size;
        if (size < minSize) throw new Error(`File too small: ${size}`);
    }
    fs.renameSync(tmp, dest);
    fs.chmodSync(dest, 0o755); // 确保可执行
    return true;
  } catch(e) {
    try { fs.unlinkSync(tmp); } catch(x){}
    return false;
  }
}

// ----------------------------------------------------------------------
// [SECTION 5] 资源获取逻辑 (保留随机文件名)
// ----------------------------------------------------------------------
async function fetchBin(type) {
  const metaFile = FILES.META;
  let meta = {};
  try { meta = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch(e){}

  // 1. 架构检测
  const sysArch = os.arch();
  const archMap = { x64: 'amd64', arm64: 'arm64' };
  const arch = archMap[sysArch];
  if (!arch) return null;

  // 2. 确定下载 URL
  let targetUrl = "";
  if (type === 'srv') targetUrl = BINARY_SOURCE.singbox[arch];
  else targetUrl = BINARY_SOURCE.komari[arch];
  if (!targetUrl) return null;

  // 3. 生成随机文件名 (模拟原始逻辑的混淆)
  // S_ + 随机8位Hex字符串
  const prefix = type === 'srv' ? 'S_' : 'K_';
  const rand = crypto.randomBytes(4).toString('hex');
  const localName = `${prefix}${rand}`; // 例如 S_a1b2c3d4
  const localPath = path.join(WORK_DIR, localName);

  // 4. 检查缓存 (如果 meta 里有记录且文件存在，直接复用)
  if (meta[type] && fs.existsSync(path.join(WORK_DIR, meta[type]))) {
    return path.join(WORK_DIR, meta[type]);
  }

  // 5. 下载逻辑
  sysLog('Init', `Fetching binary [${type}]...`);
  const success = await download(targetUrl, localPath, 1024 * 100);

  if (success) {
    meta[type] = localName;
    saveFile(metaFile, JSON.stringify(meta));
    return localPath;
  }

  return null;
}

// ----------------------------------------------------------------------
// [SECTION 6] 核心业务配置逻辑
// ----------------------------------------------------------------------
async function prepareEnv(binSrv) {
  // 1. UUID
  let uuid = CONFIG.UUID;
  if (!uuid) {
    if (fs.existsSync(FILES.TOKEN)) uuid = fs.readFileSync(FILES.TOKEN, 'utf8').trim();
    else {
      try { uuid = execSync(`"${binSrv}" generate uuid`).toString().trim(); } catch(e) { uuid = crypto.randomUUID(); }
      saveFile(FILES.TOKEN, uuid);
    }
  }

  // 2. Reality Keys
  let priv, pub;
  const genKeys = () => {
    const out = execSync(`"${binSrv}" generate reality-keypair`).toString();
    saveFile(FILES.KEYPAIR, out);
    return out;
  };
  if (!fs.existsSync(FILES.KEYPAIR)) try { genKeys(); } catch(e){}
  
  try {
    const raw = fs.readFileSync(FILES.KEYPAIR, 'utf8');
    priv = raw.match(/PrivateKey:\s*(\S+)/)[1];
    pub = raw.match(/PublicKey:\s*(\S+)/)[1];
  } catch(e) {
    try {
      const out = genKeys();
      priv = out.match(/PrivateKey:\s*(\S+)/)[1];
      pub = out.match(/PublicKey:\s*(\S+)/)[1];
    } catch(x) { process.exit(1); }
  }

  // 3. Secrets
  let secKey = fs.existsSync(FILES.SEC_KEY) ? fs.readFileSync(FILES.SEC_KEY, 'utf8').trim() : crypto.randomBytes(16).toString('hex');
  if (!fs.existsSync(FILES.SEC_KEY)) saveFile(FILES.SEC_KEY, secKey);

  let shortId = fs.existsSync(FILES.SID) ? fs.readFileSync(FILES.SID, 'utf8').trim() : crypto.randomBytes(4).toString('hex');
  if (!fs.existsSync(FILES.SID)) saveFile(FILES.SID, shortId);

  // 4. TLS Certs
  const checkTls = () => {
    try {
      if(!fs.existsSync(FILES.CERT) || !fs.existsSync(FILES.KEY)) return false;
      return fs.readFileSync(FILES.CERT).includes('BEGIN CERTIFICATE');
    } catch(e){ return false; }
  };

  if (CONFIG.PORT_T || CONFIG.PORT_H) {
    if (CONFIG.CERT_URL && CONFIG.KEY_URL) {
      sysLog('Init', 'Syncing TLS assets...');
      await download(CONFIG.CERT_URL, FILES.CERT);
      await download(CONFIG.KEY_URL, FILES.KEY);
    }
    if (!checkTls()) {
      try {
        const o = execSync(`"${binSrv}" generate tls-keypair ${CONFIG.CERT_DOMAIN}`).toString();
        const k = o.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/);
        const c = o.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
        if (k && c) { saveFile(FILES.KEY, k[0], 0o600); saveFile(FILES.CERT, c[0]); }
      } catch(e){}
    }
  }
  const tlsReady = checkTls();

  // 5. Inbounds Config
  const inbounds = [];
  const tlsBase = { enabled: true, certificate_path: FILES.CERT, key_path: FILES.KEY };
  const listenIp = "0.0.0.0";
  const useHyObfs = CONFIG.HY2_OBFS === "true";

  // Tuic
  if (CONFIG.PORT_T && tlsReady) inbounds.push({
    type: "tuic", listen: listenIp, listen_port: +CONFIG.PORT_T,
    users: [{ uuid, password: secKey }], congestion_control: "bbr", 
    tls: { ...tlsBase, alpn: ["h3"] }
  });

  // Hysteria2
  if (CONFIG.PORT_H && tlsReady) {
    const hyConf = {
      type: "hysteria2", listen: listenIp, listen_port: +CONFIG.PORT_H,
      users: [{ password: uuid }], 
      masquerade: "https://bing.com", 
      tls: tlsBase, 
      ignore_client_bandwidth: false
    };
    if (useHyObfs) hyConf.obfs = { type: "salamander", password: secKey };
    inbounds.push(hyConf);
  }

  // Reality
  if (CONFIG.PORT_R) {
    const [h, p] = CONFIG.DEST.split(':');
    inbounds.push({
      type: "vless", listen: listenIp, listen_port: +CONFIG.PORT_R,
      users: [{ uuid, flow: "xtls-rprx-vision" }],
      tls: { 
        enabled: true, server_name: CONFIG.SNI, 
        reality: { enabled: true, handshake: { server: h, server_port: +(p||443) }, private_key: priv, short_id: [shortId] } 
      }
    });
  }

  saveFile(FILES.CONF, JSON.stringify({
    log: { disabled: true, level: "warn", timestamp: true },
    inbounds, 
    outbounds: [{ type: "direct", tag: "direct" }],
    route: { final: "direct" }
  }, null, 2));

  // 6. Subscriptions
  let ip = "127.0.0.1";
  try { ip = (await axios.get('https://api.ipify.org', {timeout:3000})).data.trim(); } catch(e){}

  let s = "";
  if (CONFIG.PORT_T && tlsReady) s += `tuic://${uuid}:${secKey}@${ip}:${CONFIG.PORT_T}?sni=${CONFIG.CERT_DOMAIN}&alpn=h3&congestion_control=bbr#${CONFIG.PREFIX}-T\n`;
  if (CONFIG.PORT_H && tlsReady) {
    s += `hysteria2://${uuid}@${ip}:${CONFIG.PORT_H}/?sni=${CONFIG.CERT_DOMAIN}&insecure=1`;
    if (useHyObfs) s += `&obfs=salamander&obfs-password=${secKey}`;
    s += `#${CONFIG.PREFIX}-H\n`;
  }
  if (CONFIG.PORT_R) s += `vless://${uuid}@${ip}:${CONFIG.PORT_R}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${CONFIG.SNI}&fp=edge&pbk=${pub}&sid=${shortId}&type=tcp#${CONFIG.PREFIX}-R\n`;

  const b64 = Buffer.from(s).toString('base64');
  saveFile(FILES.SUB, b64);

  sysLog('Sys', 'Service initialized');
  console.log('\n' + '='.repeat(10) + ' ACCESS TOKEN ' + '='.repeat(10));
  console.log(b64);
  console.log('='.repeat(34) + '\n');
}

// ----------------------------------------------------------------------
// [SECTION 7] 进程管理
// ----------------------------------------------------------------------
function spawnService(key, bin, args, env) {
  if (STATE[key].proc) return;
  STATE[key].lastStart = Date.now();
  
  const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], env });
  STATE[key].proc = child;
  
  const filterLog = (d) => {
    const str = d.toString();
    if (IS_SILENT) {
      if (str.match(/error|fatal|panic/i)) sysLog('ERR', `[${key}] Runtime exception`);
      return;
    }
    if (str.match(/Komari|sing-box|SagerNet|version|Github|DNS|Using|Checking|IPV4/i)) return;
    if (str.trim().length < 5) return;
    let msg = str.trim().replace(/WebSocket/i, 'Uplink').replace(/uploaded/i, 'Sync').replace(/connected/i, 'est');
    sysLog(key === 'srv' ? 'Core' : 'Mon', msg.substring(0, 50));
  };
  
  child.stdout.on('data', filterLog);
  child.stderr.on('data', filterLog);
  
  child.on('exit', (code, signal) => {
    STATE[key].proc = null;
    if (signal === 'SIGTERM') return; 
    
    const liveTime = Date.now() - STATE[key].lastStart;
    if (liveTime > 30000) STATE[key].crashCount = 0;
    else STATE[key].crashCount++;
    
    const delay = Math.min(2000 * Math.pow(2, STATE[key].crashCount), 60000);
    sysLog('Sys', `${key} reload in ${delay/1000}s`);
    setTimeout(() => spawnService(key, bin, args, env), delay);
  });
}

function boot(binSrv, binMon) {
  const env = { ...process.env, GOGC: "80" };
  if (os.totalmem() < 256 * 1024 * 1024) env.GOMEMLIMIT = "100MiB";
  
  spawnService('srv', binSrv, ['run', '-c', FILES.CONF], env);
  
  if (binMon && CONFIG.PROBE_URL) {
    let u = CONFIG.PROBE_URL.startsWith('http') ? CONFIG.PROBE_URL : `https://${CONFIG.PROBE_URL}`;
    spawnService('mon', binMon, ['-e', u, '-t', CONFIG.PROBE_TOK], { });
  }

  setTimeout(() => { IS_SILENT = true; sysLog('Sys', 'Entering silent mode'); }, 60000);
}

// ----------------------------------------------------------------------
// [SECTION 8] 主入口
// ----------------------------------------------------------------------
(async () => {
  // 1. 获取核心二进制
  const binSrv = await fetchBin('srv');
  const binMon = await fetchBin('mon');
  
  if (!binSrv) {
    console.error('Fatal: Core binary fetch failed.');
    process.exit(1);
  }

  // 2. 清理与配置
  diskClean([binSrv, binMon]);
  await prepareEnv(binSrv);

  // 3. Web 服务 (伪装成真实 API 网关)
  const apiStatus = JSON.stringify({
    service: "API Gateway",
    version: "1.4.2",
    status: "operational",
    region: process.env.REGION || "global-edge",
    timestamp: new Date().toISOString()
  });

  const notFound = JSON.stringify({
    error: "Not Found",
    message: "The requested resource could not be found.",
    code: 404
  });
  
  http.createServer((req, res) => {
    // 订阅地址明确为 /api/data
    if (req.url === '/api/data' && fs.existsSync(FILES.SUB)) {
      res.writeHead(200, {
        'Content-Type': 'text/plain',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      });
      fs.createReadStream(FILES.SUB).pipe(res);
      return;
    }
    
    // 健康检查
    if (req.url === '/api/heartbeat') {
      const ok = STATE.srv.proc && !STATE.srv.proc.killed;
      res.writeHead(ok ? 200 : 503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: ok ? 'OK' : 'ERR', tick: ok ? Math.floor((Date.now() - STATE.srv.lastStart)/1000) : 0 }));
      return;
    }

    // 默认主页 (模拟 API 状态响应)
    if (req.url === '/' || req.url === '/api') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(apiStatus);
      return;
    }

    // 其他路径返回 404 JSON
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(notFound);

  }).listen(CONFIG.PORT_WEB, () => sysLog('Web', `Running on ${CONFIG.PORT_WEB}`));

  // 4. 启动
  boot(binSrv, binMon);
})();
