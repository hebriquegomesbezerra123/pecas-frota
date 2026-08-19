// ============================================================
//  Vigia do Bolsão Peças (local, rede da empresa)
//  - Sobe o servidor (porta 3200) e RELIGA sozinho se cair
//  - Sobe o TÚNEL público (Cloudflare) e RELIGA sozinho se cair
//  - Faz BACKUP automático do catálogo em D: e no OneDrive
//  Roda sozinho no boot (atalho na pasta Inicializar).
// ============================================================
const { spawn } = require('child_process');
const net  = require('net');
const fs   = require('fs');
const path = require('path');

const APP_DIR   = __dirname;                                   // Y:\Lucas\Oficina\pecas-api
const DATA_DIR  = 'Y:\\Lucas\\Oficina\\pecas-local-data';
const CATALOG   = path.join(DATA_DIR, 'catalog.json');
const PORT      = 3200;
const ENV = Object.assign({}, process.env, {
  PORT: String(PORT),
  DATA_DIR: DATA_DIR,
  PECAS_SENHA: '20519703',
});

// Lugares de backup (disco separado + nuvem). Criados se não existirem.
const BACKUP_DIRS = [
  'D:\\Backup_Bolsao_Pecas',
  path.join(process.env.OneDrive || 'C:\\Users\\Dell\\OneDrive', 'Backup_Bolsao_Pecas'),
];

// ── Túnel público (Cloudflare quick tunnel — grátis, sem conta) ──
const CLOUDFLARED = 'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe';
// Guardado em DOIS lugares: C: (sempre acessível, mesmo se Y: falhar) e na pasta de dados.
const URL_FILE_C  = 'C:\\BolsaoPecas\\tunnel_url.txt';
const URL_FILE_Y  = path.join(DATA_DIR, 'tunnel_url.txt');

let serverProc = null;
let tunnelProc = null;
let ultimosReinicios = [];       // timestamps do servidor (anti-loop)
let ultimosReiniciosTunel = [];  // timestamps do túnel (anti-loop)

function log(msg) {
  const ts = new Date().toLocaleString('pt-BR');
  console.log(`[${ts}] ${msg}`);
}

// ── espera a unidade Y: ficar disponível (no boot pode demorar) ──
function esperarDrive(cb) {
  if (fs.existsSync(APP_DIR) && fs.existsSync(DATA_DIR)) return cb();
  log('Aguardando a unidade Y: / pasta de dados ficar disponível...');
  const t = setInterval(() => {
    if (fs.existsSync(APP_DIR) && fs.existsSync(DATA_DIR)) { clearInterval(t); cb(); }
  }, 3000);
}

// ── porta ativa? ──
function portaAtiva() {
  return new Promise(resolve => {
    const s = net.createConnection({ port: PORT, host: '127.0.0.1' });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error',   () => { resolve(false); });
    setTimeout(() => { try { s.destroy(); } catch (_) {} resolve(false); }, 2500);
  });
}

// ── sobe o servidor ──
function iniciarServidor() {
  const agora = Date.now();
  ultimosReinicios = ultimosReinicios.filter(t => agora - t < 60000);
  if (ultimosReinicios.length >= 3) {
    log('⚠️ Muitos reinícios em 1 min — aguardando 60s antes de tentar de novo (evita loop).');
    return setTimeout(iniciarServidor, 60000);
  }
  ultimosReinicios.push(agora);

  log('▶️  Iniciando servidor Peças (porta ' + PORT + ')...');
  serverProc = spawn('node', ['server.js'], { cwd: APP_DIR, env: ENV, windowsHide: true });
  serverProc.stdout.on('data', d => process.stdout.write('[pecas] ' + d));
  serverProc.stderr.on('data', d => process.stderr.write('[pecas ERRO] ' + d));
  serverProc.on('exit', code => {
    log('⛔ Servidor caiu (código ' + code + '). Religando em 3s...');
    serverProc = null;
    setTimeout(iniciarServidor, 3000);
  });
}

// ── grava a URL pública atual (2 lugares, pra sempre achar) ──
function gravarUrlTunel(url) {
  try {
    if (!fs.existsSync('C:\\BolsaoPecas')) fs.mkdirSync('C:\\BolsaoPecas', { recursive: true });
    fs.writeFileSync(URL_FILE_C, url, 'utf-8');
  } catch (e) { log('não consegui gravar URL em C: ' + e.message); }
  try { fs.writeFileSync(URL_FILE_Y, url, 'utf-8'); } catch (e) { /* Y: pode estar indisponível, tudo bem */ }
  log('🌐 Link público atual: ' + url);
}

// ── sobe o túnel público (Cloudflare quick tunnel) ──
function iniciarTunel() {
  const agora = Date.now();
  ultimosReiniciosTunel = ultimosReiniciosTunel.filter(t => agora - t < 120000);
  if (ultimosReiniciosTunel.length >= 4) {
    log('⚠️ Túnel caindo demais — aguardando 2min antes de tentar de novo (evita loop).');
    return setTimeout(iniciarTunel, 120000);
  }
  ultimosReiniciosTunel.push(agora);

  if (!fs.existsSync(CLOUDFLARED)) {
    log('⚠️ cloudflared.exe não encontrado em ' + CLOUDFLARED + ' — túnel público desativado.');
    return;
  }

  log('▶️  Iniciando túnel público (Cloudflare)...');
  tunnelProc = spawn(CLOUDFLARED, ['tunnel', '--url', 'http://localhost:' + PORT, '--no-autoupdate'],
    { windowsHide: true });

  const bufferizar = d => {
    const texto = d.toString();
    process.stdout.write('[tunel] ' + texto);
    // a URL aparece numa linha tipo: https://palavra-aleatoria.trycloudflare.com
    const m = texto.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
    if (m) gravarUrlTunel(m[0]);
  };
  tunnelProc.stdout.on('data', bufferizar);
  tunnelProc.stderr.on('data', bufferizar);   // cloudflared loga tudo no stderr por padrão

  tunnelProc.on('exit', code => {
    log('⛔ Túnel caiu (código ' + code + '). Religando em 5s...');
    tunnelProc = null;
    setTimeout(iniciarTunel, 5000);
  });
}

// ── vigia: a cada 30s confere se está no ar ──
async function vigiar() {
  const ok = await portaAtiva();
  if (!ok && serverProc === null) {
    log('🔁 Vigia detectou servidor fora do ar. Religando...');
    iniciarServidor();
  }
  if (tunnelProc === null) {
    log('🔁 Vigia detectou túnel fora do ar. Religando...');
    iniciarTunel();
  }
}

// ── backup do catálogo ──
function fazerBackup(motivo) {
  try {
    if (!fs.existsSync(CATALOG)) return;
    const dados = fs.readFileSync(CATALOG);
    const hoje = new Date();
    const dia = hoje.getFullYear() + '-' +
      String(hoje.getMonth() + 1).padStart(2, '0') + '-' +
      String(hoje.getDate()).padStart(2, '0');
    for (const dir of BACKUP_DIRS) {
      try {
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        // cópia sempre-atual + snapshot do dia
        fs.writeFileSync(path.join(dir, 'catalog_atual.json'), dados);
        fs.writeFileSync(path.join(dir, 'catalog_' + dia + '.json'), dados);
        // mantém só os últimos 30 snapshots diários
        const snaps = fs.readdirSync(dir)
          .filter(f => /^catalog_\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort();
        while (snaps.length > 30) {
          try { fs.unlinkSync(path.join(dir, snaps.shift())); } catch (_) {}
        }
      } catch (e) { log('backup falhou em ' + dir + ': ' + e.message); }
    }
    log('💾 Backup do catálogo feito (' + motivo + ').');
  } catch (e) { log('backup erro geral: ' + e.message); }
}

// ── início ──
// Guarda anti-duplicata: se a porta já está no ar, outro vigia/gerenciador já cuida disso.
// Evita dois servidores brigando pela porta 3200 (ex.: boot + botão do Painel ao mesmo tempo).
esperarDrive(async () => {
  if (await portaAtiva()) {
    log('ℹ️ O sistema de Peças já está no ar (porta ' + PORT + '). Este vigia não é necessário — saindo.');
    process.exit(0);
  }
  log('=== Vigia Bolsão Peças iniciado ===');
  iniciarServidor();
  iniciarTunel();
  fazerBackup('início');
  setInterval(vigiar, 30000);            // confere de pé a cada 30s
  setInterval(() => fazerBackup('horário'), 60 * 60 * 1000);  // backup de hora em hora
});
