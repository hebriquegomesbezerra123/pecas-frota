require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');
const https   = require('https');
const crypto  = require('crypto');
const multer  = require('multer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Persistência (volume Railway em produção, repo local em dev) ──────────────
// DATA_DIR aponta para um volume persistente (ex: /data). Sem ele, usa o próprio dir.
const DATA_DIR     = process.env.DATA_DIR || __dirname;
const CATALOG_PATH = path.join(DATA_DIR, 'catalog.json');
const fotosDir     = path.join(DATA_DIR, 'fotos');

// Seed inicial: copia catálogo e fotos empacotados para o volume vazio (1º boot)
(function seedVolume() {
  if (DATA_DIR === __dirname) return;
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const bundledCatalog = path.join(__dirname, 'catalog.json');
  if (!fs.existsSync(CATALOG_PATH) && fs.existsSync(bundledCatalog)) {
    fs.copyFileSync(bundledCatalog, CATALOG_PATH);
  }
  const bundledFotos = path.join(__dirname, 'public', 'fotos');
  if (!fs.existsSync(fotosDir)) {
    fs.mkdirSync(fotosDir, { recursive: true });
    if (fs.existsSync(bundledFotos)) {
      for (const f of fs.readdirSync(bundledFotos)) {
        try { fs.copyFileSync(path.join(bundledFotos, f), path.join(fotosDir, f)); } catch (_) {}
      }
    }
  }
})();

// ─── Multer (upload de fotos) ─────────────────────────────────────────────────
if (!fs.existsSync(fotosDir)) fs.mkdirSync(fotosDir, { recursive: true });

const storage = multer.diskStorage({
  destination: fotosDir,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    cb(null, Date.now() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 15 * 1024 * 1024 } });

// ─── Helpers ──────────────────────────────────────────────────────────────────
function loadCatalog() {
  return JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf-8'));
}
function saveCatalog(catalog) {
  if (fs.existsSync(CATALOG_PATH)) {
    try { fs.copyFileSync(CATALOG_PATH, CATALOG_PATH + '.bak'); } catch(_) {}
  }
  const _tmp = CATALOG_PATH + '.tmp';
  fs.writeFileSync(_tmp, JSON.stringify(catalog, null, 2), 'utf-8');
  fs.renameSync(_tmp, CATALOG_PATH);
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.end();
  });
}

function httpsPost(url, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const u = new URL(url);
    const options = {
      hostname: u.hostname, path: u.pathname + u.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Autenticação / SSO ───────────────────────────────────────────────────────
const PORTAL_SECRET = process.env.PORTAL_SECRET || 'bolsao-sso-secret-2025';
const PECAS_SENHA   = process.env.PECAS_SENHA   || 'pecas2026';
const PORTAL_URL    = process.env.PORTAL_URL    || 'http://localhost:5000';

function _hmac40(secret, msg) {
  return crypto.createHmac('sha256', secret).update(msg).digest('hex').slice(0, 40);
}

// Valida token SSO gerado pelo portal (mesmo formato dos apps Flask)
function validarTokenSSO(token, appId, maxAge = 90) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf-8');
    const [ts, tid, sig] = decoded.split(':');
    if (tid !== appId) return false;
    if (Date.now() / 1000 - parseInt(ts) > maxAge) return false;
    const expected = _hmac40(PORTAL_SECRET, `${ts}:${tid}`);
    return sig.length === expected.length &&
           crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch (_) { return false; }
}

// Cookie de sessão assinado (validade 8h) — formato: ts.profileId.sig
function gerarAuthCookie(profileId) {
  const ts  = String(Math.floor(Date.now() / 1000));
  const sig = _hmac40(PORTAL_SECRET, `${ts}:${profileId}`);
  return `${ts}.${profileId}.${sig}`;
}
// Retorna profileId (string truthy) quando válido, ou null
function validarAuthCookie(val) {
  if (!val) return null;
  const parts = val.split('.');
  // Novo formato: ts.profileId.sig
  if (parts.length === 3) {
    const [ts, profileId, sig] = parts;
    if (Date.now() / 1000 - parseInt(ts) > 8 * 3600) return null;
    const expected = _hmac40(PORTAL_SECRET, `${ts}:${profileId}`);
    try {
      if (sig.length !== expected.length) return null;
      if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
      return profileId;
    } catch (_) { return null; }
  }
  // Legado: ts.sig — retrocompatibilidade (trata como admin)
  if (parts.length === 2) {
    const [ts, sig] = parts;
    if (Date.now() / 1000 - parseInt(ts) > 8 * 3600) return null;
    const expected = _hmac40(PORTAL_SECRET, ts);
    try {
      if (sig.length !== expected.length) return null;
      if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
      return '_legacy_admin';
    } catch (_) { return null; }
  }
  return null;
}
function getPerfilFromReq(req) {
  const profileId = validarAuthCookie(getCookie(req, 'pecas_auth'));
  if (!profileId) return null;
  const catalog = loadCatalog();
  const perfis  = catalog.perfis || [];
  if (!perfis.length || profileId === '_legacy_admin') {
    const admin = perfis.find(p => p.papel === 'admin' && p.ativo);
    return admin ? { id: admin.id, nome: admin.nome, papel: admin.papel }
                 : { id: '_admin', nome: 'Administrador', papel: 'admin' };
  }
  const p = perfis.find(p => p.id === profileId);
  return (p && p.ativo) ? { id: p.id, nome: p.nome, papel: normalizarPapel(p.papel) } : null;
}
function ensureAdmin(req, res, next) {
  const p = getPerfilFromReq(req);
  if (!p || p.papel !== 'admin')
    return res.status(403).json({ error: 'Permissão negada. Apenas administradores.' });
  next();
}
// Papéis reconhecidos. 'operador' é tratado como 'operacao' (retrocompat).
const PAPEIS_VALIDOS = ['admin', 'operacao', 'viewer'];
function normalizarPapel(papel) {
  if (papel === 'operador') return 'operacao';
  return papel;
}
// operacao OU admin podem registrar solicitações (baixa/entrada)
function ensureOperacao(req, res, next) {
  const p = getPerfilFromReq(req);
  const papel = p && normalizarPapel(p.papel);
  if (!p || (papel !== 'admin' && papel !== 'operacao'))
    return res.status(403).json({ error: 'Permissão negada. Apenas operação ou administrador.' });
  next();
}

// ─── Fila serializada de escrita de estoque ─────────────────────────────────────
// Toda alteração de saldo passa por aqui, UMA de cada vez. Garante que duas
// aprovações simultâneas não gerem saldo negativo nem gravação perdida no JSON.
let _writeChain = Promise.resolve();
function serializarEscrita(fn) {
  const run = _writeChain.then(fn, fn);
  // mantém a corrente viva mesmo se fn rejeitar
  _writeChain = run.then(() => {}, () => {});
  return run;
}
// Aplica uma movimentação de estoque (entrada soma, saida subtrai) e registra o
// histórico imutável em movimentacoes_estoque. NÃO valida permissão (quem chama valida).
// custo_unitario: entrada com custo atualiza o custo corrente da peça; saída sem custo
// é valorizada pelo último custo conhecido (custo_unitario da peça, senão preco_referencia).
function aplicarMovimentacao(catalog, { peca_id, tipo, quantidade, solicitacao_id, usuario_id, custo_unitario, placa, responsavel, observacoes }) {
  const idx = catalog.pecas.findIndex(p => p.id === peca_id);
  if (idx === -1) throw new Error('Peça não encontrada');
  const peca = catalog.pecas[idx];
  const saldoAnterior = peca.quantidade || 0;
  const delta = tipo === 'entrada' ? quantidade : -quantidade;
  const saldoNovo = saldoAnterior + delta;
  if (saldoNovo < 0) throw new Error(`Estoque insuficiente. Disponível: ${saldoAnterior}`);
  peca.quantidade = saldoNovo;
  let custo = custo_unitario != null && custo_unitario !== '' ? Number(custo_unitario) : null;
  if (custo == null || isNaN(custo)) {
    custo = peca.custo_unitario != null ? Number(peca.custo_unitario)
          : (peca.preco_referencia != null ? Number(peca.preco_referencia) : null);
  }
  if (tipo === 'entrada' && custo_unitario != null && custo_unitario !== '' && !isNaN(Number(custo_unitario))) {
    peca.custo_unitario = Number(custo_unitario);
  }
  if (!catalog.movimentacoes_estoque) catalog.movimentacoes_estoque = [];
  const mov = {
    id: 'ME' + String(catalog.movimentacoes_estoque.length + 1).padStart(4, '0'),
    peca_id, peca_nome: peca.nome, tipo, quantidade,
    custo_unitario: custo,
    valor_total: custo != null ? Math.round(custo * quantidade * 100) / 100 : null,
    placa: placa || null, responsavel: responsavel || null, observacoes: observacoes || null,
    saldo_anterior: saldoAnterior, saldo_novo: saldoNovo,
    solicitacao_id: solicitacao_id || null, usuario_id: usuario_id || null,
    criado_em: new Date().toISOString()
  };
  catalog.movimentacoes_estoque.push(mov);
  return { mov, saldoNovo };
}

// Visão unificada do histórico: registros antigos (movimentacoes, só baixas manuais)
// + livro-razão V3 (movimentacoes_estoque). Ordenado do mais antigo ao mais novo.
function todasMovimentacoes(catalog) {
  const sols = {};
  (catalog.solicitacoes || []).forEach(s => { sols[s.id] = s; });
  const perfis = {};
  (catalog.perfis || []).forEach(p => { perfis[p.id] = p.nome; });
  const legacy = (catalog.movimentacoes || []).map(m => ({
    id: m.id, origem: 'registro antigo', tipo: 'saida',
    peca_id: m.peca_id, peca_nome: m.peca_nome, peca_codigo: m.peca_codigo || '',
    responsavel: m.responsavel || '', veiculo: m.veiculo || '',
    quantidade: m.quantidade, custo_unitario: null, valor_total: null,
    aprovado_por: '', observacoes: m.observacoes || '',
    data: m.data, criado_em: m.criado_em || ((m.data || '') + 'T12:00:00.000Z'),
    editavel: false, editada: false, edicoes: []
  }));
  const razao = (catalog.movimentacoes_estoque || []).map(m => {
    const s = m.solicitacao_id ? sols[m.solicitacao_id] : null;
    return {
      id: m.id, origem: m.solicitacao_id ? 'autorizada' : 'direta',
      tipo: m.tipo === 'entrada' ? 'entrada' : 'saida',
      peca_id: m.peca_id, peca_nome: m.peca_nome, peca_codigo: (s && s.peca_codigo) || '',
      responsavel: m.responsavel || (s && s.solicitante_nome) || perfis[m.usuario_id] || '',
      veiculo: m.placa || (s && s.placa) || '',
      quantidade: m.quantidade,
      custo_unitario: m.custo_unitario != null ? m.custo_unitario : null,
      valor_total: m.valor_total != null ? m.valor_total : null,
      aprovado_por: perfis[m.usuario_id] || '',
      observacoes: m.observacoes || (s && s.observacao) || '',
      data: (m.criado_em || '').substring(0, 10), criado_em: m.criado_em,
      editavel: true,                       // só o livro-razão pode ser corrigido
      editada: !!m.editada,
      edicoes: m.edicoes || []
    };
  });
  return legacy.concat(razao).sort((a, b) => (a.criado_em || '').localeCompare(b.criado_em || ''));
}
function seedPerfis() {
  const catalog = loadCatalog();
  if (!catalog.perfis) catalog.perfis = [];
  // Garante que o perfil admin padrão sempre existe (upsert, não apaga outros)
  if (!catalog.perfis.find(p => p.id === 'prf001')) {
    catalog.perfis.unshift({
      id: 'prf001', nome: 'Administrador', papel: 'admin',
      senha: hashPassword(PECAS_SENHA), ativo: true, criado_em: new Date().toISOString()
    });
    saveCatalog(catalog);
    console.log('✅ Perfil administrador (re)criado com a senha padrão (PECAS_SENHA)');
  }
}
function getCookie(req, nome) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + nome + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

// Rate limiting (login)
const _loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now(), win = 5 * 60 * 1000, max = 10;
  const e = _loginAttempts.get(ip);
  if (!e || now - e.firstAt > win) { _loginAttempts.set(ip, { count: 1, firstAt: now }); return true; }
  if (e.count >= max) return false;
  e.count++; return true;
}
function resetRateLimit(ip) { _loginAttempts.delete(ip); }

// Hash de senhas (SHA-256 + salt)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return 'sha256:' + salt + ':' + hash;
}
function verifyPassword(password, stored) {
  if ((stored || '').startsWith('sha256:')) {
    const parts = stored.split(':');
    if (parts.length < 3) return false;
    const salt = parts[1], hash = parts[2];
    const expected = crypto.createHmac('sha256', salt).update(password).digest('hex');
    try {
      if (hash.length !== expected.length) return false;
      return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expected));
    } catch (_) { return false; }
  }
  // legado plain-text
  try {
    const pb = Buffer.from(password || ''), sb = Buffer.from(stored || '');
    return pb.length === sb.length && crypto.timingSafeEqual(pb, sb);
  } catch (_) { return false; }
}

// ─── Kill-switch: o portal pode desligar este sistema ──────────────────────────
const PORTAL_URL_KS = process.env.PORTAL_URL || 'https://web-production-3e595.up.railway.app';
let _ksCache = { ts: 0, ativo: true };
async function sistemaAtivo() {
  const agora = Date.now();
  if (agora - _ksCache.ts < 30000) return _ksCache.ativo;
  try {
    const data = await httpsGet(`${PORTAL_URL_KS}/api/app-status/pecas`);
    _ksCache.ativo = !(data && data.ativo === false);
  } catch (_) { _ksCache.ativo = true; }   // fail-open
  _ksCache.ts = agora;
  return _ksCache.ativo;
}
const _PAGINA_OFF = `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sistema indisponível</title>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800&display=swap" rel="stylesheet">
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:'Nunito',sans-serif;background:linear-gradient(135deg,#1B2B6E,#00BFDF);color:#fff;text-align:center;padding:1rem}
.box{max-width:420px}.ic{font-size:4rem;margin-bottom:1rem}h1{font-weight:800;font-size:1.5rem;margin:.5rem 0}
p{opacity:.9;line-height:1.5}</style></head><body><div class="box">
<div class="ic">⚙️</div><h1>Sistema temporariamente indisponível</h1>
<p>Estamos enfrentando uma instabilidade técnica no momento. Por favor, tente novamente em alguns minutos.</p>
</div></body></html>`;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Kill-switch (antes de tudo, exceto /health)
app.use(async (req, res, next) => {
  if (req.path === '/health') return next();
  if (await sistemaAtivo()) return next();
  res.status(503).send(_PAGINA_OFF);
});

// Guard de autenticação (antes do static — protege também o SPA)
// Exceções: tela de acesso rápido por QR (/rapido) + suas rotas /api/publico/*.
// Elas NÃO movem estoque — só criam solicitação pendente, que o admin autoriza.
const _ROTAS_PUBLICAS  = ['/health', '/portal-auth', '/login', '/logout', '/api/resumo', '/rapido'];
const _PREFIXOS_PUBLICOS = ['/api/publico/', '/fotos/'];   // fotos das peças aparecem na tela do QR
app.use((req, res, next) => {
  if (_ROTAS_PUBLICAS.includes(req.path)) return next();
  if (_PREFIXOS_PUBLICOS.some(p => req.path.startsWith(p))) return next();
  if (validarAuthCookie(getCookie(req, 'pecas_auth'))) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'não autenticado' });
  return res.redirect('/login');
});

app.use(express.static(path.join(__dirname, 'public')));

// ─── FOTOS ────────────────────────────────────────────────────────────────────
app.get('/fotos/:filename', (req, res) => {
  const fp = path.join(fotosDir, req.params.filename);
  if (fs.existsSync(fp)) res.sendFile(fp);
  else res.status(404).json({ error: 'Foto não encontrada' });
});

// Upload de foto para uma peça
app.post('/api/pecas/:id/fotos', upload.array('fotos', 10), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  const catalog = loadCatalog();
  const idx = catalog.pecas.findIndex(p => p.id === req.params.id);
  if (idx === -1) {
    req.files.forEach(f => fs.unlinkSync(f.path));
    return res.status(404).json({ error: 'Peça não encontrada' });
  }
  const filenames = req.files.map(f => f.filename);
  catalog.pecas[idx].fotos = [...(catalog.pecas[idx].fotos || []), ...filenames];
  saveCatalog(catalog);
  res.json({ success: true, fotos: filenames });
});

// Upload de fotos SEM peça ainda (usado no cadastro que vai p/ autorização).
// Os arquivos já ficam no fotosDir; os nomes são anexados à solicitação e à peça na aprovação.
app.post('/api/fotos-temp', upload.array('fotos', 10), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  res.json({ success: true, fotos: req.files.map(f => f.filename) });
});

// ─── PEÇAS ────────────────────────────────────────────────────────────────────
app.get('/api/pecas', (req, res) => {
  const catalog = loadCatalog();
  let pecas = catalog.pecas;
  const { categoria, veiculo, pendente, q } = req.query;
  if (categoria) pecas = pecas.filter(p => p.categoria.toLowerCase() === categoria.toLowerCase());
  if (veiculo)   pecas = pecas.filter(p => p.veiculos_compativeis.some(v => v.toLowerCase().includes(veiculo.toLowerCase())));
  if (pendente !== undefined) pecas = pecas.filter(p => p.pendente_analise === (pendente === 'true'));
  if (q) {
    const t = q.toLowerCase();
    pecas = pecas.filter(p => p.nome.toLowerCase().includes(t) || p.descricao.toLowerCase().includes(t) ||
      p.codigo.toLowerCase().includes(t) || p.fabricante.toLowerCase().includes(t));
  }
  res.json({ total: pecas.length, pecas });
});

app.get('/api/pecas/:id', (req, res) => {
  const catalog = loadCatalog();
  const peca = catalog.pecas.find(p => p.id === req.params.id);
  if (!peca) return res.status(404).json({ error: 'Peça não encontrada' });
  res.json(peca);
});

app.post('/api/pecas', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  const { nome, codigo, fabricante, categoria, descricao, veiculos_compativeis, quantidade, pendente_analise, observacoes, custo_unitario, estoque_minimo, preco_referencia } = req.body;
  if (!nome || !categoria) return res.status(400).json({ error: 'Nome e categoria são obrigatórios' });
  const maxNum = catalog.pecas.reduce((m, p) => { const n = parseInt(p.id); return n > m ? n : m; }, 0);
  const peca = {
    id: String(maxNum + 1).padStart(3, '0'),
    nome, codigo: codigo || '', fabricante: fabricante || 'Não identificado',
    categoria, descricao: descricao || '',
    veiculos_compativeis: Array.isArray(veiculos_compativeis) ? veiculos_compativeis : [],
    quantidade: parseInt(quantidade) || 0,
    pendente_analise: !!pendente_analise,
    observacoes: observacoes || '', fotos: []
  };
  if (custo_unitario != null && !isNaN(Number(custo_unitario))) peca.custo_unitario = Number(custo_unitario);
  if (estoque_minimo != null && !isNaN(parseInt(estoque_minimo))) peca.estoque_minimo = parseInt(estoque_minimo);
  if (preco_referencia != null && !isNaN(Number(preco_referencia))) peca.preco_referencia = Number(preco_referencia);
  catalog.pecas.push(peca);
  saveCatalog(catalog);
  res.json({ success: true, peca });
});

app.put('/api/pecas/:id', (req, res) => {
  const catalog = loadCatalog();
  const idx = catalog.pecas.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Peça não encontrada' });
  const perfil = getPerfilFromReq(req);
  const isAdmin = perfil && perfil.papel === 'admin';
  // Operador não altera cadastro direto: envia solicitação tipo 'alteracao' para aprovação.
  if (!isAdmin)
    return res.status(403).json({ error: 'Alterações de cadastro exigem aprovação do administrador. Use "Solicitar alteração".' });
  const allowed = ['observacoes','pendente_analise','nome','descricao','codigo','fabricante','categoria','veiculos_compativeis','preco_referencia','custo_unitario','estoque_minimo','foto_url','codigo_fornecedor','quantidade'];
  allowed.forEach(f => { if (req.body[f] !== undefined) catalog.pecas[idx][f] = req.body[f]; });
  saveCatalog(catalog);
  registrarAuditoria(catalog, perfil, 'editar_peca', 'peca', catalog.pecas[idx].id, null, { nome: catalog.pecas[idx].nome }, req);
  res.json({ success: true, peca: catalog.pecas[idx] });
});

app.delete('/api/pecas/:id', (req, res) => {
  const perfil = getPerfilFromReq(req);
  if (!perfil || perfil.papel !== 'admin')
    return res.status(403).json({ error: 'Apenas administradores podem excluir peças.' });
  const catalog = loadCatalog();
  const idx = catalog.pecas.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Peça não encontrada' });
  catalog.pecas.splice(idx, 1);
  saveCatalog(catalog);
  res.json({ success: true });
});

// ─── FROTA ────────────────────────────────────────────────────────────────────
app.get('/api/frota', (req, res) => {
  const catalog = loadCatalog();
  res.json({ total: catalog.frota.length, frota: catalog.frota });
});

// Campos extras do veículo (vindos do Relatório de Frota)
const CAMPOS_VEICULO = ['ano', 'tipo', 'km', 'setor', 'status', 'observacoes'];
function aplicarCamposVeiculo(alvo, body) {
  CAMPOS_VEICULO.forEach(f => { if (body[f] !== undefined) alvo[f] = body[f]; });
}

// Cadastro direto de veículo (só admin). Operação usa solicitação tipo 'veiculo'.
app.post('/api/frota', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  const { placa, modelo, marca } = req.body;
  if (!placa || !modelo) return res.status(400).json({ error: 'Placa e modelo são obrigatórios' });
  const pl = String(placa).toUpperCase().trim();
  if ((catalog.frota || []).some(v => v.placa.toUpperCase() === pl))
    return res.status(409).json({ error: 'Já existe um veículo com esta placa' });
  const veiculo = { placa: pl, modelo: String(modelo).trim(), marca: (marca || '').trim(), status: 'Ativo' };
  aplicarCamposVeiculo(veiculo, req.body);
  catalog.frota.push(veiculo);
  saveCatalog(catalog);
  registrarAuditoria(catalog, getPerfilFromReq(req), 'criar_veiculo', 'veiculo', pl, null, veiculo, req);
  res.json({ success: true, veiculo });
});

// Editar veículo (só admin) — usado pela aba Frota.
app.put('/api/frota/:placa', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  const pl = String(req.params.placa).toUpperCase().trim();
  const idx = (catalog.frota || []).findIndex(v => v.placa.toUpperCase() === pl);
  if (idx === -1) return res.status(404).json({ error: 'Veículo não encontrado' });
  const antes = JSON.parse(JSON.stringify(catalog.frota[idx]));
  if (req.body.modelo) catalog.frota[idx].modelo = String(req.body.modelo).trim();
  if (req.body.marca !== undefined) catalog.frota[idx].marca = String(req.body.marca).trim();
  aplicarCamposVeiculo(catalog.frota[idx], req.body);
  saveCatalog(catalog);
  registrarAuditoria(catalog, getPerfilFromReq(req), 'editar_veiculo', 'veiculo', pl, antes, catalog.frota[idx], req);
  res.json({ success: true, veiculo: catalog.frota[idx] });
});

app.get('/api/frota/:placa/pecas', (req, res) => {
  const catalog = loadCatalog();
  const veiculo = catalog.frota.find(v => v.placa.toUpperCase() === req.params.placa.toUpperCase());
  if (!veiculo) return res.status(404).json({ error: 'Veículo não encontrado' });
  const pecas = catalog.pecas.filter(p => p.veiculos_compativeis.some(v => v.includes(req.params.placa.toUpperCase())));
  res.json({ veiculo, total_pecas: pecas.length, pecas });
});

// ─── FERRAMENTAS ──────────────────────────────────────────────────────────────
// Ferramenta é emprestada (não consome estoque): sai com uma pessoa, conta o tempo,
// e só volta a ficar disponível quando devolvida COM foto do lugar limpo.
function nextFerId(catalog) {
  const arr = catalog.ferramentas || [];
  const max = arr.reduce((m, f) => { const n = parseInt((f.id || '').replace('FER', '')); return n > m ? n : m; }, 0);
  return 'FER' + String(max + 1).padStart(3, '0');
}
function nextEmpId(catalog) {
  const arr = catalog.emprestimos || [];
  const max = arr.reduce((m, e) => { const n = parseInt((e.id || '').replace('EMP', '')); return n > m ? n : m; }, 0);
  return 'EMP' + String(max + 1).padStart(4, '0');
}
// Empréstimo em aberto de uma ferramenta (ou null)
function emprestimoAberto(catalog, ferramentaId) {
  return (catalog.emprestimos || []).find(e => e.ferramenta_id === ferramentaId && e.status === 'em_uso') || null;
}
// Ferramenta + situação atual (quem está com ela e desde quando)
function ferramentaComStatus(catalog, f) {
  const emp = emprestimoAberto(catalog, f.id);
  return {
    id: f.id, nome: f.nome, codigo: f.codigo || '', descricao: f.descricao || '',
    local: f.local || '', fotos: f.fotos || [],
    status: emp ? 'em_uso' : 'disponivel',
    com_quem: emp ? emp.pessoa_nome : null,
    cargo: emp ? emp.cargo : null,
    desde: emp ? emp.retirado_em : null,
    emprestimo_id: emp ? emp.id : null
  };
}

app.get('/api/ferramentas', (req, res) => {
  const catalog = loadCatalog();
  const lista = (catalog.ferramentas || []).map(f => ferramentaComStatus(catalog, f));
  res.json({ total: lista.length, ferramentas: lista });
});

app.post('/api/ferramentas', ensureAdmin, (req, res) => {
  const { nome, codigo, descricao, local, fotos } = req.body;
  if (!nome || !String(nome).trim()) return res.status(400).json({ error: 'Nome da ferramenta é obrigatório' });
  const catalog = loadCatalog();
  if (!catalog.ferramentas) catalog.ferramentas = [];
  const ferramenta = {
    id: nextFerId(catalog), nome: String(nome).trim(), codigo: (codigo || '').trim(),
    descricao: (descricao || '').trim(), local: (local || '').trim(),
    fotos: Array.isArray(fotos) ? fotos : [], criado_em: new Date().toISOString()
  };
  catalog.ferramentas.push(ferramenta);
  saveCatalog(catalog);
  registrarAuditoria(catalog, getPerfilFromReq(req), 'criar_ferramenta', 'ferramenta', ferramenta.id, null, ferramenta, req);
  res.json({ success: true, ferramenta });
});

app.put('/api/ferramentas/:id', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  const idx = (catalog.ferramentas || []).findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Ferramenta não encontrada' });
  ['nome', 'codigo', 'descricao', 'local'].forEach(c => {
    if (req.body[c] !== undefined) catalog.ferramentas[idx][c] = String(req.body[c]).trim();
  });
  saveCatalog(catalog);
  res.json({ success: true, ferramenta: catalog.ferramentas[idx] });
});

app.delete('/api/ferramentas/:id', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  const idx = (catalog.ferramentas || []).findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Ferramenta não encontrada' });
  if (emprestimoAberto(catalog, req.params.id))
    return res.status(400).json({ error: 'Esta ferramenta está emprestada. Registre a devolução antes de excluir.' });
  catalog.ferramentas.splice(idx, 1);
  saveCatalog(catalog);
  res.json({ success: true });
});

app.post('/api/ferramentas/:id/fotos', ensureAdmin, upload.array('fotos', 10), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  const catalog = loadCatalog();
  const idx = (catalog.ferramentas || []).findIndex(f => f.id === req.params.id);
  if (idx === -1) { req.files.forEach(f => { try { fs.unlinkSync(f.path); } catch (_) {} }); return res.status(404).json({ error: 'Ferramenta não encontrada' }); }
  const nomes = req.files.map(f => f.filename);
  catalog.ferramentas[idx].fotos = [...(catalog.ferramentas[idx].fotos || []), ...nomes];
  saveCatalog(catalog);
  res.json({ success: true, fotos: nomes });
});

// Empréstimos (histórico). Admin vê tudo; demais veem os em aberto.
app.get('/api/emprestimos', (req, res) => {
  const perfil = getPerfilFromReq(req);
  if (!perfil) return res.status(401).json({ error: 'não autenticado' });
  const catalog = loadCatalog();
  let arr = (catalog.emprestimos || []).slice().reverse();
  if (req.query.status) arr = arr.filter(e => e.status === req.query.status);
  res.json({ total: arr.length, emprestimos: arr });
});

// ─── CATEGORIAS ───────────────────────────────────────────────────────────────
app.get('/api/categorias', (req, res) => {
  const catalog = loadCatalog();
  const cats = [...new Set(catalog.pecas.map(p => p.categoria))].sort();
  res.json(cats.map(cat => ({
    categoria: cat,
    total: catalog.pecas.filter(p => p.categoria === cat).length,
    total_unidades: catalog.pecas.filter(p => p.categoria === cat).reduce((s, p) => s + p.quantidade, 0)
  })));
});

// ─── ESTATÍSTICAS ─────────────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  const catalog = loadCatalog();
  const pecas = catalog.pecas;
  res.json({
    total_itens: pecas.length,
    total_unidades: pecas.reduce((s, p) => s + p.quantidade, 0),
    pendentes_analise: pecas.filter(p => p.pendente_analise).length,
    fora_da_frota: pecas.filter(p => p.veiculos_compativeis.length === 0).length,
    por_categoria: pecas.reduce((a, p) => { a[p.categoria] = (a[p.categoria]||0) + p.quantidade; return a; }, {}),
    por_fabricante: pecas.reduce((a, p) => { const f = p.fabricante.split(' ')[0]; a[f] = (a[f]||0) + p.quantidade; return a; }, {})
  });
});

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
app.get('/api/dashboard', (req, res) => {
  const catalog = loadCatalog();
  // baixas = saídas do histórico unificado (registros antigos + livro-razão V3)
  const movs  = todasMovimentacoes(catalog).filter(m => m.tipo === 'saida');
  const pecas = catalog.pecas;

  // Movimentações por veículo (quantidade total retirada)
  const porVeiculo = {};
  movs.forEach(m => {
    const v = m.veiculo || 'Sem veículo';
    porVeiculo[v] = (porVeiculo[v] || 0) + m.quantidade;
  });

  // Top peças mais retiradas
  const porPeca = {};
  movs.forEach(m => { porPeca[m.peca_nome] = (porPeca[m.peca_nome] || 0) + m.quantidade; });
  const topPecas = Object.entries(porPeca)
    .sort((a,b) => b[1] - a[1]).slice(0, 10)
    .map(([nome, qtd]) => ({ nome: nome.length > 28 ? nome.substring(0,25)+'…' : nome, qtd }));

  // Estoque por categoria
  const porCategoria = {};
  pecas.forEach(p => { porCategoria[p.categoria] = (porCategoria[p.categoria] || 0) + p.quantidade; });

  // Movimentações por mês (últimos 6 meses)
  const porMes = {};
  const now = new Date();
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    porMes[`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`] = 0;
  }
  movs.forEach(m => { const k = (m.data||'').substring(0,7); if (k in porMes) porMes[k] += m.quantidade; });

  // Últimas 5 movimentações
  const ultimas = movs.slice().reverse().slice(0, 5);

  res.json({
    total_baixas: movs.length,
    total_qtd_baixas: movs.reduce((s,m) => s + m.quantidade, 0),
    por_veiculo: porVeiculo,
    top_pecas: topPecas,
    por_categoria: porCategoria,
    por_mes: porMes,
    ultimas_movimentacoes: ultimas
  });
});

// ─── MOVIMENTAÇÕES ────────────────────────────────────────────────────────────
app.get('/api/movimentacoes', (req, res) => {
  const catalog = loadCatalog();
  const movs = todasMovimentacoes(catalog).reverse();
  res.json({ total: movs.length, movimentacoes: movs });
});

app.get('/api/movimentacoes/peca/:pecaId', (req, res) => {
  const catalog = loadCatalog();
  const movs = todasMovimentacoes(catalog).filter(m => m.peca_id === req.params.pecaId).reverse();
  res.json({ total: movs.length, movimentacoes: movs });
});

// Baixa direta do admin — vai para o MESMO livro-razão das aprovações (com valor).
app.post('/api/movimentacoes', ensureAdmin, (req, res) => {
  const perfil = getPerfilFromReq(req);
  serializarEscrita(() => {
    const catalog = loadCatalog();
    const { peca_id, responsavel, veiculo, quantidade, observacoes } = req.body;
    if (!peca_id || !responsavel || !quantidade) { res.status(400).json({ error: 'peca_id, responsavel e quantidade são obrigatórios' }); return; }
    const qty = parseInt(quantidade);
    if (!Number.isInteger(qty) || qty <= 0) { res.status(400).json({ error: 'quantidade deve ser inteiro positivo' }); return; }
    try {
      const { mov, saldoNovo } = aplicarMovimentacao(catalog, {
        peca_id, tipo: 'saida', quantidade: qty,
        usuario_id: perfil ? perfil.id : null,
        placa: veiculo ? String(veiculo).trim().split(' ')[0].toUpperCase() : null,
        responsavel, observacoes: observacoes || ''
      });
      saveCatalog(catalog);
      registrarAuditoria(catalog, perfil, 'baixa_direta', 'movimentacao', mov.id, null, mov, req);
      res.json({ success: true, movimentacao: mov, nova_quantidade: saldoNovo });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }).catch(e => { if (!res.headersSent) res.status(500).json({ error: e.message }); });
});

// ─── ENDEREÇO NA REDE (para o QR Code) ───────────────────────────────────
// O QR precisa apontar para o IP do servidor na rede local — nunca "localhost",
// que no celular apontaria para o próprio celular.
app.get('/api/endereco-lan', (req, res) => {
  const os = require('os');
  let ip = null;
  const ifaces = os.networkInterfaces();
  for (const nome of Object.keys(ifaces)) {
    for (const i of ifaces[nome] || []) {
      if (i.family === 'IPv4' && !i.internal && !/^169\.254\./.test(i.address)) {
        // prefere a rede local comum (192.168.x / 10.x / 172.16-31.x)
        if (/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(i.address)) { ip = i.address; break; }
        if (!ip) ip = i.address;
      }
    }
    if (ip && /^192\.168\./.test(ip)) break;
  }
  const porta = String(PORT);
  res.json({ ip, porta, base: ip ? `http://${ip}:${porta}` : null });
});

// ─── EDITAR MOVIMENTAÇÃO (admin) ──────────────────────────────────────────────
// Corrige um lançamento errado. O MOTIVO é obrigatório e tudo fica na auditoria.
// Se a quantidade mudar, o saldo da peça é corrigido pela diferença (serializado).
app.put('/api/movimentacoes/:id', ensureAdmin, (req, res) => {
  const perfil = getPerfilFromReq(req);
  const motivo = String(req.body.motivo || '').trim();
  if (motivo.length < 3)
    return res.status(400).json({ error: 'O motivo da edição é obrigatório (mínimo 3 letras).' });

  serializarEscrita(() => {
    const catalog = loadCatalog();
    const id = req.params.id;
    const mov = (catalog.movimentacoes_estoque || []).find(m => m.id === id);
    if (!mov) { res.status(404).json({ error: 'Movimentação não encontrada. Registros antigos não podem ser editados.' }); return; }

    const antes = JSON.parse(JSON.stringify(mov));
    try {
      // ── quantidade: corrige o saldo pela diferença ──
      if (req.body.quantidade !== undefined) {
        const nova = parseInt(req.body.quantidade);
        if (!Number.isInteger(nova) || nova <= 0) throw new Error('Quantidade inválida.');
        const dif = nova - mov.quantidade;
        if (dif !== 0) {
          const idxP = catalog.pecas.findIndex(p => p.id === mov.peca_id);
          if (idxP === -1) throw new Error('Peça desta movimentação não existe mais.');
          // entrada: +dif no estoque | saída: -dif no estoque
          const delta = mov.tipo === 'entrada' ? dif : -dif;
          const saldoAtual = catalog.pecas[idxP].quantidade || 0;
          const saldoNovo  = saldoAtual + delta;
          if (saldoNovo < 0) throw new Error(`Correção deixaria o estoque negativo (ficaria ${saldoNovo}).`);
          catalog.pecas[idxP].quantidade = saldoNovo;
          mov.saldo_novo = (mov.saldo_anterior || 0) + (mov.tipo === 'entrada' ? nova : -nova);
        }
        mov.quantidade = nova;
      }
      // ── demais campos ──
      if (req.body.custo_unitario !== undefined) {
        const c = req.body.custo_unitario === '' || req.body.custo_unitario === null ? null : Number(req.body.custo_unitario);
        if (c !== null && (isNaN(c) || c < 0)) throw new Error('Custo inválido.');
        mov.custo_unitario = c;
      }
      if (req.body.placa       !== undefined) mov.placa       = String(req.body.placa || '').toUpperCase().trim() || null;
      if (req.body.responsavel !== undefined) mov.responsavel = String(req.body.responsavel || '').trim() || null;
      if (req.body.observacoes !== undefined) mov.observacoes = String(req.body.observacoes || '').trim() || null;

      // valor total sempre recalculado
      mov.valor_total = mov.custo_unitario != null
        ? Math.round(mov.custo_unitario * mov.quantidade * 100) / 100 : null;

      // marca que foi editada (fica visível no histórico)
      if (!mov.edicoes) mov.edicoes = [];
      mov.edicoes.push({
        motivo, por: perfil ? perfil.nome : null, em: new Date().toISOString(),
        de: { quantidade: antes.quantidade, custo_unitario: antes.custo_unitario,
              placa: antes.placa, responsavel: antes.responsavel, observacoes: antes.observacoes },
      });
      mov.editada = true;

      saveCatalog(catalog);
      registrarAuditoria(catalog, perfil, 'editar_movimentacao', 'movimentacao', mov.id,
        antes, Object.assign({}, mov, { motivo_edicao: motivo }), req);
      res.json({ success: true, movimentacao: mov });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }).catch(e => { if (!res.headersSent) res.status(500).json({ error: e.message }); });
});

// ─── DIAGNÓSTICO ─────────────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  const key = process.env.GEMINI_API_KEY || '';
  res.json({
    ok: true,
    gemini_configurado: key.length > 0,
    gemini_key_preview: key ? key.substring(0,8)+'...' : 'NÃO CONFIGURADA',
    node_env: process.env.NODE_ENV || 'não definido',
    hora: new Date().toISOString()
  });
});

// ─── PERFIS DE ACESSO ─────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  const p = getPerfilFromReq(req);
  if (!p) return res.status(401).json({ error: 'não autenticado' });
  res.json({ id: p.id, nome: p.nome, papel: p.papel });
});

app.get('/api/perfis', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  const perfis = (catalog.perfis || []).map(p => ({
    id: p.id, nome: p.nome, papel: p.papel, ativo: p.ativo, criado_em: p.criado_em
  }));
  res.json(perfis);
});

app.post('/api/perfis', ensureAdmin, (req, res) => {
  const { nome, papel, senha } = req.body;
  if (!nome || !papel || !senha) return res.status(400).json({ error: 'nome, papel e senha são obrigatórios' });
  const papelNorm = normalizarPapel(papel);
  if (!PAPEIS_VALIDOS.includes(papelNorm)) return res.status(400).json({ error: 'papel inválido' });
  const catalog = loadCatalog();
  if (!catalog.perfis) catalog.perfis = [];
  if (catalog.perfis.some(p => p.nome.toLowerCase() === nome.toLowerCase()))
    return res.status(409).json({ error: 'Já existe um perfil com este nome' });
  const maxNum = catalog.perfis.reduce((m, p) => {
    const n = parseInt(p.id.replace('prf', '')); return (n > m ? n : m);
  }, 0);
  const perfil = {
    id: 'prf' + String(maxNum + 1).padStart(3, '0'),
    nome, papel: papelNorm, senha: hashPassword(senha), ativo: true, criado_em: new Date().toISOString()
  };
  catalog.perfis.push(perfil);
  saveCatalog(catalog);
  res.json({ success: true, perfil: { id: perfil.id, nome: perfil.nome, papel: perfil.papel, ativo: perfil.ativo } });
});

app.put('/api/perfis/:id', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  if (!catalog.perfis) return res.status(404).json({ error: 'Perfil não encontrado' });
  const idx = catalog.perfis.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Perfil não encontrado' });
  const { nome, papel, senha, ativo } = req.body;
  if (nome) {
    if (catalog.perfis.some((p, i) => i !== idx && p.nome.toLowerCase() === nome.toLowerCase()))
      return res.status(409).json({ error: 'Já existe um perfil com este nome' });
    catalog.perfis[idx].nome = nome;
  }
  if (papel && PAPEIS_VALIDOS.includes(normalizarPapel(papel))) catalog.perfis[idx].papel = normalizarPapel(papel);
  if (senha) catalog.perfis[idx].senha = hashPassword(senha);
  if (ativo !== undefined) catalog.perfis[idx].ativo = !!ativo;
  saveCatalog(catalog);
  const p = catalog.perfis[idx];
  res.json({ success: true, perfil: { id: p.id, nome: p.nome, papel: p.papel, ativo: p.ativo } });
});

app.delete('/api/perfis/:id', ensureAdmin, (req, res) => {
  const meId = getPerfilFromReq(req)?.id;
  const catalog = loadCatalog();
  if (!catalog.perfis) return res.status(404).json({ error: 'Perfil não encontrado' });
  const idx = catalog.perfis.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Perfil não encontrado' });
  if (catalog.perfis[idx].id === meId)
    return res.status(400).json({ error: 'Você não pode excluir seu próprio perfil.' });
  const isAdmin    = catalog.perfis[idx].papel === 'admin';
  const adminCount = catalog.perfis.filter(p => p.papel === 'admin' && p.ativo).length;
  if (isAdmin && adminCount <= 1)
    return res.status(400).json({ error: 'Não é possível excluir o único administrador.' });
  catalog.perfis.splice(idx, 1);
  saveCatalog(catalog);
  res.json({ success: true });
});

// ─── ANÁLISE IA (GEMINI) ─────────────────────────────────────────────────
app.﻿post('/api/analisar-foto', upload.single('foto'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhuma foto enviada' });
  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    try { fs.unlinkSync(req.file.path); } catch(_) {}
    return res.status(503).json({ error: 'GEMINI_API_KEY nao configurada no servidor' });
  }
  try {
    const catalog = loadCatalog();
    const cats = [...new Set((catalog.pecas||[]).map(p=>p.categoria).filter(Boolean))].sort().join(', ') || 'Filtros, Freios, Motor, Embreagem, Suspensao, Carroceria, Eletrica';
    const base64 = fs.readFileSync(req.file.path).toString('base64');
    const mime   = req.file.mimetype || 'image/jpeg';
    try { fs.unlinkSync(req.file.path); } catch(_) {}

    const linhas = [
      'Voce e um especialista em identificacao de pecas mecanicas, industriais, agricolas e automotivas.',
      'Analise CUIDADOSAMENTE esta imagem e identifique a peca.',
      '',
      'REGRAS OBRIGATORIAS:',
      '1. Leia TODO texto visivel na embalagem, rotulo ou na propria peca (codigo, marca, referencia)',
      '2. NAO assuma que e peca de carro. Pode ser de moto, caminhao, trator, maquina industrial, equipamento agricola etc.',
      '3. Identifique pelo que REALMENTE ve na imagem, nao por suposicao',
      '4. Se houver codigo ou referencia visivel, copie EXATAMENTE como aparece',
      '5. Se nao tiver certeza, deixe o campo como string vazia',
      '',
      'Categorias disponiveis: ' + cats,
      '',
      'Retorne SOMENTE JSON puro sem markdown:',
      '{"nome":"nome tecnico da peca","codigo":"codigo visivel ou vazio","fabricante":"marca visivel ou Nao identificado","categoria":"categoria adequada","descricao":"descreva o que voce ve na imagem em 1-2 frases"}'
    ];
    const prompt = linhas.join('\n');

    const result = await httpsPost(
      'https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=' + key,
      {
        contents: [{ parts: [{ text: prompt }, { inline_data: { mime_type: mime, data: base64 } }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 1024 }
      }
    );

    if (result && result.error) return res.status(502).json({ error: 'Gemini API: ' + (result.error.message || JSON.stringify(result.error)) });

    const text = ((((result||{}).candidates||[])[0]||{}).content||{}).parts && result.candidates[0].content.parts[0].text || '';
    if (!text) return res.status(422).json({ error: 'Gemini nao gerou resposta' });

    let parsed;
    try { parsed = JSON.parse(text.trim()); } catch(_) {}
    if (!parsed) try { parsed = JSON.parse(text.replace(/[\s\S]*?({[\s\S]*})[\s\S]*/,'')); } catch(_) {}
    if (!parsed) { const m = text.match(/{[\s\S]*}/); if(m) try { parsed = JSON.parse(m[0]); } catch(_) {} }
    if (!parsed) return res.status(422).json({ error: 'IA nao retornou JSON valido', raw: text.substring(0,500) });

    res.json({ success: true, dados: parsed });
  } catch(e) {
    try { if (req.file) fs.unlinkSync(req.file.path); } catch(_) {}
    res.status(500).json({ error: e.message });
  }
})

// ─── PREÇO MERCADO LIVRE ──────────────────────────────────────────────────────
app.get('/api/preco/:id', async (req, res) => {
  try {
    const catalog = loadCatalog();
    const peca = catalog.pecas.find(p => p.id === req.params.id);
    if (!peca) return res.status(404).json({ error: 'Peça não encontrada' });
    const q = encodeURIComponent([peca.nome, peca.codigo, peca.fabricante].filter(Boolean).join(' ').substring(0, 80));
    const data = await httpsGet(`https://api.mercadolibre.com/sites/MLB/search?q=${q}&limit=10`);
    const items = (data.results || []).filter(i => i.price > 0).slice(0, 10);
    if (!items.length) return res.json({ found: false });
    const prices = items.map(i => i.price);
    const avg = prices.reduce((s, p) => s + p, 0) / prices.length;
    res.json({
      found: true,
      media: Math.round(avg * 100) / 100,
      minimo: Math.min(...prices),
      maximo: Math.max(...prices),
      amostras: items.length,
      exemplos: items.slice(0, 3).map(i => ({ titulo: i.title.substring(0, 70), preco: i.price, url: i.permalink }))
    });
  } catch(e) { res.json({ found: false, error: e.message }); }
});

// ─── AUTENTICAÇÃO / SSO / HEALTH ───────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', sistema: 'Bolsão Peças' }));

// KPIs para o painel do Portal (público)
app.get('/api/resumo', (req, res) => {
  try {
    const c = loadCatalog();
    const pecas = c.pecas || [];
    const minimo = p => (p.estoque_minimo != null ? p.estoque_minimo : 2);
    const mesAtual = new Date().toISOString().substring(0, 7);
    const movsMes = todasMovimentacoes(c).filter(m => (m.data || '').substring(0, 7) === mesAtual).length;
    res.json({
      total_itens:       pecas.length,
      total_unidades:    pecas.reduce((s, p) => s + (p.quantidade || 0), 0),
      pendentes_analise: pecas.filter(p => p.pendente_analise).length,
      veiculos:          (c.frota || []).length,
      // KPIs do Painel Bolsão (contagens apenas — sem valores R$ em rota pública)
      total_pecas:       pecas.length,
      sem_estoque:       pecas.filter(p => (p.quantidade || 0) === 0).length,
      estoque_baixo:     pecas.filter(p => (p.quantidade || 0) > 0 && (p.quantidade || 0) <= minimo(p)).length,
      total_frota:       (c.frota || []).length,
      movimentacoes_mes: movsMes,
      pendentes_autorizacao: (c.solicitacoes || []).filter(s => s.status === 'pendente').length,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/portal-auth', (req, res) => {
  if (validarTokenSSO(req.query.token || '', 'pecas')) {
    const catalog = loadCatalog();
    const admin   = (catalog.perfis || []).find(p => p.papel === 'admin' && p.ativo);
    const pid     = admin ? admin.id : '_legacy_admin';
    res.setHeader('Set-Cookie',
      `pecas_auth=${gerarAuthCookie(pid)}; HttpOnly; Path=/; Max-Age=28800; SameSite=Lax`);
  }
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'pecas_auth=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/login');
});

function _paginaLogin(erro, msg) {
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login — Bolsão Peças</title>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  :root{--navy:#1B2B6E;--orange:#F5941D;--cyan:#00BFDF}
  *{box-sizing:border-box} body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    font-family:'Nunito',sans-serif;background:linear-gradient(135deg,var(--navy),var(--cyan));padding:1rem}
  .card{background:#fff;border-radius:1rem;border-top:5px solid var(--orange);box-shadow:0 12px 40px rgba(0,0,0,.25);
    width:100%;max-width:360px;padding:2.5rem 2rem 2rem;text-align:center}
  .icon{font-size:3rem}
  h1{color:var(--navy);font-weight:800;font-size:1.35rem;margin:.5rem 0 .25rem}
  p.sub{color:#8a92b2;font-size:.85rem;margin:0 0 1.5rem}
  label{display:block;text-align:left;font-weight:600;color:#3a3f5c;font-size:.85rem;margin-bottom:.35rem}
  input{width:100%;padding:.6rem .75rem;border:1px solid #d0d4e4;border-radius:.5rem;font-size:1rem;font-family:inherit}
  input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,191,223,.15)}
  button{width:100%;margin-top:1rem;padding:.65rem;border:none;border-radius:.5rem;background:var(--navy);color:#fff;
    font-weight:700;font-size:1rem;font-family:inherit;cursor:pointer;transition:background .15s}
  button:hover{background:var(--orange)}
  .erro{background:#f8d7da;color:#842029;border-radius:.4rem;padding:.5rem;font-size:.85rem;margin-bottom:1rem}
</style></head><body>
  <form class="card" method="POST" action="/login">
    <div class="icon">🔧</div>
    <h1>Bolsão Peças</h1>
    <p class="sub">Catálogo de Peças Veiculares</p>
    ${erro ? `<div class="erro">${msg || 'Senha incorreta.'}</div>` : ''}
    <label>Nome de usuário</label>
    <input type="text" name="nome" autofocus required autocomplete="username" placeholder="Seu nome">
    <label style="margin-top:.75rem">Senha</label>
    <input type="password" name="senha" required autocomplete="current-password" placeholder="••••••">
    <button type="submit">Entrar</button>
  </form>
</body></html>`;
}

app.get('/login', (req, res) => {
  if (validarAuthCookie(getCookie(req, 'pecas_auth'))) return res.redirect('/');
  res.send(_paginaLogin(false));
});

app.post('/login', (req, res) => {
  const ip = ((req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0]).trim();
  if (!checkRateLimit(ip)) return res.status(429).send(_paginaLogin(true, 'Muitas tentativas. Aguarde 5 minutos.'));
  const { nome, senha } = req.body;
  const catalog = loadCatalog();
  const perfis  = catalog.perfis || [];

  // Sem perfis cadastrados → fallback senha única (legado)
  if (!perfis.length) {
    if ((senha || '') === PECAS_SENHA) {
      resetRateLimit(ip);
      res.setHeader('Set-Cookie',
        `pecas_auth=${gerarAuthCookie('_legacy_admin')}; HttpOnly; Path=/; Max-Age=28800; SameSite=Lax`);
      return res.redirect('/');
    }
    return res.status(401).send(_paginaLogin(true));
  }

  const perfil = perfis.find(p =>
    p.nome.toLowerCase() === (nome || '').trim().toLowerCase() &&
    verifyPassword(senha, p.senha) && p.ativo
  );
  if (!perfil) return res.status(401).send(_paginaLogin(true));
  if (!(perfil.senha || '').startsWith('sha256:')) {
    const cL = loadCatalog();
    const pL = cL.perfis.find(x => x.id === perfil.id);
    if (pL) { pL.senha = hashPassword(senha); saveCatalog(cL); }
  }
  resetRateLimit(ip);
  try { registrarAuditoria(loadCatalog(), { id: perfil.id, nome: perfil.nome }, 'login', 'sessao', perfil.id, null, { papel: normalizarPapel(perfil.papel) }, req); } catch (_) {}
  res.setHeader('Set-Cookie',
    `pecas_auth=${gerarAuthCookie(perfil.id)}; HttpOnly; Path=/; Max-Age=28800; SameSite=Lax`);
  res.redirect('/');
});

// ─── FALLBACK ─────────────────────────────────────────────────────────────────
// Export CSV movimentações
app.get('/api/movimentacoes/export', (req, res) => {
  const catalog = loadCatalog();
  const movs = todasMovimentacoes(catalog).reverse();
  const esc = s => '"' + String(s || '').replace(/"/g, '""') + '"';
  const num = v => v == null ? '' : String(v).replace('.', ',');
  const hdr = ['ID','Data','Tipo','Peca','Codigo','Responsavel','Veiculo','Quantidade','Custo Unit (R$)','Valor Total (R$)','Autorizado por','Observacoes'].join(';');
  const rows = movs.map(m => [m.id, m.data, m.tipo === 'entrada' ? 'Entrada' : 'Saida', esc(m.peca_nome), esc(m.peca_codigo), esc(m.responsavel), esc(m.veiculo), m.quantidade, num(m.custo_unitario), num(m.valor_total), esc(m.aprovado_por), esc(m.observacoes)].join(';'));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="movimentacoes_' + new Date().toISOString().split('T')[0] + '.csv"');
  res.send('\ufeff' + [hdr, ...rows].join('\r\n'));
});

// ─── ACESSO RÁPIDO POR QR (sem login, só na rede da empresa) ────────────────────
// A pessoa escaneia o QR, vê as peças e pede a baixa preenchendo nome/setor/veículo/motivo.
// NADA aqui move estoque: só cria solicitação 'pendente' para o admin autorizar.
// Não expõe custo/preço — a tela do QR é só operação.

// Limite anti-abuso: no máx. 20 pedidos por IP a cada 10 min.
const _pedidosPublicos = new Map();
function limitePublico(ip) {
  const agora = Date.now(), janela = 10 * 60 * 1000, max = 20;
  const e = _pedidosPublicos.get(ip);
  if (!e || agora - e.inicio > janela) { _pedidosPublicos.set(ip, { count: 1, inicio: agora }); return true; }
  if (e.count >= max) return false;
  e.count++; return true;
}
function ipDaReq(req) {
  return ((req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'desconhecido').split(',')[0]).trim();
}

app.get('/rapido', (req, res) => res.sendFile(path.join(__dirname, 'public', 'rapido.html')));

// Peças visíveis na tela do QR (sem custo/preço)
app.get('/api/publico/pecas', (req, res) => {
  const catalog = loadCatalog();
  const pecas = (catalog.pecas || []).map(p => ({
    id: p.id, nome: p.nome, codigo: p.codigo || '', fabricante: p.fabricante || '',
    categoria: p.categoria || '', quantidade: p.quantidade || 0,
    veiculos_compativeis: p.veiculos_compativeis || [], fotos: p.fotos || []
  }));
  res.json({ total: pecas.length, pecas });
});

app.get('/api/publico/frota', (req, res) => {
  const catalog = loadCatalog();
  res.json({ frota: (catalog.frota || []).map(v => ({ placa: v.placa, modelo: v.modelo, marca: v.marca || '' })) });
});

// ── Ferramentas na tela do QR (sem login) ──
app.get('/api/publico/ferramentas', (req, res) => {
  const catalog = loadCatalog();
  const lista = (catalog.ferramentas || []).map(f => ferramentaComStatus(catalog, f));
  res.json({ total: lista.length, ferramentas: lista });
});

// RETIRADA de ferramenta pelo QR: nome + cargo obrigatórios. O relógio começa aqui.
app.post('/api/publico/emprestimos', (req, res) => {
  const ip = ipDaReq(req);
  if (!limitePublico(ip)) return res.status(429).json({ error: 'Muitos pedidos deste aparelho. Aguarde alguns minutos.' });

  const nome  = String(req.body.nome  || '').trim();
  const cargo = String(req.body.cargo || '').trim();
  const obs   = String(req.body.observacao || '').trim();
  if (!nome || nome.length < 3) return res.status(400).json({ error: 'Informe seu nome completo.' });
  if (!cargo)                   return res.status(400).json({ error: 'Informe o seu cargo.' });

  const catalog = loadCatalog();
  const ferramenta = (catalog.ferramentas || []).find(f => f.id === req.body.ferramenta_id);
  if (!ferramenta) return res.status(404).json({ error: 'Ferramenta não encontrada.' });
  const aberto = emprestimoAberto(catalog, ferramenta.id);
  if (aberto) return res.status(409).json({ error: `Esta ferramenta já está com ${aberto.pessoa_nome} desde ${new Date(aberto.retirado_em).toLocaleString('pt-BR')}.` });

  if (!catalog.emprestimos) catalog.emprestimos = [];
  const emp = {
    id: nextEmpId(catalog),
    ferramenta_id: ferramenta.id, ferramenta_nome: ferramenta.nome, ferramenta_codigo: ferramenta.codigo || '',
    pessoa_nome: nome, cargo, observacao: obs,
    status: 'em_uso',
    retirado_em: new Date().toISOString(),      // SEMPRE do servidor
    devolvido_em: null, foto_devolucao: null, observacao_devolucao: '',
    via_qr: true
  };
  catalog.emprestimos.push(emp);
  saveCatalog(catalog);
  registrarAuditoria(catalog, { id: null, nome: `${nome} (QR · ${cargo})` }, 'retirar_ferramenta', 'emprestimo', emp.id, null, emp, req);
  res.json({ success: true, emprestimo: emp });
});

// DEVOLUÇÃO pelo QR: exige FOTO da ferramenta no lugar, limpa.
app.post('/api/publico/emprestimos/:id/devolver', upload.single('foto'), (req, res) => {
  const catalog = loadCatalog();
  const emp = (catalog.emprestimos || []).find(e => e.id === req.params.id);
  if (!emp) { if (req.file) { try { fs.unlinkSync(req.file.path); } catch (_) {} } return res.status(404).json({ error: 'Empréstimo não encontrado.' }); }
  if (emp.status !== 'em_uso') { if (req.file) { try { fs.unlinkSync(req.file.path); } catch (_) {} } return res.status(409).json({ error: 'Esta ferramenta já foi devolvida.' }); }
  if (!req.file) return res.status(400).json({ error: 'A foto da ferramenta no lugar é obrigatória.' });

  emp.status = 'devolvido';
  emp.devolvido_em = new Date().toISOString();   // SEMPRE do servidor
  emp.foto_devolucao = req.file.filename;
  emp.observacao_devolucao = String(req.body.observacao || '').trim();
  emp.devolvido_por = String(req.body.nome || emp.pessoa_nome).trim();
  saveCatalog(catalog);
  registrarAuditoria(catalog, { id: null, nome: `${emp.devolvido_por} (QR)` }, 'devolver_ferramenta', 'emprestimo', emp.id, null, emp, req);
  res.json({ success: true, emprestimo: emp });
});

// Pedido de baixa pelo QR. TODOS os campos são obrigatórios. Data/hora = do servidor.
app.post('/api/publico/solicitacoes', (req, res) => {
  const ip = ipDaReq(req);
  if (!limitePublico(ip)) return res.status(429).json({ error: 'Muitos pedidos deste aparelho. Aguarde alguns minutos.' });

  const nome  = String(req.body.nome  || '').trim();
  const setor = String(req.body.setor || '').trim();
  const placa = String(req.body.placa || '').trim().toUpperCase();
  const obs   = String(req.body.observacao || '').trim();
  const qtd   = parseInt(req.body.quantidade);

  if (!nome  || nome.length  < 3) return res.status(400).json({ error: 'Informe seu nome completo.' });
  if (!setor)                     return res.status(400).json({ error: 'Informe o setor.' });
  if (!placa)                     return res.status(400).json({ error: 'Selecione o veículo.' });
  if (!obs   || obs.length   < 3) return res.status(400).json({ error: 'Descreva o motivo da troca.' });
  if (!Number.isInteger(qtd) || qtd <= 0) return res.status(400).json({ error: 'Informe a quantidade.' });

  const catalog = loadCatalog();
  const peca = (catalog.pecas || []).find(p => p.id === req.body.peca_id);
  if (!peca) return res.status(404).json({ error: 'Peça não encontrada.' });
  const veiculo = (catalog.frota || []).find(v => v.placa.toUpperCase() === placa);
  if (!veiculo) return res.status(400).json({ error: 'Veículo não cadastrado na frota.' });
  if ((peca.quantidade || 0) < qtd)
    return res.status(400).json({ error: `Estoque insuficiente. Disponível: ${peca.quantidade || 0}` });

  if (!catalog.solicitacoes) catalog.solicitacoes = [];
  const sol = {
    id: nextSolId(catalog), tipo: 'baixa', status: 'pendente',
    peca_id: peca.id, peca_nome: peca.nome, peca_codigo: peca.codigo || '',
    placa, quantidade_solicitada: qtd, quantidade_aprovada: null,
    observacao: obs,
    setor, via_qr: true,                       // veio da tela do QR (nome declarado, sem login)
    solicitante_id: null, solicitante_nome: nome,
    criado_em: new Date().toISOString(),       // SEMPRE do servidor
    aprovado_por: null, aprovado_por_nome: null, aprovado_em: null, motivo_recusa: null
  };
  catalog.solicitacoes.push(sol);
  saveCatalog(catalog);
  registrarAuditoria(catalog, { id: null, nome: `${nome} (QR · ${setor})` }, 'criar_solicitacao', 'solicitacao', sol.id, null, sol, req);
  res.json({ success: true, solicitacao: sol });
});

// ─── SOLICITAÇÕES (fila de autorização) ─────────────────────────────────────────
// Toda baixa/entrada nasce aqui como 'pendente'. O estoque NÃO muda até o admin aprovar.
function nextSolId(catalog) {
  const arr = catalog.solicitacoes || [];
  const max = arr.reduce((m, s) => { const n = parseInt((s.id || '').replace('SOL', '')); return n > m ? n : m; }, 0);
  return 'SOL' + String(max + 1).padStart(4, '0');
}

// Cria solicitação (operacao ou admin). Não move estoque.
app.post('/api/solicitacoes', ensureOperacao, (req, res) => {
  const perfil = getPerfilFromReq(req);
  const { tipo, peca_id, placa, quantidade, observacao, fornecedor, custo_unitario, nota_fiscal } = req.body;

  // ── CADASTRO de nova peça (vai para autorização; não entra no catálogo ainda) ──
  if (tipo === 'cadastro') {
    const dados = req.body.dados || {};
    if (!dados.nome || !dados.categoria) return res.status(400).json({ error: 'Nome e categoria são obrigatórios' });
    const catalog = loadCatalog();
    if (!catalog.solicitacoes) catalog.solicitacoes = [];
    const sol = {
      id: nextSolId(catalog), tipo: 'cadastro', status: 'pendente',
      peca_id: null, peca_nome: dados.nome, peca_codigo: dados.codigo || '',
      placa: null,
      quantidade_solicitada: parseInt(dados.quantidade) || 0, quantidade_aprovada: null,
      observacao: observacao || dados.observacoes || '',
      dados: {
        nome: dados.nome, codigo: dados.codigo || '', fabricante: dados.fabricante || 'Não identificado',
        categoria: dados.categoria, descricao: dados.descricao || '',
        veiculos_compativeis: Array.isArray(dados.veiculos_compativeis) ? dados.veiculos_compativeis : [],
        quantidade: parseInt(dados.quantidade) || 0, observacoes: dados.observacoes || '',
        preco_referencia: dados.preco_referencia != null ? Number(dados.preco_referencia) : undefined,
        custo_unitario: dados.custo_unitario != null && !isNaN(Number(dados.custo_unitario)) ? Number(dados.custo_unitario) : undefined,
        estoque_minimo: dados.estoque_minimo != null && !isNaN(parseInt(dados.estoque_minimo)) ? parseInt(dados.estoque_minimo) : undefined
      },
      fotos: Array.isArray(req.body.fotos) ? req.body.fotos : [],
      solicitante_id: perfil.id, solicitante_nome: perfil.nome,
      criado_em: new Date().toISOString(),
      aprovado_por: null, aprovado_por_nome: null, aprovado_em: null, motivo_recusa: null
    };
    catalog.solicitacoes.push(sol);
    saveCatalog(catalog);
    registrarAuditoria(catalog, perfil, 'criar_solicitacao', 'solicitacao', sol.id, null, sol, req);
    return res.json({ success: true, solicitacao: sol });
  }

  // ── ALTERAÇÃO de cadastro de peça (vai para autorização; só grava depois do OK) ──
  if (tipo === 'alteracao') {
    const dados = req.body.dados || {};
    const catalog = loadCatalog();
    const peca = (catalog.pecas || []).find(p => p.id === req.body.peca_id);
    if (!peca) return res.status(404).json({ error: 'Peça não encontrada' });
    // Campos de cadastro permitidos (estoque NUNCA muda por aqui — só baixa/entrada)
    const CAMPOS_ALTERACAO = ['nome','codigo','fabricante','categoria','descricao','observacoes','veiculos_compativeis','preco_referencia','custo_unitario','estoque_minimo','pendente_analise'];
    const mudancas = {}, antes = {};
    CAMPOS_ALTERACAO.forEach(f => {
      if (dados[f] === undefined) return;
      const atual = peca[f] === undefined ? null : peca[f];
      if (JSON.stringify(dados[f]) !== JSON.stringify(atual)) { mudancas[f] = dados[f]; antes[f] = atual; }
    });
    if (!Object.keys(mudancas).length) return res.status(400).json({ error: 'Nenhuma alteração em relação ao cadastro atual.' });
    if (!catalog.solicitacoes) catalog.solicitacoes = [];
    const sol = {
      id: nextSolId(catalog), tipo: 'alteracao', status: 'pendente',
      peca_id: peca.id, peca_nome: peca.nome, peca_codigo: peca.codigo || '',
      placa: null, quantidade_solicitada: 0, quantidade_aprovada: null,
      observacao: observacao || '',
      dados: mudancas, dados_antes: antes,
      fotos: [],
      solicitante_id: perfil.id, solicitante_nome: perfil.nome,
      criado_em: new Date().toISOString(),
      aprovado_por: null, aprovado_por_nome: null, aprovado_em: null, motivo_recusa: null
    };
    catalog.solicitacoes.push(sol);
    saveCatalog(catalog);
    registrarAuditoria(catalog, perfil, 'criar_solicitacao', 'solicitacao', sol.id, null, sol, req);
    return res.json({ success: true, solicitacao: sol });
  }

  // ── CADASTRO de veículo (vai para autorização; não entra na frota ainda) ──
  if (tipo === 'veiculo') {
    const dados = req.body.dados || {};
    if (!dados.placa || !dados.modelo) return res.status(400).json({ error: 'Placa e modelo são obrigatórios' });
    const catalog = loadCatalog();
    const pl = String(dados.placa).toUpperCase().trim();
    if ((catalog.frota || []).some(v => v.placa.toUpperCase() === pl))
      return res.status(409).json({ error: 'Já existe um veículo com esta placa' });
    if (!catalog.solicitacoes) catalog.solicitacoes = [];
    const sol = {
      id: nextSolId(catalog), tipo: 'veiculo', status: 'pendente',
      peca_id: null, peca_nome: `${pl} — ${dados.modelo}`, peca_codigo: '',
      placa: pl, quantidade_solicitada: 0, quantidade_aprovada: null,
      observacao: observacao || '',
      dados: { placa: pl, modelo: String(dados.modelo).trim(), marca: (dados.marca || '').trim() },
      fotos: [],
      solicitante_id: perfil.id, solicitante_nome: perfil.nome,
      criado_em: new Date().toISOString(),
      aprovado_por: null, aprovado_por_nome: null, aprovado_em: null, motivo_recusa: null
    };
    catalog.solicitacoes.push(sol);
    saveCatalog(catalog);
    registrarAuditoria(catalog, perfil, 'criar_solicitacao', 'solicitacao', sol.id, null, sol, req);
    return res.json({ success: true, solicitacao: sol });
  }

  if (!['baixa', 'entrada'].includes(tipo)) return res.status(400).json({ error: "tipo deve ser 'baixa', 'entrada', 'cadastro', 'veiculo' ou 'alteracao'" });
  const qty = parseInt(quantidade);
  if (!Number.isInteger(qty) || qty <= 0) return res.status(400).json({ error: 'quantidade deve ser inteiro positivo' });

  const catalog = loadCatalog();
  const peca = (catalog.pecas || []).find(p => p.id === peca_id);
  if (!peca) return res.status(404).json({ error: 'Peça não encontrada' });

  if (tipo === 'baixa') {
    if (!placa) return res.status(400).json({ error: 'Veículo (placa) é obrigatório na baixa' });
    const veiculo = (catalog.frota || []).find(v => v.placa.toUpperCase() === String(placa).toUpperCase());
    if (!veiculo) return res.status(400).json({ error: 'Veículo não cadastrado na frota' });
    // valida contra o estoque atual já na criação (dá feedback cedo; revalidado na aprovação)
    if ((peca.quantidade || 0) < qty)
      return res.status(400).json({ error: `Estoque insuficiente. Disponível: ${peca.quantidade || 0}` });
  }

  if (!catalog.solicitacoes) catalog.solicitacoes = [];
  const sol = {
    id: nextSolId(catalog), tipo, status: 'pendente',
    peca_id, peca_nome: peca.nome, peca_codigo: peca.codigo || '',
    placa: tipo === 'baixa' ? String(placa).toUpperCase() : null,
    quantidade_solicitada: qty, quantidade_aprovada: null,
    observacao: observacao || '',
    fornecedor: tipo === 'entrada' ? (fornecedor || '') : null,
    custo_unitario: tipo === 'entrada' && custo_unitario != null ? Number(custo_unitario) : null,
    nota_fiscal: tipo === 'entrada' ? (nota_fiscal || '') : null,
    solicitante_id: perfil.id, solicitante_nome: perfil.nome,
    criado_em: new Date().toISOString(),          // SEMPRE do servidor
    aprovado_por: null, aprovado_por_nome: null, aprovado_em: null, motivo_recusa: null
  };
  catalog.solicitacoes.push(sol);
  saveCatalog(catalog);
  registrarAuditoria(catalog, perfil, 'criar_solicitacao', 'solicitacao', sol.id, null, sol, req);
  res.json({ success: true, solicitacao: sol });
});

// Lista solicitações. Admin vê tudo; operacao/viewer veem as próprias.
app.get('/api/solicitacoes', (req, res) => {
  const perfil = getPerfilFromReq(req);
  if (!perfil) return res.status(401).json({ error: 'não autenticado' });
  const catalog = loadCatalog();
  let arr = (catalog.solicitacoes || []).slice().reverse();
  if (perfil.papel !== 'admin') arr = arr.filter(s => s.solicitante_id === perfil.id);
  const { status, tipo } = req.query;
  if (status) arr = arr.filter(s => s.status === status);
  if (tipo)   arr = arr.filter(s => s.tipo === tipo);
  res.json({ total: arr.length, solicitacoes: arr });
});

// Contador de pendências (badge)
app.get('/api/solicitacoes/pendentes/count', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  res.json({ count: (catalog.solicitacoes || []).filter(s => s.status === 'pendente').length });
});

// APROVAR — único ponto onde o estoque se move. Serializado (sem saldo negativo).
app.post('/api/solicitacoes/:id/aprovar', ensureAdmin, (req, res) => {
  const perfil = getPerfilFromReq(req);
  serializarEscrita(() => {
    const catalog = loadCatalog();
    const sol = (catalog.solicitacoes || []).find(s => s.id === req.params.id);
    if (!sol) { res.status(404).json({ error: 'Solicitação não encontrada' }); return; }
    if (sol.status !== 'pendente') { res.status(409).json({ error: `Solicitação já ${sol.status}` }); return; }
    // Permite ajustar a quantidade na aprovação (ex.: pediram 3, saíram 2)
    let qty = sol.quantidade_solicitada;
    if (req.body.quantidade_aprovada != null) {
      qty = parseInt(req.body.quantidade_aprovada);
      if (!Number.isInteger(qty) || qty <= 0) { res.status(400).json({ error: 'quantidade_aprovada inválida' }); return; }
    }
    const antes = JSON.parse(JSON.stringify(sol));
    try {
      // ── VEÍCULO: adiciona à frota ──
      if (sol.tipo === 'veiculo') {
        const d = sol.dados || {};
        const pl = String(d.placa).toUpperCase().trim();
        if ((catalog.frota || []).some(v => v.placa.toUpperCase() === pl)) throw new Error('Já existe um veículo com esta placa');
        catalog.frota.push({ placa: pl, modelo: d.modelo, marca: d.marca || '' });
        sol.status = 'aprovada'; sol.aprovado_por = perfil.id; sol.aprovado_por_nome = perfil.nome; sol.aprovado_em = new Date().toISOString();
        saveCatalog(catalog);
        registrarAuditoria(catalog, perfil, 'aprovar_solicitacao', 'solicitacao', sol.id, antes, sol, req);
        res.json({ success: true, solicitacao: sol });
        return;
      }
      // ── ALTERAÇÃO: aplica os campos aprovados na peça ──
      if (sol.tipo === 'alteracao') {
        const idxP = catalog.pecas.findIndex(p => p.id === sol.peca_id);
        if (idxP === -1) throw new Error('Peça não existe mais no catálogo');
        const CAMPOS_ALTERACAO = ['nome','codigo','fabricante','categoria','descricao','observacoes','veiculos_compativeis','preco_referencia','custo_unitario','estoque_minimo','pendente_analise'];
        CAMPOS_ALTERACAO.forEach(f => { if (sol.dados && sol.dados[f] !== undefined) catalog.pecas[idxP][f] = sol.dados[f]; });
        sol.status = 'aprovada'; sol.aprovado_por = perfil.id; sol.aprovado_por_nome = perfil.nome; sol.aprovado_em = new Date().toISOString();
        saveCatalog(catalog);
        registrarAuditoria(catalog, perfil, 'aprovar_solicitacao', 'solicitacao', sol.id, antes, sol, req);
        res.json({ success: true, solicitacao: sol, peca: catalog.pecas[idxP] });
        return;
      }
      // ── CADASTRO: cria a peça no catálogo (estoque inicial via livro-razão) ──
      if (sol.tipo === 'cadastro') {
        const d = sol.dados || {};
        const maxNum = catalog.pecas.reduce((m, p) => { const n = parseInt(p.id); return n > m ? n : m; }, 0);
        const nova = {
          id: String(maxNum + 1).padStart(3, '0'),
          nome: d.nome, codigo: d.codigo || '', fabricante: d.fabricante || 'Não identificado',
          categoria: d.categoria, descricao: d.descricao || '',
          veiculos_compativeis: Array.isArray(d.veiculos_compativeis) ? d.veiculos_compativeis : [],
          quantidade: 0, pendente_analise: false, observacoes: d.observacoes || '',
          fotos: Array.isArray(sol.fotos) ? sol.fotos : []
        };
        if (d.preco_referencia != null) nova.preco_referencia = Number(d.preco_referencia);
        if (d.custo_unitario != null) nova.custo_unitario = Number(d.custo_unitario);
        if (d.estoque_minimo != null) nova.estoque_minimo = parseInt(d.estoque_minimo);
        catalog.pecas.push(nova);
        if (qty > 0) aplicarMovimentacao(catalog, { peca_id: nova.id, tipo: 'entrada', quantidade: qty, solicitacao_id: sol.id, usuario_id: perfil.id, custo_unitario: d.custo_unitario });
        sol.status = 'aprovada'; sol.quantidade_aprovada = qty; sol.peca_id = nova.id;
        sol.aprovado_por = perfil.id; sol.aprovado_por_nome = perfil.nome; sol.aprovado_em = new Date().toISOString();
        saveCatalog(catalog);
        registrarAuditoria(catalog, perfil, 'aprovar_solicitacao', 'solicitacao', sol.id, antes, sol, req);
        res.json({ success: true, solicitacao: sol, peca: nova, novo_saldo: nova.quantidade });
        return;
      }
      const { saldoNovo } = aplicarMovimentacao(catalog, {
        peca_id: sol.peca_id,
        tipo: sol.tipo === 'entrada' ? 'entrada' : 'saida',
        quantidade: qty, solicitacao_id: sol.id, usuario_id: perfil.id,
        custo_unitario: sol.tipo === 'entrada' ? sol.custo_unitario : null,
        placa: sol.placa || null, responsavel: sol.solicitante_nome || null,
        observacoes: sol.observacao || null
      });
      sol.status = 'aprovada';
      sol.quantidade_aprovada = qty;
      sol.aprovado_por = perfil.id; sol.aprovado_por_nome = perfil.nome;
      sol.aprovado_em = new Date().toISOString();
      saveCatalog(catalog);
      registrarAuditoria(catalog, perfil, 'aprovar_solicitacao', 'solicitacao', sol.id, antes, sol, req);
      res.json({ success: true, solicitacao: sol, novo_saldo: saldoNovo });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }).catch(e => { if (!res.headersSent) res.status(500).json({ error: e.message }); });
});

// RECUSAR — não move estoque. Motivo obrigatório.
app.post('/api/solicitacoes/:id/recusar', ensureAdmin, (req, res) => {
  const perfil = getPerfilFromReq(req);
  const motivo = (req.body.motivo || '').trim();
  if (!motivo) return res.status(400).json({ error: 'motivo é obrigatório para recusar' });
  const catalog = loadCatalog();
  const sol = (catalog.solicitacoes || []).find(s => s.id === req.params.id);
  if (!sol) return res.status(404).json({ error: 'Solicitação não encontrada' });
  if (sol.status !== 'pendente') return res.status(409).json({ error: `Solicitação já ${sol.status}` });
  const antes = JSON.parse(JSON.stringify(sol));
  sol.status = 'recusada';
  sol.motivo_recusa = motivo;
  sol.aprovado_por = perfil.id; sol.aprovado_por_nome = perfil.nome;
  sol.aprovado_em = new Date().toISOString();
  saveCatalog(catalog);
  registrarAuditoria(catalog, perfil, 'recusar_solicitacao', 'solicitacao', sol.id, antes, sol, req);
  res.json({ success: true, solicitacao: sol });
});

// ─── AUDITORIA ──────────────────────────────────────────────────────────────────
function registrarAuditoria(catalog, perfil, acao, entidade, entidade_id, antes, depois, req) {
  try {
    if (!catalog.auditoria) catalog.auditoria = [];
    catalog.auditoria.push({
      id: 'AUD' + String(catalog.auditoria.length + 1).padStart(5, '0'),
      usuario_id: perfil ? perfil.id : null, usuario_nome: perfil ? perfil.nome : null,
      acao, entidade, entidade_id, dados_antes: antes, dados_depois: depois,
      ip: req ? ((req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0]).trim() : null,
      user_agent: req ? String(req.headers['user-agent'] || '').slice(0, 200) : null,
      criado_em: new Date().toISOString()
    });
    saveCatalog(catalog);
  } catch (_) { /* auditoria nunca derruba a operação principal */ }
}
app.get('/api/auditoria', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  res.json({ total: (catalog.auditoria || []).length, auditoria: (catalog.auditoria || []).slice().reverse().slice(0, 500) });
});

// ─── RELATÓRIOS (admin) — totais por semana e por mês, em quantidade e R$ ──────
app.get('/api/relatorios', ensureAdmin, (req, res) => {
  const catalog = loadCatalog();
  const movs = todasMovimentacoes(catalog);
  // fallback de valor: movimentos antigos sem custo usam o custo atual da peça
  const custoPeca = {};
  (catalog.pecas || []).forEach(p => {
    custoPeca[p.id] = p.custo_unitario != null ? Number(p.custo_unitario)
                    : (p.preco_referencia != null ? Number(p.preco_referencia) : 0);
  });
  const valorDe = m => m.valor_total != null ? m.valor_total
    : m.quantidade * (m.custo_unitario != null ? m.custo_unitario : (custoPeca[m.peca_id] || 0));

  const hoje = new Date();
  const dia = d => d.toISOString().substring(0, 10);
  // início da semana (segunda-feira)
  function inicioSemana(d) {
    const x = new Date(d); const dow = (x.getDay() + 6) % 7;
    x.setDate(x.getDate() - dow); x.setHours(0, 0, 0, 0); return x;
  }
  const fmtDM = d => String(d.getDate()).padStart(2, '0') + '/' + String(d.getMonth() + 1).padStart(2, '0');

  function bucketVazio() { return { saidas_qtd: 0, saidas_valor: 0, entradas_qtd: 0, entradas_valor: 0 }; }
  function soma(bucket, m) {
    const v = valorDe(m);
    if (m.tipo === 'entrada') { bucket.entradas_qtd += m.quantidade; bucket.entradas_valor += v; }
    else { bucket.saidas_qtd += m.quantidade; bucket.saidas_valor += v; }
  }
  const r2 = o => { ['saidas_valor', 'entradas_valor'].forEach(k => o[k] = Math.round(o[k] * 100) / 100); return o; };

  // últimas 8 semanas e últimos 6 meses (sempre presentes, mesmo zerados)
  const semanas = [];
  for (let i = 7; i >= 0; i--) {
    const ini = inicioSemana(new Date(hoje.getTime() - i * 7 * 86400000));
    const fim = new Date(ini.getTime() + 6 * 86400000);
    semanas.push({ inicio: dia(ini), fim: dia(fim), label: fmtDM(ini) + ' a ' + fmtDM(fim), ...bucketVazio() });
  }
  const meses = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(hoje.getFullYear(), hoje.getMonth() - i, 1);
    meses.push({ mes: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`,
      label: d.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' }), ...bucketVazio() });
  }

  const topPecasMes = {}, porVeiculoMes = {};
  const mesAtual = `${hoje.getFullYear()}-${String(hoje.getMonth() + 1).padStart(2, '0')}`;
  movs.forEach(m => {
    const dataM = m.data || (m.criado_em || '').substring(0, 10);
    if (!dataM) return;
    semanas.forEach(s => { if (dataM >= s.inicio && dataM <= s.fim) soma(s, m); });
    const mesM = dataM.substring(0, 7);
    const mm = meses.find(x => x.mes === mesM);
    if (mm) soma(mm, m);
    if (m.tipo === 'saida' && mesM === mesAtual) {
      // agrupa por ID (nome pode mudar com o tempo); exibe o nome atual da peça
      const chave = m.peca_id || m.peca_nome;
      const tp = topPecasMes[chave] || (topPecasMes[chave] = { qtd: 0, valor: 0, nome: null });
      const atual = (catalog.pecas || []).find(p => p.id === m.peca_id);
      tp.nome = (atual && atual.nome) || m.peca_nome;
      tp.qtd += m.quantidade; tp.valor += valorDe(m);
      const veic = m.veiculo || 'Sem veículo';
      const pv = porVeiculoMes[veic] || (porVeiculoMes[veic] = { qtd: 0, valor: 0 });
      pv.qtd += m.quantidade; pv.valor += valorDe(m);
    }
  });
  semanas.forEach(r2); meses.forEach(r2);

  const top_pecas_mes = Object.values(topPecasMes)
    .sort((a, b) => b.valor - a.valor || b.qtd - a.qtd).slice(0, 10)
    .map(v => ({ nome: v.nome, qtd: v.qtd, valor: Math.round(v.valor * 100) / 100 }));
  const por_veiculo_mes = Object.entries(porVeiculoMes)
    .sort((a, b) => b[1].valor - a[1].valor || b[1].qtd - a[1].qtd)
    .map(([veiculo, v]) => ({ veiculo, qtd: v.qtd, valor: Math.round(v.valor * 100) / 100 }));

  res.json({
    semana_atual: semanas[semanas.length - 1],
    mes_atual: meses[meses.length - 1],
    por_semana: semanas.slice().reverse(),
    por_mes: meses.slice().reverse(),
    top_pecas_mes, por_veiculo_mes,
    gerado_em: new Date().toISOString()
  });
});

// (A antiga tela /admin foi integrada ao sistema principal — aba "Autorizações".)
// Redireciona qualquer link antigo para a home.
app.get('/admin', (req, res) => res.redirect('/'));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  seedPerfis();
  console.log(`\n✅ Servidor rodando em http://localhost:${PORT}`);
  console.log(`📦 API disponível em http://localhost:${PORT}/api/pecas\n`);
});
