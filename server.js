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
  fs.writeFileSync(CATALOG_PATH, JSON.stringify(catalog, null, 2), 'utf-8');
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
  return (p && p.ativo) ? { id: p.id, nome: p.nome, papel: p.papel } : null;
}
function ensureAdmin(req, res, next) {
  const p = getPerfilFromReq(req);
  if (!p || p.papel !== 'admin')
    return res.status(403).json({ error: 'Permissão negada. Apenas administradores.' });
  next();
}
function seedPerfis() {
  const catalog = loadCatalog();
  if (catalog.perfis && catalog.perfis.length > 0) return;
  if (!catalog.perfis) catalog.perfis = [];
  catalog.perfis.push({
    id: 'prf001', nome: 'Administrador', papel: 'admin',
    senha: PECAS_SENHA, ativo: true, criado_em: new Date().toISOString()
  });
  saveCatalog(catalog);
  console.log('✅ Perfil administrador criado com a senha padrão (PECAS_SENHA)');
}
function getCookie(req, nome) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + nome + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
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
const _ROTAS_PUBLICAS = ['/health', '/portal-auth', '/login', '/logout'];
app.use((req, res, next) => {
  if (_ROTAS_PUBLICAS.includes(req.path)) return next();
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

app.post('/api/pecas', (req, res) => {
  const catalog = loadCatalog();
  const { nome, codigo, fabricante, categoria, descricao, veiculos_compativeis, quantidade, pendente_analise, observacoes } = req.body;
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
  catalog.pecas.push(peca);
  saveCatalog(catalog);
  res.json({ success: true, peca });
});

app.put('/api/pecas/:id', (req, res) => {
  const catalog = loadCatalog();
  const idx = catalog.pecas.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Peça não encontrada' });
  const allowed = ['quantidade','observacoes','pendente_analise','nome','descricao','codigo','fabricante','categoria','veiculos_compativeis','preco_referencia'];
  allowed.forEach(f => { if (req.body[f] !== undefined) catalog.pecas[idx][f] = req.body[f]; });
  saveCatalog(catalog);
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

app.get('/api/frota/:placa/pecas', (req, res) => {
  const catalog = loadCatalog();
  const veiculo = catalog.frota.find(v => v.placa.toUpperCase() === req.params.placa.toUpperCase());
  if (!veiculo) return res.status(404).json({ error: 'Veículo não encontrado' });
  const pecas = catalog.pecas.filter(p => p.veiculos_compativeis.some(v => v.includes(req.params.placa.toUpperCase())));
  res.json({ veiculo, total_pecas: pecas.length, pecas });
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
  const movs  = catalog.movimentacoes || [];
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
  res.json({ total: (catalog.movimentacoes||[]).length, movimentacoes: (catalog.movimentacoes||[]).slice().reverse() });
});

app.get('/api/movimentacoes/peca/:pecaId', (req, res) => {
  const catalog = loadCatalog();
  const movs = (catalog.movimentacoes||[]).filter(m => m.peca_id === req.params.pecaId).slice().reverse();
  res.json({ total: movs.length, movimentacoes: movs });
});

app.post('/api/movimentacoes', (req, res) => {
  const catalog = loadCatalog();
  if (!catalog.movimentacoes) catalog.movimentacoes = [];
  const { peca_id, responsavel, veiculo, quantidade, data, observacoes } = req.body;
  if (!peca_id || !responsavel || !quantidade) return res.status(400).json({ error: 'peca_id, responsavel e quantidade são obrigatórios' });
  const idx = catalog.pecas.findIndex(p => p.id === peca_id);
  if (idx === -1) return res.status(404).json({ error: 'Peça não encontrada' });
  const peca = catalog.pecas[idx];
  const qty  = parseInt(quantidade);
  if (peca.quantidade < qty) return res.status(400).json({ error: `Estoque insuficiente. Disponível: ${peca.quantidade}` });
  const mov = {
    id: 'MOV' + String(catalog.movimentacoes.length + 1).padStart(4, '0'),
    peca_id, peca_nome: peca.nome, peca_codigo: peca.codigo,
    responsavel, veiculo: veiculo || '', quantidade: qty,
    data: data || new Date().toISOString().split('T')[0],
    observacoes: observacoes || '', criado_em: new Date().toISOString()
  };
  catalog.movimentacoes.push(mov);
  catalog.pecas[idx].quantidade -= qty;
  saveCatalog(catalog);
  res.json({ success: true, movimentacao: mov, nova_quantidade: catalog.pecas[idx].quantidade });
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
  if (!['admin', 'operador'].includes(papel)) return res.status(400).json({ error: 'papel inválido' });
  const catalog = loadCatalog();
  if (!catalog.perfis) catalog.perfis = [];
  if (catalog.perfis.some(p => p.nome.toLowerCase() === nome.toLowerCase()))
    return res.status(409).json({ error: 'Já existe um perfil com este nome' });
  const maxNum = catalog.perfis.reduce((m, p) => {
    const n = parseInt(p.id.replace('prf', '')); return (n > m ? n : m);
  }, 0);
  const perfil = {
    id: 'prf' + String(maxNum + 1).padStart(3, '0'),
    nome, papel, senha, ativo: true, criado_em: new Date().toISOString()
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
  if (papel && ['admin', 'operador'].includes(papel)) catalog.perfis[idx].papel = papel;
  if (senha) catalog.perfis[idx].senha = senha;
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
app.post('/api/analisar-foto', upload.single('foto'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhuma foto enviada' });
  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    fs.unlinkSync(req.file.path);
    return res.status(503).json({ error: 'GEMINI_API_KEY não configurada no servidor' });
  }
  try {
    const catalog = loadCatalog();
    const modelos = [...new Set(catalog.frota.map(v => v.modelo))].sort().join(', ');
    const base64 = fs.readFileSync(req.file.path).toString('base64');
    const mime   = req.file.mimetype || 'image/jpeg';
    fs.unlinkSync(req.file.path);

    const prompt = `Analise a imagem desta peça automotiva e retorne SOMENTE um objeto JSON puro, sem nenhum texto antes ou depois, sem blocos de código markdown.

Formato exato (substitua os valores):
{"nome":"nome técnico da peça","codigo":"referência visível ou vazio","fabricante":"marca ou Não identificado","categoria":"uma das categorias abaixo","descricao":"descrição técnica em 1-2 frases","preco_estimado":0,"veiculos_sugeridos":["modelo1","modelo2"]}

Categorias válidas (use exatamente uma): Filtros | Freios | Motor | Embreagem | Suspensão e Fixação | Carroceria | Elétrica e Eletrônica

Frota disponível para veiculos_sugeridos: ${modelos}

Responda APENAS com o JSON. Nenhum outro texto.`;

    const result = await httpsPost(
      `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${key}`,
      {
        contents: [{ parts: [{ text: prompt }, { inline_data: { mime_type: mime, data: base64 } }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 8192 }
      }
    );

    // Verifica erro na API do Gemini
    if (result?.error) return res.status(502).json({ error: `Gemini API: ${result.error.message || JSON.stringify(result.error)}` });

    const text = result?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const finishReason = result?.candidates?.[0]?.finishReason || '';
    if (!text) return res.status(422).json({ error: `Gemini não gerou texto (finishReason: ${finishReason})`, result: JSON.stringify(result).substring(0, 400) });

    // Extrai bloco JSON mesmo que venha dentro de markdown ou com texto ao redor
    let parsed;
    const attempts = [
      () => JSON.parse(text.trim()),
      () => JSON.parse(text.replace(/```json\s*/gi, '').replace(/```/g, '').trim()),
      () => { const m = text.match(/\{[\s\S]*\}/); if (m) return JSON.parse(m[0]); throw new Error('no match'); }
    ];
    for (const fn of attempts) { try { parsed = fn(); break; } catch(e) {} }
    if (!parsed) return res.status(422).json({ error: 'IA não retornou JSON válido', raw: text.substring(0, 500) });

    res.json({ success: true, dados: parsed });
  } catch(e) {
    try { if (req.file) fs.unlinkSync(req.file.path); } catch(_) {}
    res.status(500).json({ error: e.message });
  }
});

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

function _paginaLogin(erro) {
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
    ${erro ? '<div class="erro">Senha incorreta.</div>' : ''}
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
  const { nome, senha } = req.body;
  const catalog = loadCatalog();
  const perfis  = catalog.perfis || [];

  // Sem perfis cadastrados → fallback senha única (legado)
  if (!perfis.length) {
    if ((senha || '') === PECAS_SENHA) {
      res.setHeader('Set-Cookie',
        `pecas_auth=${gerarAuthCookie('_legacy_admin')}; HttpOnly; Path=/; Max-Age=28800; SameSite=Lax`);
      return res.redirect('/');
    }
    return res.status(401).send(_paginaLogin(true));
  }

  const perfil = perfis.find(p =>
    p.nome.toLowerCase() === (nome || '').trim().toLowerCase() &&
    p.senha === senha && p.ativo
  );
  if (!perfil) return res.status(401).send(_paginaLogin(true));

  res.setHeader('Set-Cookie',
    `pecas_auth=${gerarAuthCookie(perfil.id)}; HttpOnly; Path=/; Max-Age=28800; SameSite=Lax`);
  res.redirect('/');
});

// ─── FALLBACK ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  seedPerfis();
  console.log(`\n✅ Servidor rodando em http://localhost:${PORT}`);
  console.log(`📦 API disponível em http://localhost:${PORT}/api/pecas\n`);
});
