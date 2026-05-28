require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');
const https   = require('https');
const multer  = require('multer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Multer (upload de fotos) ─────────────────────────────────────────────────
const fotosDir = path.join(__dirname, 'public', 'fotos');
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
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'catalog.json'), 'utf-8'));
}
function saveCatalog(catalog) {
  fs.writeFileSync(path.join(__dirname, 'catalog.json'), JSON.stringify(catalog, null, 2), 'utf-8');
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

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
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
  const allowed = ['quantidade','observacoes','pendente_analise','nome','descricao','codigo','fabricante','veiculos_compativeis','preco_referencia'];
  allowed.forEach(f => { if (req.body[f] !== undefined) catalog.pecas[idx][f] = req.body[f]; });
  saveCatalog(catalog);
  res.json({ success: true, peca: catalog.pecas[idx] });
});

app.delete('/api/pecas/:id', (req, res) => {
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
        generationConfig: { temperature: 0.1, maxOutputTokens: 2048 },
        thinkingConfig: { thinkingBudget: 0 }
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

// ─── FALLBACK ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n✅ Servidor rodando em http://localhost:${PORT}`);
  console.log(`📦 API disponível em http://localhost:${PORT}/api/pecas\n`);
});
