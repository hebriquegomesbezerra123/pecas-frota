const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Carregar catálogo
function loadCatalog() {
  const raw = fs.readFileSync(path.join(__dirname, 'catalog.json'), 'utf-8');
  return JSON.parse(raw);
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── ROTAS DE FOTOS (public/fotos/) ──────────────────────────────────────────
app.get('/fotos/:filename', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'fotos', req.params.filename);
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'Foto não encontrada' });
  }
});

// ─── ROTA: TODAS AS PEÇAS ─────────────────────────────────────────────────────
app.get('/api/pecas', (req, res) => {
  const catalog = loadCatalog();
  let pecas = catalog.pecas;

  // Filtros opcionais
  const { categoria, veiculo, pendente, q } = req.query;

  if (categoria) {
    pecas = pecas.filter(p => p.categoria.toLowerCase() === categoria.toLowerCase());
  }
  if (veiculo) {
    pecas = pecas.filter(p =>
      p.veiculos_compativeis.some(v => v.toLowerCase().includes(veiculo.toLowerCase()))
    );
  }
  if (pendente !== undefined) {
    pecas = pecas.filter(p => p.pendente_analise === (pendente === 'true'));
  }
  if (q) {
    const term = q.toLowerCase();
    pecas = pecas.filter(p =>
      p.nome.toLowerCase().includes(term) ||
      p.descricao.toLowerCase().includes(term) ||
      p.codigo.toLowerCase().includes(term) ||
      p.fabricante.toLowerCase().includes(term)
    );
  }

  res.json({ total: pecas.length, pecas });
});

// ─── ROTA: UMA PEÇA ───────────────────────────────────────────────────────────
app.get('/api/pecas/:id', (req, res) => {
  const catalog = loadCatalog();
  const peca = catalog.pecas.find(p => p.id === req.params.id);
  if (!peca) return res.status(404).json({ error: 'Peça não encontrada' });
  res.json(peca);
});

// ─── ROTA: ATUALIZAR PEÇA (quantidade, observações) ──────────────────────────
app.put('/api/pecas/:id', (req, res) => {
  const catalogPath = path.join(__dirname, 'catalog.json');
  const catalog = loadCatalog();
  const idx = catalog.pecas.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Peça não encontrada' });

  const allowed = ['quantidade', 'observacoes', 'pendente_analise', 'nome', 'descricao', 'codigo', 'fabricante', 'veiculos_compativeis'];
  allowed.forEach(field => {
    if (req.body[field] !== undefined) {
      catalog.pecas[idx][field] = req.body[field];
    }
  });

  fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2), 'utf-8');
  res.json({ success: true, peca: catalog.pecas[idx] });
});

// ─── ROTA: FROTA ─────────────────────────────────────────────────────────────
app.get('/api/frota', (req, res) => {
  const catalog = loadCatalog();
  res.json({ total: catalog.frota.length, frota: catalog.frota });
});

// ─── ROTA: PEÇAS POR VEÍCULO ──────────────────────────────────────────────────
app.get('/api/frota/:placa/pecas', (req, res) => {
  const catalog = loadCatalog();
  const veiculo = catalog.frota.find(v => v.placa.toUpperCase() === req.params.placa.toUpperCase());
  if (!veiculo) return res.status(404).json({ error: 'Veículo não encontrado' });

  const pecas = catalog.pecas.filter(p =>
    p.veiculos_compativeis.some(v => v.includes(req.params.placa.toUpperCase()))
  );

  res.json({ veiculo, total_pecas: pecas.length, pecas });
});

// ─── ROTA: CATEGORIAS ─────────────────────────────────────────────────────────
app.get('/api/categorias', (req, res) => {
  const catalog = loadCatalog();
  const cats = [...new Set(catalog.pecas.map(p => p.categoria))].sort();
  const result = cats.map(cat => ({
    categoria: cat,
    total: catalog.pecas.filter(p => p.categoria === cat).length,
    total_unidades: catalog.pecas.filter(p => p.categoria === cat).reduce((sum, p) => sum + p.quantidade, 0)
  }));
  res.json(result);
});

// ─── ROTA: ESTATÍSTICAS ───────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  const catalog = loadCatalog();
  const pecas = catalog.pecas;

  res.json({
    total_itens: pecas.length,
    total_unidades: pecas.reduce((sum, p) => sum + p.quantidade, 0),
    pendentes_analise: pecas.filter(p => p.pendente_analise).length,
    fora_da_frota: pecas.filter(p => p.veiculos_compativeis.length === 0).length,
    por_categoria: pecas.reduce((acc, p) => {
      acc[p.categoria] = (acc[p.categoria] || 0) + p.quantidade;
      return acc;
    }, {}),
    por_fabricante: pecas.reduce((acc, p) => {
      const fab = p.fabricante.split(' ')[0];
      acc[fab] = (acc[fab] || 0) + p.quantidade;
      return acc;
    }, {})
  });
});

// ─── ROTA: CRIAR PEÇA ────────────────────────────────────────────────────────
app.post('/api/pecas', (req, res) => {
  const catalogPath = path.join(__dirname, 'catalog.json');
  const catalog = loadCatalog();
  const { nome, codigo, fabricante, categoria, descricao, veiculos_compativeis, quantidade, pendente_analise, observacoes } = req.body;
  if (!nome || !categoria) return res.status(400).json({ error: 'Nome e categoria são obrigatórios' });
  const maxNum = catalog.pecas.reduce((m, p) => { const n = parseInt(p.id); return n > m ? n : m; }, 0);
  const newPeca = {
    id: String(maxNum + 1).padStart(3, '0'),
    nome, codigo: codigo || '', fabricante: fabricante || 'Não identificado',
    categoria, descricao: descricao || '',
    veiculos_compativeis: Array.isArray(veiculos_compativeis) ? veiculos_compativeis : [],
    quantidade: parseInt(quantidade) || 0,
    pendente_analise: !!pendente_analise,
    observacoes: observacoes || '', fotos: []
  };
  catalog.pecas.push(newPeca);
  fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2), 'utf-8');
  res.json({ success: true, peca: newPeca });
});

// ─── ROTA: EXCLUIR PEÇA ───────────────────────────────────────────────────────
app.delete('/api/pecas/:id', (req, res) => {
  const catalogPath = path.join(__dirname, 'catalog.json');
  const catalog = loadCatalog();
  const idx = catalog.pecas.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Peça não encontrada' });
  catalog.pecas.splice(idx, 1);
  fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2), 'utf-8');
  res.json({ success: true });
});

// ─── ROTA: MOVIMENTAÇÕES ──────────────────────────────────────────────────────
app.get('/api/movimentacoes', (req, res) => {
  const catalog = loadCatalog();
  const movs = (catalog.movimentacoes || []).slice().reverse();
  res.json({ total: movs.length, movimentacoes: movs });
});

app.get('/api/movimentacoes/peca/:pecaId', (req, res) => {
  const catalog = loadCatalog();
  const movs = (catalog.movimentacoes || []).filter(m => m.peca_id === req.params.pecaId).slice().reverse();
  res.json({ total: movs.length, movimentacoes: movs });
});

app.post('/api/movimentacoes', (req, res) => {
  const catalogPath = path.join(__dirname, 'catalog.json');
  const catalog = loadCatalog();
  if (!catalog.movimentacoes) catalog.movimentacoes = [];
  const { peca_id, responsavel, veiculo, quantidade, data, observacoes } = req.body;
  if (!peca_id || !responsavel || !quantidade) return res.status(400).json({ error: 'peca_id, responsavel e quantidade são obrigatórios' });
  const pecaIdx = catalog.pecas.findIndex(p => p.id === peca_id);
  if (pecaIdx === -1) return res.status(404).json({ error: 'Peça não encontrada' });
  const peca = catalog.pecas[pecaIdx];
  const qty = parseInt(quantidade);
  if (peca.quantidade < qty) return res.status(400).json({ error: `Estoque insuficiente. Disponível: ${peca.quantidade}` });
  const mov = {
    id: 'MOV' + String(catalog.movimentacoes.length + 1).padStart(4, '0'),
    peca_id, peca_nome: peca.nome, peca_codigo: peca.codigo,
    responsavel, veiculo: veiculo || '', quantidade: qty,
    data: data || new Date().toISOString().split('T')[0],
    observacoes: observacoes || '', criado_em: new Date().toISOString()
  };
  catalog.movimentacoes.push(mov);
  catalog.pecas[pecaIdx].quantidade -= qty;
  fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2), 'utf-8');
  res.json({ success: true, movimentacao: mov, nova_quantidade: catalog.pecas[pecaIdx].quantidade });
});

// ─── ROTA: PREÇO MERCADO LIVRE ────────────────────────────────────────────────
app.get('/api/preco/:id', async (req, res) => {
  try {
    const catalog = loadCatalog();
    const peca = catalog.pecas.find(p => p.id === req.params.id);
    if (!peca) return res.status(404).json({ error: 'Peça não encontrada' });
    const q = encodeURIComponent([peca.nome, peca.codigo, peca.fabricante].filter(Boolean).join(' ').substring(0, 80));
    const url = `https://api.mercadolibre.com/sites/MLB/search?q=${q}&limit=10`;
    const response = await fetch(url);
    const data = await response.json();
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

// ─── FALLBACK → index.html ────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n✅ Servidor rodando em http://localhost:${PORT}`);
  console.log(`📦 API de Peças disponível em http://localhost:${PORT}/api/pecas`);
  console.log(`🚛 Frota disponível em http://localhost:${PORT}/api/frota\n`);
});
