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

// ─── FALLBACK → index.html ────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n✅ Servidor rodando em http://localhost:${PORT}`);
  console.log(`📦 API de Peças disponível em http://localhost:${PORT}/api/pecas`);
  console.log(`🚛 Frota disponível em http://localhost:${PORT}/api/frota\n`);
});
