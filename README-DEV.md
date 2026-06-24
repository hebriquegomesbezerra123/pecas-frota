# Guia do Desenvolvedor — Controle de Peças (Frota)

Documento técnico para quem vai adicionar funcionalidades ao sistema.

## Stack

- **Backend:** Node.js + Express. Arquivo único [`server.js`](server.js). Sem framework extra, sem build.
- **Frontend:** SPA com Bootstrap 5.3. Tudo num só arquivo [`public/index.html`](public/index.html) (HTML + CSS + JS vanilla inline). Sem React, sem bundler.
- **Dados:** flat-file JSON em `catalog.json`. Sem banco SQL.
- **Upload:** Multer (fotos em disco).
- **IA:** Google Gemini (`gemini-2.5-flash`) para autopreencher peça a partir de foto.
- **Deploy:** Railway, auto-deploy ao dar push na branch `master`.

## Rodando local

```bash
npm install
npm start          # porta 3000 → http://localhost:3000
```

Login padrão local: usuário `Administrador`, senha `pecas2026`.

Para testar a IA localmente, crie um arquivo `.env` na raiz com sua própria chave Gemini:

```
GEMINI_API_KEY=sua_chave_aqui
```

> `.env` está no `.gitignore` — nunca comitar chaves.

## Estrutura do projeto

```
server.js          # toda a API + auth + login + Gemini
public/index.html  # toda a interface (SPA)
public/fotos/      # fotos seed
catalog.json       # dados seed (ver "Persistência" abaixo)
railway.toml       # config de deploy
```

## Persistência — LEIA ANTES DE MEXER

- Em produção, os dados ficam em um **volume do Railway** montado em `/data` (variável `DATA_DIR=/data`).
- `catalog.json` e as fotos vivem **no volume**, não no repositório.
- O `catalog.json` do repo é apenas **seed**: no primeiro boot com volume vazio, o servidor copia ele para `/data` (ver função `seedVolume()` em `server.js`).
- **Não comite dados reais** no `catalog.json`. Trate-o como estrutura/seed.

Formato do `catalog.json`:

```json
{
  "frota": [ { "placa": "...", "modelo": "...", "marca": "..." } ],
  "pecas": [ { "id": "001", "nome": "...", "categoria": "...", "quantidade": 0, "veiculos_compativeis": [], "fotos": [] } ],
  "movimentacoes": [ { "id": "MOV0001", "peca_id": "...", "responsavel": "...", "quantidade": 1, "data": "YYYY-MM-DD" } ],
  "perfis": [ { "id": "prf001", "nome": "...", "papel": "admin|operador", "senha": "...", "ativo": true } ]
}
```

## Como adicionar uma ferramenta

### Backend (nova rota)

Em `server.js`, siga o padrão das rotas existentes. Helpers prontos:

```js
const catalog = loadCatalog();      // lê catalog.json
// ...mexe no catalog...
saveCatalog(catalog);               // grava de volta
```

Exemplo:

```js
app.get('/api/minha-ferramenta', (req, res) => {
  const catalog = loadCatalog();
  res.json({ ok: true, total: catalog.pecas.length });
});
```

### Autenticação

- Todas as rotas `/api/*` já exigem sessão válida (middleware global). Não precisa repetir login.
- Para restringir a **admin**, use o middleware pronto:

```js
app.post('/api/algo-sensivel', ensureAdmin, (req, res) => { ... });
```

- Para saber quem é o usuário atual dentro da rota:

```js
const perfil = getPerfilFromReq(req);   // { id, nome, papel } ou null
if (perfil?.papel === 'admin') { ... }
```

### Frontend (nova view)

Em `public/index.html`:

1. Adicione o bloco HTML da view dentro de `<main>` com `id="viewXxx" style="display:none"`.
2. Inclua `'xxx'` no array `VIEWS` e o rótulo em `VIEW_LABELS`.
3. Trate o carregamento em `setView()` (`if (v==='xxx') loadXxx();`).
4. Adicione o link na sidebar seguindo o padrão dos itens existentes (`<li>` + `onclick="setView('xxx')"`).

Para chamar a API use `fetch('/api/...')` normal — o cookie de sessão vai junto.

## Perfis de acesso

Dois papéis:

| Papel | Permissões |
|-------|------------|
| `admin` | Acesso total: excluir peças, gerenciar perfis |
| `operador` | Consulta, cadastro e baixa de peças. Não exclui peças nem gerencia perfis |

## Convenções

- Português nos textos de UI e mensagens.
- IDs de peça: string com zero à esquerda (`"001"`). Movimentações: `MOV0001`. Perfis: `prf001`.
- Mantenha o estilo do código existente (vanilla, sem dependências novas a menos que necessário).
- Deploy é automático no push para `master` — teste local antes.
