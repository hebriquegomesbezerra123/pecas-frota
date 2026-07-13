# Bolsão Peças — V3 (Portal de Autorização)

Camada nova **por cima** do sistema existente. Não reescreve nada: reaproveita o
mesmo `catalog.json`, a mesma autenticação por cookie e as peças/frota já cadastradas.

## O que esta etapa entregou

**O coração da V3: nada mexe no estoque sem a sua autorização.**

- Toda **baixa** (saída) e **entrada** de peça nasce como uma *solicitação* `pendente`.
  O estoque **não muda** enquanto está pendente.
- O admin autoriza no painel **`/admin`** → só aí o estoque se move.
- Novos papéis: `admin` (autoriza tudo), `operacao` (registra, vai pra fila), `viewer` (só lê).
- Criação de logins pelo próprio painel (sem autocadastro).
- Livro-razão imutável (`movimentacoes_estoque`) + auditoria de tudo (`auditoria`).

### Tudo dentro do MESMO sistema (index.html) — não há tela separada
- O sistema de sempre continua: dashboard, peças, fotos, veículos, movimentações.
- **Permissão por papel**, aplicada no próprio catálogo:
  - `admin` (você): vê tudo, cadastra/edita/exclui peça, dá baixa/entrada direta, e tem a aba **Autorizações**.
  - `operacao`: vê o catálogo/estoque/veículos e registra **baixa** e **entrada** — que vão pra sua fila. Não cadastra nem edita.
  - `viewer`: só visualiza.
- **Baixa** (operador): abre a peça → "Dar Baixa" → responsável já vem travado do login,
  escolhe o veículo da frota, quantidade e observação (o que trocou). Vira pendência.
- **Entrada** (operador): botão "Entrada" na peça → quantidade, fornecedor, NF, custo, obs. Vira pendência.
- **Aba Autorizações** (só admin): cards com quem pediu, veículo/fornecedor, quantidade, obs e
  **estoque atual**. Botões: Autorizar / Ajustar / Recusar (motivo). Badge com contador no menu.
- **QR de Acesso** (botão na aba Autorizações): gera o QR do `/login` e imprime em A4 com o
  cabeçalho da empresa, pra colar no almoxarifado. O operador escaneia e entra com login/senha.

## Mudanças no banco (`catalog.json`) — todas aditivas, nada removido

| Chave | Novo? | Conteúdo |
|-------|-------|----------|
| `solicitacoes` | novo | fila de baixas/entradas (pendente/aprovada/recusada) |
| `movimentacoes_estoque` | novo | livro-razão: só recebe linha quando o admin aprova |
| `auditoria` | novo | quem fez o quê, quando, antes/depois, IP |
| `pecas[].estoque_minimo`, `foto_url`, `codigo_fornecedor` | opcionais | criados sob demanda |
| `perfis[].papel` | valores | `operador` é lido como `operacao` (retrocompat) |

As tabelas antigas (`frota`, `pecas`, `movimentacoes`, `perfis`) **não foram alteradas na estrutura**.

## Novas rotas (backend)

| Método | Rota | Quem | O quê |
|--------|------|------|-------|
| POST | `/api/solicitacoes` | operacao/admin | cria baixa ou entrada (pendente, não move estoque) |
| GET | `/api/solicitacoes` | logado | lista (admin vê tudo; demais veem as próprias) |
| GET | `/api/solicitacoes/pendentes/count` | admin | contador do badge |
| POST | `/api/solicitacoes/:id/aprovar` | admin | **move o estoque** (serializado); aceita `quantidade_aprovada` |
| POST | `/api/solicitacoes/:id/recusar` | admin | recusa; `motivo` obrigatório; não move estoque |
| GET | `/api/auditoria` | admin | últimos 500 eventos |
| GET | `/admin` | admin | serve o painel |

**Bloqueios adicionados:** `POST /api/movimentacoes` agora exige admin; `PUT /api/pecas`
não deixa mais alterar `quantidade` sem ser admin (estoque só via aprovação).

## Como rodar local

```bash
npm install
# opcional: DATA_DIR isolado p/ teste; PECAS_SENHA define a senha do admin semeado
DATA_DIR=./_teste PORT=3100 PECAS_SENHA=teste123 node server.js
# admin: usuário "Administrador", senha = PECAS_SENHA
```

Sem `perfis` no catálogo, o servidor semeia um admin com a senha `PECAS_SENHA`.

## Variáveis de ambiente (nenhuma nova obrigatória)

Reaproveita as existentes: `PORT`, `DATA_DIR`, `PORTAL_SECRET`, `PECAS_SENHA`, `PORTAL_URL`, `GEMINI_API_KEY`.

## Testado (Seção 8 do prompt) — todos passando

- ✅ baixa pendente não altera estoque
- ✅ aprovação reduz o estoque exatamente na quantidade aprovada
- ✅ recusa não altera o estoque
- ✅ operacao recebe 403 em rotas de admin (fila/aprovar)
- ✅ baixa maior que o estoque é bloqueada no backend
- ✅ usuário desativado não loga, mas o histórico dele continua visível
- ✅ duas aprovações simultâneas da mesma peça não geram saldo negativo (fila serializada)
- ✅ saldo de cada peça bate com o livro-razão

## O que ainda falta (próximas etapas)

- Lista de compras (`lista_compras`) + sugestão automática por estoque mínimo.
- Relatórios (por período/peça/veículo/pessoa) e exportação PDF/Excel.
- Aviso push no celular do admin para novas pendências (hoje há badge + polling).
- Tela do operador para acompanhar o status das próprias solicitações (hoje vê no toast).

## O que pode dar errado

- **Persistência em JSON**: escolhida a fila serializada em memória (mutex) — segura para o
  volume atual (poucas operações/dia). Se o uso crescer muito, migrar estoque para SQLite.
- **Deploy Railway**: o `catalog.json` do volume em produção **não tem** as chaves novas ainda;
  elas são criadas sozinhas na 1ª solicitação/aprovação. Fazer backup do volume antes de subir.
