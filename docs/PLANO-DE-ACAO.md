# Plano de ação

Três frentes, independentes entre si. A frente 2 já foi implementada; restam a 1 e a 3.

---

## 1. Processamento em lote de arquivos de chaveiro

**Objetivo.** Ler um export de chaveiro existente (KeePassXC, Bitwarden, …), percorrer entrada
por entrada, propor um nome de contexto a partir da URL, gerar a senha nova sob o padrão atual
e escrever um arquivo novo — com confirmação individual a cada entrada.

Decisões de arquitetura em [ADR-0005](adr/0005-processamento-em-lote-de-chaveiros.md).

### 1.1 Leitura de chaveiros (`storage.py`)

`EXPORT_FORMATS` (storage.py:12) hoje só sabe **escrever**: tem `header` e um lambda `row`.
Falta o mapa inverso. Estender cada entrada com um dicionário `fields` que liga os nomes
canônicos às colunas daquele formato:

```python
"keepassxc": {
    "filename_prefix": "keepassxc",
    "header": ["Title", "Username", "Password", "URL", "Notes"],
    "row": lambda name, url, username, pwd: [name, username, pwd, url, ""],
    "fields": {"name": "Title", "username": "Username", "password": "Password", "url": "URL"},
},
```

Os sete formatos precisam do `fields`. Note que `firefox` não tem coluna de título — o nome
canônico deve cair para a URL nesse caso.

Funções novas:

- `detect_vault_format(header_row)` — compara o cabeçalho lido com o `header` de cada formato.
  Os sete cabeçalhos são textualmente distintos (`Title` vs `Name` vs `title` vs `name`), então
  a detecção é inequívoca. Retorna `None` se nada casar.
- `read_vault_csv(path, vault_format=None)` — usa `csv.DictReader`; se `vault_format` for
  `None`, chama `detect_vault_format`. Devolve uma lista de dicts canônicos
  `{"name", "url", "username", "password"}`. Reaproveita o `csv` já importado.
- `suggest_context_from_url(url, fallback_name)` — remove esquema, `www.` e caminho, ficando
  com o host; cai para `fallback_name` quando a URL é vazia ou inválida. É a sugestão que o
  usuário aceita com Enter ou reescreve.

`write_export_csv` já existe (storage.py:805) e é reaproveitado na escrita.

### 1.2 Pipeline interativo (`main.py`)

Flags novas:

| Flag | Função |
|---|---|
| `--vault-in CAMINHO` | Arquivo de chaveiro a processar |
| `--vault-out CAMINHO` | Arquivo a gerar (obrigatório; nunca sobrescreve a entrada) |
| `--vault-format NOME` | Força o formato de entrada, desligando a autodetecção |
| `-o/--output` | Já existe; define o formato de **saída** (pode diferir do de entrada) |

Fluxo:

1. **Segredos primeiro, uma única vez.** Senha-mestra via `get_master_password` e segredo
   temporal via `getpass` (não `input`, ao contrário do fluxo comum — em lote o segredo fica
   muito tempo na tela). Se vierem por `--master-pass`/`-T`, disparar
   `storage.print_command_line_warning()`, que já existe.
2. Para cada entrada: exibir Título / URL / Usuário e a sugestão de contexto.
3. Ler a decisão: Enter aceita a sugestão, texto novo substitui, `s` pula a entrada
   preservando a senha antiga, `q` interrompe e grava o que já foi feito.
4. Gerar a senha com `crypto.generate_password('v2', ...)` e os flags atuais; exibir; confirmar.
5. Ao confirmar, registrar via `storage.build_and_log_line` (storage.py:763) — assim a entrada
   passa a existir no log e fica visível para a frente 3.
6. Ao final, `write_export_csv` para o formato de saída.

### 1.3 Segurança do arquivo gerado

Todo formato de chaveiro é CSV com senhas em texto puro. Ao terminar, imprimir aviso
explícito: importar no chaveiro e **apagar o arquivo**. Criar com `os.open(..., 0o600)` em vez
de `open()` puro.

### 1.4 Testes

- Round-trip por formato: escrever com `write_export_csv`, ler com `read_vault_csv`, comparar.
- `detect_vault_format` acerta os 7 e devolve `None` para cabeçalho desconhecido.
- `suggest_context_from_url` para `https://www.site.com/login?x=1` → `site.com`; URL vazia →
  fallback; URL inválida → fallback.
- Pipeline ponta a ponta com entradas mockadas, cobrindo aceitar / editar / pular / interromper.
- Senha-mestra e temporal são pedidos **uma vez só**, mesmo com N entradas.
- Arquivo de saída nasce com modo `0600`.
- O arquivo de entrada nunca é modificado.

---

## 2. `--view-log` com logs de formato misto — ✅ CONCLUÍDO

**Estado verificado (antes da correção).** Funciona em log 100% cifrado e em log 100% texto puro. **Quebra em log
misto**, que surge naturalmente ao usar `--plain-log` uma vez e voltar ao padrão:

| Ordem | Sintoma |
|---|---|
| texto puro → cifrado | `UnicodeDecodeError`, traceback, **log inteiro perdido** |
| cifrado → texto puro | **perda silenciosa**: 2 registros gravados, 1 exibido |

A segunda é a pior: não há erro, só ausência.

**Causa.** `storage.read_logs_from_file` (storage.py:725) escolhe o formato olhando **só os 14
primeiros bytes do arquivo** e depois trata o arquivo inteiro como daquele tipo.

**Correção.** Decidir o formato **por registro**, não por arquivo. Percorrer o buffer:

- se os próximos 14 bytes forem dígitos ASCII → linha de texto puro, ler até `\n`;
- caso contrário → bloco cifrado, ler prefixo de 4 bytes + payload.

O discriminador continua válido registro a registro: o prefixo de comprimento de um bloco
cifrado começa em `\x00\x00\x00` para qualquer payload realista, e nunca é dígito ASCII. Esse é
exatamente o argumento já registrado no docstring da função — ele só não estava sendo aplicado
por registro.

Decisões em [ADR-0006](adr/0006-formato-do-log-e-deteccao-por-registro.md).

**Testes.** Log só cifrado; log só texto puro; misto nas duas ordens; log vazio; log truncado
no meio de um bloco (não pode levantar exceção); senha-mestra errada devolve lista vazia sem
estourar.

---

## 3. Verificação de senha contra o log

**O que existe.** `--audit` (main.py:459) responde "existe registro para este contexto?", via
`storage.find_in_log`. Ele **não** verifica a senha e devolve todas as ocorrências, sem noção
de qual é a mais recente.

**O que falta** é o que você descreveu: pedir os fatores, regenerar a senha e comparar com a
**última modificação documentada** daquele sistema, varrendo o log de baixo para cima.

Decisões e limites em [ADR-0007](adr/0007-verificacao-de-senha-contra-o-log.md).

### 3.1 `storage.py`

`find_last_entry(app_summary, temporal_salt, master_hash=None)` — varre `read_logs_from_file`
**de trás para frente** e devolve o primeiro casamento como dict de campos já parseados
(`date`, `len`, `feat`, `pwd`, `changed`), ou `None`. Compartilha o parser de tokens com
`find_last_features` (storage.py:860), que hoje duplica essa lógica — extrair
`_parse_log_tokens(line)` e usar nos dois.

### 3.2 `main.py`

Flag `--verify`. Fluxo:

1. Pedir contexto e segredo temporal com `getpass` (ocultos), no mesmo padrão do `--audit`
   interativo — não deixa rastro no histórico do shell.
2. `find_last_entry` para achar o último registro daquele contexto.
3. Regenerar a senha usando `len`/`feat` **do próprio registro**, não os flags da linha de
   comando. Sem isso a comparação falharia sempre que o padrão default tivesse mudado.
4. Comparar `crypto.summarize_password_hash(senha)` com o campo `pwd:` do registro.

Três desfechos, distintos e explícitos:

| Desfecho | Significado |
|---|---|
| Sem registro | Nunca gerada, ou gerada com `-w` (log desligado). **Não** é "senha errada" |
| Registro + confere | A senha atual reproduz a última modificação documentada |
| Registro + diverge | Algum fator mudou desde então (senha-mestra, temporal ou contexto) |

Exibir data do registro e se ele traz o marcador ` C` (modo troca).

### 3.3 Testes

- Confere após gerar; diverge com senha-mestra errada; diverge com temporal errado.
- Com várias entradas para o mesmo contexto, retorna a **última** (ordem cronológica do log).
- Ausência de registro é reportada como ausência, não como divergência.
- Regeneração usa `len`/`feat` do registro, não os defaults — teste com flags divergentes.
- Funciona com log cifrado e com log em texto puro (depende da frente 2).

---

## Verificação geral

```bash
cd /home/janio/Documentos/Pessoais/Code/Passweird
python -m pytest tests/ -v
python -m pytest tests/ -v -m "not slow"

# frente 2, o caso que hoje quebra
python main.py site-a -T ""
python main.py site-b -T "" --plain-log
python main.py --view-log          # precisa listar as duas entradas

# frente 1, ponta a ponta
python main.py --vault-in ~/keepass-export.csv --vault-out /tmp/novo.csv -o keepassxc
ls -l /tmp/novo.csv                # precisa nascer 0600

# frente 3
python main.py --verify
```
