# Plano — sobrescrever `github.com/janiocarlosvieira/passweird`

## O que existe hoje no remoto (auditado)

Cloneei o repositório numa área descartável e inspecionei antes de propor qualquer coisa:

| | |
|---|---|
| Visibilidade | **pública** |
| Criado / último push | 2025-09-16 (um único dia de atividade) |
| Histórico | **1 commit** — `5e17bb1 "versao inicial"` |
| Conteúdo | **1 arquivo** — `passweird.py`, 527 linhas (a versão monolítica antiga) |
| Branch padrão | **`master`** |
| Stars / forks | **0 / 0** |
| Issues / PRs / releases | nenhum |
| Licença detectada | nenhuma |
| Descrição / topics | vazios |

**Varredura de segredos no histórico remoto: limpo.** A única ocorrência que casou com o padrão
de busca foi `password = ''.join(...)` — linha de código, não credencial.

Consequências disso: ninguém depende do repositório (0 forks, 0 clones conhecidos), não há
issues ou PRs a preservar, e não há segredo exposto que exija remoção definitiva.

## A decisão que precisa ser sua

`git push --force` **não apaga** o commit antigo do GitHub. O objeto `5e17bb1` continua
alcançável por SHA via web e API por tempo indeterminado. Como não há segredo ali, isso é
inofensivo — mas define duas rotas diferentes:

| Rota | O que acontece com a versão antiga | Quando escolher |
|---|---|---|
| **A — force-push** (recomendada) | Some da listagem, mas continua recuperável por SHA | Quando não há segredo a apagar. É o caso. |
| **B — apagar e recriar o repo** | Desaparece de verdade | Só se houvesse segredo exposto. Perde a data de criação e a URL fica brevemente 404. |

Há ainda uma variante da rota A que custa um comando e evita perda:

> **A+ — preservar a versão antiga numa tag** (`v0-legacy`) antes de sobrescrever. O
> `passweird.py` monolítico deixa de estar no `master` mas fica citável e navegável. Recomendo:
> é a origem do projeto e o custo é uma linha.

## Passos propostos (rota A+)

### 1. Conferências antes de qualquer push

```bash
cd /home/janio/Documentos/Pessoais/Code/Passweird
python3 -m pytest tests/ -q                  # 134 devem passar
git status --short                           # árvore precisa estar limpa
git ls-files | wc -l                         # 23 arquivos rastreados
git ls-files | grep -Ei '\.(csv|key|pem|cred|asc)$|passweird/|id_rsa|id_ed25519' \
  && echo "ABORTAR" || echo "sem material sensível rastreado"
```

O último comando é a trava: nada com extensão de segredo pode estar rastreado. Já rodei essa
verificação e ela passa, mas ela é barata e deve rodar de novo imediatamente antes do push.

### 2. Preservar a versão antiga numa tag

```bash
git remote add origin https://github.com/janiocarlosvieira/passweird.git
git fetch origin master                                   # traz o commit antigo
git tag -a v0-legacy origin/master -m "Versão monolítica original (passweird.py), set/2025"
```

A tag aponta para uma história sem relação com a nova — o Git aceita isso sem problema.

### 3. Sobrescrever o `master` remoto

```bash
git push --force origin main:master        # os 4 commits novos assumem o master
git push origin v0-legacy                  # publica a tag da versão antiga
```

Usar `main:master` no primeiro push evita ficar com dois branches durante a transição.

### 4. Adotar `main` como branch padrão

```bash
git push origin main                                    # cria o branch main
gh repo edit janiocarlosvieira/passweird --default-branch main
git push origin --delete master                         # só depois de trocar o padrão
git branch --set-upstream-to=origin/main main
```

Ordem importa: o GitHub recusa apagar o branch que é o padrão.

### 5. Metadados do repositório

```bash
gh repo edit janiocarlosvieira/passweird \
  --description "Gerador determinístico e stateless de senhas, chaves SSH/SSL/RSA, TOTP e PGP — nada é armazenado, tudo é recomputado" \
  --add-topic password-generator --add-topic deterministic --add-topic cryptography \
  --add-topic stateless --add-topic python --add-topic gplv3
```

A licença passa a ser detectada sozinha assim que o `LICENSE` chegar ao remoto.

### 6. Verificação depois do push

```bash
gh repo view janiocarlosvieira/passweird --json defaultBranchRef,licenseInfo,description
git ls-remote --heads --tags origin
cd /tmp && rm -rf pw-check && git clone -q <url> pw-check && cd pw-check \
  && python3 -m pytest tests/ -q                # a suíte tem que passar num clone limpo
```

O clone limpo é o teste que importa: prova que o que foi publicado é autossuficiente e que o
`.gitignore` não excluiu nada necessário.

## Riscos e o que fazer se der errado

| Risco | Mitigação |
|---|---|
| Push apaga algo que importava | Já auditado: 1 commit, 1 arquivo, preservado na tag `v0-legacy` |
| Alguém clonou o repo antigo | 0 forks e 0 stars; o clone dessa pessoa simplesmente diverge |
| Force-push errado de branch | Push explícito `main:master`, nunca `--all` nem `--mirror` |
| Arrependimento | O commit antigo continua em `v0-legacy` e alcançável por SHA; reverter é `git push --force origin v0-legacy:master` |

## Fora do escopo, mas pendente

O `.git` na pasta home (71 entradas não rastreadas, incluindo `.ssh/` e `.gnupg/`) não tem
relação com esta publicação, mas continua sendo o risco mais sério do ambiente. O projeto está
isolado dele desde o `git init` local.
