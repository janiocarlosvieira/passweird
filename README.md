# Passweird

Passweird é um gerador de senhas **determinístico e "stateless"**: em vez de guardar senhas em um cofre, ele recalcula a mesma senha sempre que você fornece os mesmos ingredientes — **senha-mestre + nome do aplicativo/contexto** (e, opcionalmente, um **segredo temporal**). Não existe arquivo de senhas para vazar ou perder: se você lembra da master password e do contexto, você reconstrói a senha em qualquer máquina.

O mesmo princípio se estende a outras identidades criptográficas: chaves **SSH**, certificados **SSL/TLS**, segredos **TOTP** e pares de chave **PGP** também podem ser regenerados de forma idêntica a partir dos mesmos ingredientes.

## Arquitetura

O projeto é dividido em três módulos:

- **`crypto.py`** — toda a matemática pura: hashing, derivação HKDF, geração determinística de senhas/chaves, criptografia AES-GCM.
- **`storage.py`** — persistência, logs, configuração, exportação para gerenciadores de senha, internacionalização (`_()`).
- **`main.py`** — interface de linha de comando e orquestração.

## Requisitos

- Python 3.10+
- Binário `gpg` (GnuPG) instalado no sistema, se for usar `--pgp`
- Um autenticador FIDO2 físico (YubiKey ou similar), se for usar `--fido2`/`--fido2-register`

## Instalação

```bash
pip install -r requirements.txt
```

Isso instala `cryptography`, `python-gnupg`, `pyotp` e `fido2`.

Para rodar os testes, instale também as dependências de desenvolvimento:

```bash
pip install -r requirements-dev.txt
```

## Uso básico

```bash
python3 main.py <contexto>
```

Você será solicitado a digitar a senha-mestre (entrada oculta), e a senha determinística para aquele contexto será gerada e exibida:

```bash
$ python3 main.py github
Master password:
Context: github
Generated Password: 6x93w7CpY@UgRXm1U+
```

Rodar o mesmo comando de novo, com a mesma senha-mestre, produz **exatamente a mesma senha**.

### Primeiros passos recomendados

```bash
# 1. Gera um arquivo de configuração padrão comentado em ~/.passweird/passweird.cfg
python3 main.py -g

# 2. Registra o hash da sua senha-mestre localmente, para detectar erros de digitação
python3 main.py --register-master

# 3. Salva as flags atuais (comprimento, classes de caracteres, etc.) como padrão
python3 main.py -L 24 -s --save-settings
```

## Referência de flags

### Geração de senha padrão

| Flag | Descrição |
|---|---|
| `contexto` (posicional) | Nome do aplicativo/contexto (modo visível) |
| `-T, --temporal` | Segredo/salt temporal (ex: `2026/01`, `Q2`). Se omitido, é pedido interativamente (ou lido de `--temporal-secret-file`) |
| `-L, --length` | Comprimento da senha (padrão 18; mínimo 8, ou 6 se só dígitos) |
| `-p, --paranoid` | Modo paranoico: oculta a digitação do contexto |
| `-U, --no-uppercase` / `-l, --no-lowercase` / `-n, --no-numbers` / `-s, --no-specials` | Desativa classes de caracteres |
| `-v, --invisible-password [cor]` | Imprime a senha em uma cor "invisível" (padrão: preto) |
| `-o, --output {bitwarden,keepassxc,protonpass,chrome,firefox,seahorse,kaspersky}` | Exporta a entrada para CSV de um gerenciador de senhas |
| `--force` | Pula o aviso de divergência de flags em relação ao último uso registrado no log |

### Senha-mestre e segredo temporal

| Flag | Descrição |
|---|---|
| `--master-file ARQUIVO` | Lê a senha-mestre de um arquivo em texto puro (**inseguro**, imprime aviso) |
| `--master-pass SENHA` | Passa a senha-mestre direto na linha de comando (**inseguro**, imprime aviso) |
| `--temporal-secret-file ARQUIVO` | Lê o segredo temporal padrão de um arquivo (Enter no prompt repete esse valor) |
| `--register-master` | Registra o hash da senha-mestre atual como padrão desta máquina (pede confirmação dupla na primeira vez) |
| `--no-check` | Pula a verificação contra o hash registrado |

### Modo de troca e processamento em lote

| Flag | Descrição |
|---|---|
| `-c, --change` | Modo de troca: pede master/app antigos e novos, gera os dois, loga com marcador `C` |
| `-f, --file [ARQUIVO]` | Processa em lote um arquivo texto (`contexto identificadores...` por linha) ou CSV (`app,identificadores`) |
| `--mass-rekey` | Regera as senhas de **todos** os contextos salvos em `hosts.enc` sob uma nova senha-mestre, exporta um CSV com pares antigo/novo e re-criptografa `hosts.enc` com a nova senha |
| `--old-key-file` / `--new-key-file` | Keyfiles físicas antiga/nova a usar durante `--mass-rekey` |

### Segundo fator físico

| Flag | Descrição |
|---|---|
| `--key-file CAMINHO` | Usa um arquivo (qualquer arquivo, ou uma keyfile gerada pelo Passweird) como segundo fator, misturado ao hash da senha-mestre |
| `--gen-keyfile CAMINHO` | Gera uma nova keyfile **aleatória**, criptografada em repouso com a senha-mestre atual — um fator "algo que se tem": perder o arquivo sem backup é perder o fator |
| `--gen-keyfile CAMINHO --recoverable` | Gera uma keyfile **derivada da senha-mestre + uma frase de recuperação** perguntada interativamente — pode ser regenerada de memória se o arquivo físico for perdido |
| `--fido2-register` | Registra uma nova credencial em uma chave de segurança FIDO2 conectada (exige toque físico) |
| `--fido2` | Usa a credencial FIDO2 registrada como fator adicional para a geração atual (exige toque físico a cada uso) |

### Identidades determinísticas adicionais

| Flag | Descrição |
|---|---|
| `--ssh` | Gera um par de chaves SSH Ed25519 determinístico |
| `--ssl` | Gera um certificado SSL/TLS autoassinado determinístico (Ed25519) |
| `--rsa BITS` | Como `--ssl`, mas usando RSA — totalmente determinístico: os primos p e q são derivados do mesmo stream HKDF (mínimo 2048, múltiplo de 16). Custo típico: ~1 s em 2048 bits, ~2 s em 4096 bits |
| `--totp` | Gera um segredo TOTP determinístico (mostra segredo Base32, URI `otpauth://` e código atual de 6 dígitos) |
| `--pgp` | Gera um par de chaves PGP/OpenPGP determinístico (exportado em formato armored, pronto para `gpg --import`) |

> ⚠️ **Use um segredo temporal forte com `--ssl` e `--rsa`.**
> O certificado publica o nome do contexto no campo CN, em texto claro. Ou seja: escolher um
> nome de contexto imprevisível **não protege nada** aqui — quem baixar o certificado lê o
> contexto. Como a chave pública também é publicada, ela funciona como um oráculo de
> verificação offline: um atacante testa senhas candidatas contra o módulo `n` sem qualquer
> limite de tentativas.
>
> Com isso, o segredo temporal (`-T`) é **a única entrada imprevisível que não vaza junto com
> o artefato**. Ele deve ser tratado como uma segunda senha, não como um rótulo de versão:
> use algo como uma passphrase de 6+ palavras aleatórias, não `2026/01`. O CLI avisa quando
> você gera um certificado sem segredo temporal.
>
> O mesmo vale **no mesmo grau** para `--pgp`: o UID da chave é `Passweird <contexto>`, ou seja,
> o contexto vai publicado ali igualmente. Para `--ssh` o contexto **não** vaza (a chave pública
> é derivada de `app_hash` e não carrega comentário), então ali um nome de contexto imprevisível
> soma entropia de verdade.

### Auditoria, logs e lista de hosts

| Flag | Descrição |
|---|---|
| `--audit` | Verifica se um contexto/temporal já foi usado antes, buscando no log local (sem `contexto`/`-T` na linha de comando, pede tudo de forma oculta — não deixa rastro no histórico do shell) |
| `--view-log` | Descriptografa e exibe todo o histórico de logs |
| `--plain-log` | Desativa a criptografia AES do log (grava em texto puro) |
| `-w, --write` | Desativa a gravação de resumos de hash no log |
| `--no-print-hash` | Não imprime a linha de resumo de hash no terminal |
| `--encrypt-list ARQUIVO` | Criptografa um arquivo texto com nomes de hosts/sistemas em `~/.passweird/hosts.enc` |
| `--view-list` | Descriptografa e exibe a lista de hosts/sistemas salva |

### Configuração

| Flag | Descrição |
|---|---|
| `-g, --generate` | Cria `~/.passweird/passweird.cfg` comentado com todas as opções, e sai |
| `--save-settings` | Salva as flags atuais como padrão em `passweird.cfg` |

Rode `python3 main.py --help` para a lista completa e atualizada (a ajuda é totalmente internacionalizada — veja abaixo).

## Internacionalização

A interface detecta o idioma do sistema (`locale`) automaticamente. Idiomas suportados hoje: **português, espanhol, francês, alemão e chinês simplificado** (com inglês como padrão de fallback para o que não estiver traduzido). Para testar um idioma específico:

```bash
LANG=fr_FR.UTF-8 python3 main.py --help
```

(requer que o locale correspondente esteja instalado no sistema, ex. via `locale-gen`).

## Modelo de segurança, em resumo

- A senha-mestre nunca é gravada em disco — apenas um hash duplo (`modified_hash`) é opcionalmente registrado para checagem local.
- Logs guardam somente **resumos truncados de hash** (senha, master, app, temporal), nunca os valores em si — e são criptografados com AES-256-GCM por padrão.
- Keyfiles geradas pelo Passweird (`--gen-keyfile`) são criptografadas em repouso com a senha-mestre atual: quem só tem o arquivo, sem a senha, não tem nada.
- Trocar a senha-mestre invalida automaticamente keyfiles antigas e o `hosts.enc` antigo — use `--mass-rekey` para migrar tudo de uma vez.

### Material assimétrico publicado exige mais cuidado

Senhas só são testáveis contra o serviço, que impõe limite de tentativas. **Chaves públicas
são diferentes**: uma vez publicadas (certificado TLS servido por um host, chave SSH em
`authorized_keys`, chave PGP num keyserver), qualquer um pode testar senhas-mestre candidatas
offline, sem limite, comparando o resultado com a chave pública conhecida.

O custo de derivar a chave **não** protege contra isso na proporção que parece: o atacante não
precisa refazer os testes de primalidade, basta dividir o módulo por cada candidato da
sequência. Medido: ~2,4 ms por tentativa por core, contra ~0,8 µs de um palpite de senha comum.
É um freio de ~3.000×, não de 300.000×.

Consequência prática — quando usar `--ssl`, `--rsa`, `--pgp` ou `--ssh`:

1. **Use um segredo temporal forte** (`-T`). Para `--ssl`/`--rsa` ele é a única entrada
   imprevisível que não é publicada junto com o certificado.
2. **Senha-mestre e segredo temporal somados devem ter entropia alta.** Duas passphrases de
   6 palavras aleatórias cada (~77 bits por passphrase) resolvem com folga. Senhas curtas ou
   memorizáveis "à moda antiga" não resolvem.
3. **Considere `--key-file` ou `--fido2`.** Uma keyfile aleatória contribui com entropia que
   não é adivinhável, e não depende de você lembrar de nada.

### Como escolher um segredo temporal (e por que "parecer forte" engana)

Comprimento e variedade de caracteres **não medem** entropia. O que mede é
imprevisibilidade — quantos palpites o atacante precisa dar, sabendo como você pensa.

| Segredo temporal | Medidor ingênuo diria | Na prática | Tempo para quebrar¹ |
|---|---|---|---|
| `08/2026`, `2026/01`, `Q2` | ~15 bits | **~9 bits** | instantâneo |
| `[mYpAsswordiSaUgustoF26]` | **~147 bits** | **~40 bits** | ~17 minutos |
| 4 palavras sorteadas ao acaso | ~50 bits | **~52 bits** | ~42 dias |
| 6 palavras sorteadas ao acaso | ~75 bits | **~78 bits** | ~7 milhões de anos |

¹ a 10⁹ palpites/s — ver [ADR-0003](docs/adr/0003-chave-publica-publicada-como-oraculo-offline.md).

A segunda linha é a armadilha e merece atenção. `[mYpAsswordiSaUgustoF26]` tem 24 caracteres,
maiúsculas alternadas, dígitos e colchetes; qualquer medidor de força o classificaria como
excelente. Mas ele é uma **frase previsível com uma transformação previsível**: "my password is
august of 26", mais um padrão de capitalização e uma cercadura. Ferramentas de quebra reais
(regras do hashcat, PRINCE, modelos estatísticos) atacam exatamente essa estrutura — um
dicionário de frases plausíveis cruzado com um conjunto grande de regras chega lá em ~2⁴⁰.

**É muito melhor que `08/2026`** — sai de ~9 para ~40 bits. Mas fica quatro ordens de grandeza
abaixo do que aparenta, e é justamente esse tipo de segredo que dá falsa confiança.

O que funciona é sorteio, não criatividade: **palavras escolhidas ao acaso** (diceware, dados,
`shuf`). A entropia vira um número que você pode calcular, e ele **continua valendo mesmo que o
atacante conheça exatamente o método** — que é o teste que "frases espertas" não passam.

```bash
# sorteia um segredo temporal e informa quantos bits ele realmente carrega
python3 main.py --gen-temporal        # 6 palavras
python3 main.py --gen-temporal 8      # mais margem
```

### Por que este README não sugere padrões "criativos"

É tentador oferecer um repertório de ideias — trocar a data por um nome de álbum, intercalar
letras e dígitos, inverter a ordem das letras. A intuição é que exemplos variados quebram o
viés de todo mundo escolher a mesma coisa, como no experimento em que quase todos respondem
"martelo vermelho".

A lição do martelo vermelho, porém, é outra: **a escolha humana livre carrega ~4 bits**.
Sugerir outra coisa não elimina o agrupamento, apenas o desloca. E aqui existe uma assimetria
que inverte o resultado: **o atacante lê este README**. Toda sugestão publicada vira uma regra
que ele *enumera*; você é apenas *empurrado* por ela.

Medindo os padrões que costumam ser propostos, supondo que o atacante conheça o esquema:

| Padrão | Espaço restante | Tempo |
|---|---|---|
| Intercalar mês e ano (`a2u0g2u6s`) | 12 × 10 × 8 = **2¹⁰** | instantâneo |
| `NN-AlbumFamoso-NN` (`08-DarkSideOfTheMoon-26`) | 2¹⁴ × 12 × 10 × 8 = **2²⁴** | instantâneo |
| Inverter as letras de uma frase | 2²⁰ × 2¹² = **2³²** | instantâneo |
| 6 palavras sorteadas | **2⁷⁸** | 7 milhões de anos |

Repare que o primeiro é o que *parece* mais engenhoso e é o mais fraco de todos. Inverter
letras, aliás, é a regra `r` do hashcat — está em todo conjunto de regras há décadas.

A moral: **o esforço que um esquema exige da sua memória não tem relação nenhuma com o que
ele custa a quem ataca.** Por isso aqui há um sorteador (`--gen-temporal`) em vez de um
catálogo de ideias.

Por isso o Passweird **não exibe medidor de força**: um número baseado em charset daria ~147
bits para o exemplo acima e abençoaria a escolha errada. Ele apenas avisa sobre formatos
inegavelmente fracos (vazio, só dígitos/pontuação, curto demais) e aponta para esta seção.
Silêncio significa "não é obviamente fraco" — nunca "é forte".

Ver [`docs/adr/0003`](docs/adr/0003-chave-publica-publicada-como-oraculo-offline.md) para a
análise completa e os números medidos.

## Rodando os testes

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

A suíte (pytest) cobre:

- `tests/test_crypto.py` — determinismo de todas as primitivas (HKDF, senha, SSH, SSL, TOTP, PGP, keyfiles, FIDO2 com cliente mockado).
- `tests/test_regressions.py` — regressões dedicadas para os bugs já corrigidos (bug do `--key-file`/`hashlib`, `--ssl`/`datetime.UTC`).
- `tests/test_storage.py` — configuração, formatos de exportação, construção/leitura de log, lista de hosts.
- `tests/test_cli.py` — fluxos completos de CLI (troca, lote, master-file, temporal-file, keyfile, TOTP, PGP, rekey em massa) com entrada simulada.

Os testes nunca tocam o `~/.passweird` real: um `conftest.py` redireciona `HOME` para um diretório temporário a cada teste.

**Limitação conhecida:** os testes de FIDO2 usam um cliente simulado (não há hardware físico disponível no ambiente de desenvolvimento). Se você tiver uma chave de segurança FIDO2, valide manualmente com:

```bash
python3 main.py --fido2-register
python3 main.py meucontexto --fido2
```

## Licença

GNU General Public License v3.0.
