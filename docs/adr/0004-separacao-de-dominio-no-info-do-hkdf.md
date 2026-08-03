# ADR-0004 — Separação de domínio no `info` do HKDF

**Status:** Aceito
**Data:** 2026-08-03

## Contexto

Todos os geradores montam o `info` do HKDF por concatenação de campos separados por `:`,
terminando no `temporal_salt`:

```
{app_hash}:ssl_seed:{temporal_salt}
```

Alguns geradores precisam de uma **sub-derivação** a partir do mesmo material — o número de
série do certificado, o `checkint` do container OpenSSH, o timestamp de criação da chave PGP.
Essas eram obtidas anexando um sufixo literal ao `info` já pronto:

```python
serial_seed = hkdf_expand(prk, info + b":serial", 19)
```

O problema: `temporal_salt` é **texto livre controlado pelo usuário** e fica no **fim** do
`info`. Anexar um sufixo depois dele torna a codificação ambígua — não há como, olhando a
string final, saber onde o salt termina e onde o sufixo começa.

Concretamente, para uma mesma senha-mestre e um mesmo contexto:

| Configuração | `info` resultante |
|---|---|
| serial do certificado com salt `X` | `{ah}:ssl_seed:X:serial` |
| **chave privada** com salt `X:serial` | `{ah}:ssl_seed:X:serial` |

São idênticos. E como o HKDF-Expand produz um stream cujo prefixo é estável, os 19 bytes do
serial são exatamente os 19 primeiros bytes da seed privada de 32 bytes. **152 dos 256 bits
da chave privada Ed25519 ficam legíveis para qualquer um que tenha o certificado**, que
publica o serial em texto claro. Restam 104 bits — não é quebra imediata, mas é vazamento de
chave privada.

Verificado também em `:checkint` (SSH) e `:ctime` (PGP), com o mesmo formato e severidade
menor (o checkint fica no container privado; o ctime vaza 4 bytes).

Os caminhos de senha e de RSA **não** são afetados: neles o último campo é o contador/nonce,
que é composto só de dígitos e nunca contém `:`. A decomposição pela direita é única, então
nenhum salt consegue forjar o campo final.

## Decisão

Nenhum campo é anexado depois do `temporal_salt`. Sub-derivações passam a ter **label
próprio**, posicionado antes do salt:

| Antes | Depois |
|---|---|
| `{ah}:ssl_seed:{salt}` + `":serial"` | `{ah}:ssl_serial:{salt}` |
| `{ah}:ssh_seed:{salt}` + `":checkint"` | `{ah}:ssh_checkint:{salt}` |
| `{ah}:pgp_seed:{salt}` + `":ctime"` | `{ah}:pgp_ctime:{salt}` |

Regra geral para código novo: **o salt é sempre o último campo do `info`**. Qualquer
variação de derivação vira um label distinto, não um sufixo.

Descartada a alternativa de aplicar `sha256()` ao salt antes de inseri-lo (o que também o
tornaria de comprimento fixo e não-ambíguo): resolveria o problema, mas alteraria a
derivação de **toda** senha já gerada com segredo temporal, inclusive as de salt vazio.

## Consequências

A escolha do label próprio preserva os `*_seed`, então **o material de chave não muda**:

- **SSH** — chave pública e privada idênticas; só os bytes do container OpenSSH mudam.
  Entradas em `authorized_keys` já implantadas continuam válidas. Coberto por teste.
- **SSL** — chave idêntica; só o número de série do certificado muda.
- **PGP** — a chave Ed25519 é a mesma, mas o `ctime` entra no cálculo do fingerprint, então
  o **Key ID muda**. Chaves PGP já distribuídas precisam ser redistribuídas.
- **Senha, RSA, TOTP** — nada muda.

## Bug latente descoberto junto

Trocar o label do `ctime` moveu o valor derivado para outro ponto do intervalo e fez o teste
de importação no `gpg` falhar. A causa não era a mudança: o cálculo era
`derivado % 2_000_000_000`, cujo teto é 2033-05-18. Timestamps no futuro fazem o `gpg`
recusar a importação (`failed to re-lookup public key`), e isso atingia cerca de **1 em cada
9** combinações de senha/contexto/salt — só não aparecia porque o valor derivado
anteriormente calhava de cair no passado.

Corrigido mapeando para uma janela fixa e permanentemente passada (2000-01-01 mais até 20
anos). A janela **não pode** acompanhar o relógio: o timestamp entra no fingerprint, então um
limite móvel mudaria silenciosamente a identidade da chave com o tempo.
