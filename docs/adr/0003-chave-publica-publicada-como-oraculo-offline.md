# ADR-0003 — Chave pública publicada como oráculo offline

**Status:** Aceito — risco assumido, não mitigado
**Data:** 2026-08-03

## Contexto

Material assimétrico determinístico tem uma propriedade que uma senha comum não tem: **a
metade pública é publicada**. Um certificado TLS servido por um host, uma chave SSH em
`authorized_keys`, uma chave PGP num keyserver — todos ficam acessíveis a qualquer um.

Isso transforma a chave pública num **oráculo de verificação offline**. Contra o RSA
determinístico de [ADR-0001](0001-geracao-rsa-deterministica.md), o ataque é direto:

1. Chuta uma senha mestra candidata.
2. Deriva `modified_hash` e daí apenas o **primeiro** primo p (metade do trabalho).
3. Testa `n mod p == 0`, com `n` lido do certificado público.

Um acerto confirma a senha mestra — e com ela, todas as outras senhas derivadas dela. Não há
rate limiting possível: o atacante tem o `n` e trabalha offline.

O KDF atual não sustenta essa exposição. `modified_hash()` (`crypto.py`) é literalmente:

```python
first_hash = hashlib.sha256(value.encode()).hexdigest()
derived = hashlib.sha256(first_hash[:-1].encode()).hexdigest()
```

Dois SHA-256, sem salt, sem fator de trabalho. Agrava: `storage.save_master_hash()` grava
esse valor em claro em `~/.passweird/master.hash`, o que dá um segundo oráculo offline a
quem tiver leitura no disco, custando 2 SHA-256 por tentativa.

## Decisão

**Aceitar o risco agora** e implementar o RSA determinístico sem tocar no KDF.

Motivo: trocar `modified_hash` por Argon2id é uma mudança que invalida **toda** senha já
gerada pelo Passweird e exige versionamento e um caminho de migração. Misturar isso com a
feature de RSA acoplaria duas mudanças de risco muito diferente — uma aditiva e testável em
isolamento, outra que quebra todos os usuários existentes.

## Mitigação parcial (acidental) — e por que ela é menor do que parece

É tentador supor que o custo de gerar a chave (~230 ms em 2048 bits) vira proof-of-work e
encarece cada tentativa do atacante na mesma proporção. **Não vira.** O atacante tem um
atalho: ele não precisa descobrir *qual* candidato da sequência é primo. Basta percorrer os
candidatos e testar `n mod candidato == 0` em cada um. Se o candidato for o nosso p, ele
divide n; se for composto, não divide. Isso elimina o crivo de pequenos primos e todas as
rodadas de Miller-Rabin — justamente o que domina o custo honesto.

Medido nesta base de código (CPython puro, um core, K=400 candidatos por tentativa):

| Oráculo | Custo por palpite | Palpites/s/core |
|---|---|---|
| `~/.passweird/master.hash` (2× SHA-256) | 0,76 µs | ~1.324.000 |
| Chave pública RSA publicada | 2,36 ms | ~424 |
| *(geração honesta, para comparação)* | 229 ms | — |

Ou seja: o atacante paga cerca de **1% do custo da geração honesta**, e o freio efetivo é de
~3.000× sobre um palpite de senha comum — não os ~300.000× que a diferença de tempo de
geração sugeriria. Num equipamento de 100 cores são ~42 k palpites/s; reimplementado em C ou
GPU, muito mais. Uma senha de ~40 bits de entropia é alcançável; uma passphrase diceware de
6+ palavras não é.

A conclusão é que isso **não é uma defesa projetada** e não deve ser contabilizada como tal.

## Pré-computação: o que é e o que não é "rainbow table"

Vale distinguir, porque os dois oráculos têm formatos de ataque diferentes:

- **`master.hash` é o caso clássico.** `modified_hash` não tem salt e é idêntica para todo
  usuário do Passweird, então uma única tabela pré-computada inverte o arquivo de qualquer
  um. É exatamente o cenário para o qual rainbow tables foram inventadas.
- **A chave pública não é**, no sentido clássico: o alvo `n` é único por (senha mestra,
  contexto), e nenhuma tabela cobre isso sem enumerar também os contextos.

Mas há duas brechas de pré-computação reais mesmo assim:

1. O pipeline é `senha → modified_hash → HKDF(contexto) → p,q → n`, e o **primeiro estágio
   não depende do contexto**. Uma tabela de `master_hash` para um dicionário grande é
   construída uma vez e reusada contra todos os alvos Passweird que existirem.
2. Contextos têm entropia baixa e são adivinháveis (`gmail.com`, `github.com`). Para um
   contexto popular, dá para pré-computar `senha → n` e casar contra qualquer usuário
   daquele serviço.

Ambas morrem com um salt por usuário no KDF — que é precisamente o que a migração para
Argon2id deve trazer.

## O contexto não é secreto no caminho SSL

Um agravante específico de `--ssl`/`--rsa`: o certificado **imprime o contexto de derivação no
CN**, em texto claro. Escolher um nome de contexto imprevisível — estratégia que funciona para
`--ssh`, cuja chave pública não carrega o contexto — aqui não vale nada, porque quem baixa o
certificado lê o contexto junto.

Por isso o `temporal_salt` foi plugado no caminho SSL/RSA (antes ele era calculado em
`main.py` e descartado). Ele é **a única entrada imprevisível que não é publicada com o
artefato**, e deve ser tratado como uma segunda senha, não como rótulo de versão: `2026/01`
não adiciona entropia significativa; uma passphrase de 6+ palavras aleatórias, sim.

Consequência para a documentação: o README instrui explicitamente sobre isso e o CLI emite um
aviso quando um certificado é gerado sem segredo temporal.

## Quanta entropia é preciso

O ataque custa ~2,4 ms/palpite/core nesta implementação em Python. Assumindo um atacante que
reimplemente em C, ganhe 100× e disponha de 10⁴ cores, chega-se à ordem de 10⁹ palpites/s; um
adversário estatal com 100× mais recursos chegaria a 10¹¹.

| Entropia combinada (senha-mestre + segredo temporal) | a 10⁹ palpites/s | a 10¹¹ palpites/s |
|---|---|---|
| 40 bits | 18 minutos | segundos |
| 50 bits | 13 dias | 3 horas |
| 60 bits | 37 anos | 133 dias |
| 70 bits | 3,7×10⁴ anos | 374 anos |
| 80 bits | 3,8×10⁷ anos | 3,8×10⁵ anos |
| 100 bits | inviável | inviável |

Duas passphrases diceware de 6 palavras somam ~155 bits e ficam confortavelmente fora de
alcance. Uma senha-mestre "forte" no sentido comum (12 caracteres mistos, ~60–70 bits) resiste
a um atacante oportunista, mas não com folga contra um adversário dedicado — e não resiste de
jeito nenhum se a entropia real for menor do que a contagem ingênua sugere, o que é o caso
típico de senhas escolhidas por humanos. É essa a razão de o README recomendar segredo temporal
forte, keyfile ou FIDO2 sempre que material assimétrico for publicado.

**Nota:** uma versão anterior deste ADR trazia "~semanas" para 60 bits e "~10⁴ anos" para 80
bits. Ambos estavam errados por erro aritmético — subestimavam a resistência em cerca de três e
quatro ordens de grandeza, respectivamente. Os números acima foram recalculados.

## Consequências

- Quem usa `--rsa`, `--ssl`, `--ssh` ou `--pgp` com uma senha mestra fraca está
  materialmente menos protegido do que quem só gera senhas, porque publica o oráculo. Isso
  deve ser dito na documentação em linguagem clara, não escondido.
- Fica registrado como item de roadmap separado: substituir `modified_hash` por Argon2id com
  salt e versionamento de algoritmo, e parar de gravar o hash mestre em claro. Um ADR futuro
  supersede este quando isso for feito.
