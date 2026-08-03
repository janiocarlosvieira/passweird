# ADR-0007 — Verificação de senha contra o log

**Status:** Proposto
**Data:** 2026-08-03

## Contexto

Num gerador stateless, a pergunta prática mais frequente não é "qual é minha senha?" — é
**"a senha que eu geraria agora ainda é a que está na conta?"**. Ela some quando qualquer
fator muda sem que o usuário perceba: um flag de comprimento diferente, um segredo temporal
digitado com variação, uma senha-mestra trocada.

O `--audit` (main.py:459) chega perto mas responde outra coisa: ele verifica se **existe
registro** para um par contexto/temporal, via `storage.find_in_log`. Não regenera a senha, não
compara nada, e devolve todas as ocorrências sem distinguir qual é a mais recente.

O log já guarda o que falta: cada linha traz `pwd:<resumo>`, onde o resumo é
`crypto.summarize_password_hash` — os 10 primeiros e os 10 últimos caracteres do hex de
`sha256(senha)`.

## Decisão

Uma verificação nova (`--verify`) que:

1. pede contexto e segredo temporal com `getpass` (ocultos, como o `--audit` interativo, para
   não deixar rastro no histórico do shell);
2. varre o log **de baixo para cima** e para no primeiro registro daquele contexto — a última
   modificação documentada, cronologicamente;
3. regenera a senha usando `len` e `feat` **lidos do próprio registro**, não os flags da linha
   de comando;
4. compara o resumo com o campo `pwd:` do registro.

O ponto 3 é a decisão menos óbvia e a mais importante: regenerar com os defaults atuais faria a
verificação falhar toda vez que o padrão do usuário tivesse mudado desde a geração — que é
justamente a situação em que ele mais precisa de uma resposta confiável. Verificar significa
reproduzir as condições registradas, não as condições correntes.

## Consequências

### O que o resumo truncado permite afirmar

São 20 dos 64 caracteres hex de um SHA-256, ou seja **80 bits**. A chance de duas senhas
distintas colidirem nesses 80 bits é 2⁻⁸⁰. Um casamento é conclusivo para qualquer efeito
prático.

### Os três desfechos precisam ser distintos

| Desfecho | Significado |
|---|---|
| Sem registro | Nunca foi gerada, **ou** foi gerada com `-w/--write` (log desligado) |
| Registro e confere | A senha atual reproduz a última modificação documentada |
| Registro e diverge | Algum fator mudou: senha-mestra, segredo temporal ou contexto |

Colapsar o primeiro caso nos outros seria um erro grave de usabilidade: "não encontrei
registro" e "a senha não confere" levam a ações opostas, e confundi-los pode fazer o usuário
trocar a senha de uma conta sem necessidade.

### Limite herdado

A verificação só enxerga o que foi registrado. Quem usa `-w` de forma sistemática não tem o que
verificar — e isso precisa ser dito na saída, não inferido pelo usuário.

### Dependência

Depende da correção do [ADR-0006](0006-formato-do-log-e-deteccao-por-registro.md): sobre um log
de formato misto, a leitura atual perde registros silenciosamente, e uma verificação que lê um
log incompleto responderia "sem registro" para senhas que existem — exatamente o desfecho que
não pode ser confundido.

## O log como oráculo

Registrar `pwd:<80 bits de sha256(senha)>` é o que torna a verificação possível, e é também um
oráculo de verificação offline para a senha gerada — um único SHA-256 por tentativa, sem salt.

O risco é contido, não eliminado: o log é cifrado em repouso com AES-256-GCM sob uma chave
derivada da própria senha-mestra, então quem não a tem não lê os resumos. Mas `--plain-log`
grava tudo em claro, e aí os resumos de senha, de master e de temporal ficam legíveis a quem
tiver leitura no disco.

Isso não é introduzido por este ADR — o formato do log já é assim. Fica registrado aqui porque
esta funcionalidade é a que dá utilidade ao campo, e portanto a que fixa o campo no formato.
Ver [ADR-0003](0003-chave-publica-publicada-como-oraculo-offline.md) para o mesmo padrão de
risco em material assimétrico, e para o motivo de o KDF atual não sustentar bem nenhum dos dois.
