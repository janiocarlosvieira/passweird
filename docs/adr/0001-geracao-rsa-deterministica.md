# ADR-0001 — Geração determinística de chaves RSA

**Status:** Aceito
**Data:** 2026-08-03

## Contexto

A premissa do Passweird é ser *stateless*: nada é guardado em cofre, tudo é recomputado a
partir da senha mestra mais um contexto. Todas as saídas respeitavam isso — senhas, chaves
SSH Ed25519, TOTP, PGP — exceto uma. A flag `--rsa BITS` chamava
`rsa.generate_private_key()` sem qualquer semente, produzindo material novo a cada execução.
O CLI imprimia um WARNING admitindo o problema e o README o documentava como se fosse
intransponível: *"a lib não oferece geração seedada de RSA"*.

A limitação era da API, não da matemática. A geração de RSA tem exatamente **uma** fonte de
aleatoriedade: a escolha de p e q. Tudo o mais — `n = p·q`, `d = e⁻¹ mod λ(n)`, os parâmetros
CRT — já é função determinística desses dois primos.

## Decisão

Derivar p e q do mesmo stream HKDF-SHA512 que o resto do projeto já usa (`hkdf_expand`), e
montar a chave via `rsa.RSAPrivateNumbers(...).private_key()` em vez de
`rsa.generate_private_key()`.

Detalhes que fazem parte da decisão:

- **Labels HKDF distintos** para os dois primos (`{app_hash}:rsa_seed:{temporal_salt}:p` e
  `:q`), seguindo o padrão já estabelecido em `:ssh_seed:`, `:ssl_seed` e `:serial`.
  Descartada a alternativa de derivar o segundo primo transformando a entrada do usuário (por
  exemplo, invertendo as palavras-chave): é uma transformação ad-hoc, de baixa diversidade, e
  não oferece nenhum argumento de independência entre p e q.
- **O caminho SSL foi uniformizado com os demais geradores** no mesmo change-set: passou a
  derivar de `app_hash` (não mais do `app` cru) e a receber `temporal_salt`, que antes era
  calculado em `main.py` e silenciosamente descartado. `domain_context` sobrou apenas como o
  CN do certificado. Isso invalida qualquer chave SSL Ed25519 emitida antes — aceito porque
  nenhuma havia sido emitida. Ver ADR-0003 para por que o salt importa tanto aqui.
- **Sem redução modular para uma faixa.** O candidato é montado forçando os dois bits mais
  altos a 1 (garante que `p·q` tenha o comprimento pedido) e o bit 0 a 1 (ímpar). Um `mod`
  sobre um intervalo que não é potência de dois enviesaria a extremidade baixa do intervalo.
- **Restrições obrigatórias** aplicadas na rejeição: `gcd(e, p−1) = gcd(e, q−1) = 1` (senão
  `d` não existe) e `|p − q| > 2^(bits/2 − 100)` (FIPS 186-5; sem isso, o método de Fermat
  fatora o módulo trivialmente).
- `RSAPrivateNumbers` valida os parâmetros CRT na construção, o que serve de auto-checagem
  gratuita.

## Consequências

**Positivas.** `--rsa` passa a honrar a premissa do projeto. O WARNING sai do CLI. O
certificado inteiro passa a ser reprodutível (ver a nota sobre validade abaixo).

**Custo.** O projeto passa a carregar aritmética própria de primalidade (crivo de pequenos
primos + Miller-Rabin), com o risco que código criptográfico caseiro sempre traz — mitigado
por testes que cruzam nossa primalidade com a implementação independente do `sympy` e por um
teste de assinatura/verificação que prova que o OpenSSL aceita a chave montada.

**Desempenho medido** (CPython puro, sem `gmpy2`, CPU comum): ~0,2–1 s para 2048 bits e
~1–4 s para 4096 bits. A dispersão é intrínseca — depende de quantos candidatos são
necessários até cair num primo — e não do hardware. É a mesma ordem de grandeza do
`openssl genrsa`, então não é um custo novo para o usuário.

**Efeito colateral necessário.** A validade do certificado vinha de `datetime.now()`, que tem
granularidade de segundo: dois certificados gerados com mais de um segundo de intervalo já
divergiam. Isso passava despercebido porque Ed25519 gera em microssegundos; com RSA levando
segundos, anunciar reprodutibilidade seria meia-verdade. A âncora passou a ser a meia-noite
UTC do dia corrente, o que torna o certificado byte-idêntico dentro do mesmo dia UTC. Isso
altera os bytes dos certificados Ed25519 emitidos anteriormente — as chaves Ed25519 seguem
idênticas, só a janela de validade muda.

## Alternativas rejeitadas

- **pycryptodome com `randfunc=`.** Funciona e é limpo, mas adiciona uma dependência de
  criptografia inteira para algo que a `cryptography` já permite montar via
  `RSAPrivateNumbers`. Manter uma única biblioteca de criptografia vale mais.
- **`gmpy2` obrigatório.** Aceleraria a geração em cerca de uma ordem de grandeza, mas exige
  toolchain de compilação e transforma um `pip install` simples num ponto de atrito. Fica
  como aceleração opcional futura (usar se disponível, cair no CPython puro se não).
- **Âncora de validade em época fixa** (por exemplo, 2020-01-01 + offset derivado). Daria
  reprodutibilidade perfeita e permanente, mas geraria certificados já expirados.
