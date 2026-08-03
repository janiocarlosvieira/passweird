# ADR-0002 — Amostragem de primos: rejeição, não busca incremental

**Status:** Aceito
**Data:** 2026-08-03

## Contexto

Definido em [ADR-0001](0001-geracao-rsa-deterministica.md) que p e q seriam derivados do
stream HKDF, resta escolher **como** transformar um candidato qualquer num primo. Há duas
famílias:

1. **Busca incremental (*next-prime*).** Gera-se um candidato e anda-se para cima
   (`p += 2`) fazendo testes de primalidade até encontrar o primeiro primo acima dele.
2. **Rejeição.** Cada candidato reprovado é descartado inteiro e um candidato novo e
   independente é derivado, incrementando um contador que entra no `info` do HKDF.

A busca incremental é a primeira ideia natural, e é intuitivamente mais barata: só um
candidato precisa ser derivado do KDF.

## Decisão

Usar **rejeição**.

## Justificativa

A busca incremental escolhe cada primo com probabilidade **proporcional ao gap que o
precede**. Primos que vêm logo depois de um gap grande são super-amostrados; primos gêmeos
são sub-amostrados. Perto de 2^1024 o gap médio é ~710, mas gaps de ordem `(ln x)²` ocorrem,
o que dá uma não-uniformidade de até ~3 ordens de grandeza. O FIPS 186-5 §B.3.3 proíbe busca
incremental exatamente por isso e exige um candidato novo a cada rejeição.

Na prática esse viés não é uma quebra do RSA, e num esquema determinístico importa ainda
menos: a entropia real da chave vem da senha mestra, não do sorteio de p. O argumento
decisivo foi outro — **medimos as duas e o custo é equivalente**:

| | primo 1024 bits | primo 2048 bits |
|---|---|---|
| rejeição | ~0,07 s | ~1,5 s |
| busca incremental | ~0,11 s | ~0,5 s |

A variância entre sementes domina a diferença entre os dois métodos. Como não há trade-off
de desempenho a pagar, escolhe-se o método que é padrão-compatível e mais simples de
argumentar.

## Consequências

- `_derive_prime` carrega um contador que entra no `info` do HKDF; é ele que produz
  candidatos independentes. O contador **não** é exposto: a função é uma pura função de
  (prk, label, bits).
- As bases do Miller-Rabin são derivadas de `SHA-512(n)`, nunca de `secrets`/`random` — usar
  uma fonte aleatória aqui destruiria silenciosamente a reprodutibilidade. Derivá-las do
  próprio candidato (em vez de fixá-las publicamente) também impede que alguém triture
  contextos até achar um pseudoprimo forte que passe um conjunto de bases conhecido de
  antemão.
- São 24 rodadas (12 bases fixas + 12 derivadas), o que põe a probabilidade de falso positivo
  em torno de 2⁻⁴⁸. É mais do que o FIPS exige; o custo extra recai só sobre os dois primos
  confirmados, já que praticamente todo candidato composto morre na base 2.
- Um crivo de Eratóstenes até 65536, computado uma vez no import, elimina ~84% dos candidatos
  ímpares por divisão trivial antes de qualquer exponenciação modular. É o que mantém a
  geração na casa do segundo.
