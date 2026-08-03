# Architecture Decision Records

Registro das decisões de arquitetura do Passweird. Cada ADR descreve um contexto, a
decisão tomada e suas consequências. ADRs não são editados depois de aceitos — uma
decisão que muda é substituída por um novo ADR que a supersede.

| ADR | Título | Status |
|---|---|---|
| [0001](0001-geracao-rsa-deterministica.md) | Geração determinística de chaves RSA | Aceito |
| [0002](0002-amostragem-de-primos-rejeicao-vs-incremental.md) | Amostragem de primos: rejeição, não busca incremental | Aceito |
| [0003](0003-chave-publica-publicada-como-oraculo-offline.md) | Chave pública publicada como oráculo offline | Aceito (risco assumido) |
| [0004](0004-separacao-de-dominio-no-info-do-hkdf.md) | Separação de domínio no `info` do HKDF | Aceito |
| [0005](0005-processamento-em-lote-de-chaveiros.md) | Processamento em lote de arquivos de chaveiro | Proposto |
| [0006](0006-formato-do-log-e-deteccao-por-registro.md) | Formato do log e detecção por registro | Proposto |
| [0007](0007-verificacao-de-senha-contra-o-log.md) | Verificação de senha contra o log | Proposto |

O plano de execução correspondente aos ADRs propostos está em
[`../PLANO-DE-ACAO.md`](../PLANO-DE-ACAO.md).
