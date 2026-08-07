# Architecture Decision Records

Record of Passweird's architecture decisions. Each ADR describes a context, the decision made
and its consequences. ADRs are not edited after being accepted — a decision that changes is
superseded by a new ADR.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-geracao-rsa-deterministica.md) | Deterministic RSA key generation | Accepted |
| [0002](0002-amostragem-de-primos-rejeicao-vs-incremental.md) | Prime sampling: rejection, not incremental search | Accepted |
| [0003](0003-chave-publica-publicada-como-oraculo-offline.md) | Published public key as an offline oracle | Accepted (risk accepted) |
| [0004](0004-separacao-de-dominio-no-info-do-hkdf.md) | Domain separation in the HKDF `info` string | Accepted |
| [0005](0005-processamento-em-lote-de-chaveiros.md) | Batch processing of keyring files | Proposed |
| [0006](0006-formato-do-log-e-deteccao-por-registro.md) | Log format and per-record detection | Accepted |
| [0007](0007-verificacao-de-senha-contra-o-log.md) | Password verification against the log | Proposed |
| [0008](0008-kotlin-multiplatform-port.md) | Kotlin Multiplatform port | Proposed |

The execution plan for the proposed ADRs is in
[`../PLANO-DE-ACAO.md`](../PLANO-DE-ACAO.md).
