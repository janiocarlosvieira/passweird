# ADR-0006 — Formato do log e detecção por registro

**Status:** Proposto
**Data:** 2026-08-03

## Contexto

O log local (`~/.passweird/passweird.log`) é gravado em dois formatos, escolhidos por execução:

- **cifrado** (padrão): blocos AES-256-GCM, cada um precedido de um prefixo de comprimento de
  4 bytes big-endian;
- **texto puro** (`--plain-log`): uma linha por registro, sempre começando com um `date_str` de
  14 dígitos.

Como a escolha é **por execução** e o arquivo é **append-only**, um mesmo arquivo pode conter
os dois formatos intercalados em qualquer ordem. Basta usar `--plain-log` uma vez e voltar ao
padrão — não é um caso exótico.

`storage.read_logs_from_file` (storage.py:725) escolhe o formato inspecionando **os 14
primeiros bytes do arquivo** e depois trata o arquivo inteiro como sendo daquele tipo. O
docstring da função argumenta corretamente por que o discriminador é sólido (um prefixo de
comprimento nunca é composto de dígitos ASCII) — mas aplica esse discriminador uma vez só.

Comportamento verificado em log misto:

| Ordem de gravação | Sintoma |
|---|---|
| texto puro, depois cifrado | `UnicodeDecodeError` sobe até o topo; o log inteiro fica ilegível |
| cifrado, depois texto puro | **perda silenciosa**: dois registros gravados, um exibido |

A segunda é a mais grave: não há erro nenhum, apenas registros que somem. Isso atinge
`--view-log`, `--audit` e qualquer coisa construída sobre o log, porque todas passam por essa
função.

## Decisão

Decidir o formato **por registro**, não por arquivo. O laço de leitura passa a olhar, a cada
posição:

- próximos 14 bytes são dígitos ASCII → registro em texto puro, consumir até `\n`;
- caso contrário → bloco cifrado, consumir prefixo de 4 bytes + payload.

O discriminador continua sendo o mesmo já documentado e continua correto registro a registro: o
prefixo de comprimento de um bloco cifrado começa em `\x00\x00\x00` para qualquer payload de
tamanho realista, e byte nulo não é dígito ASCII. A mudança é onde ele é aplicado, não qual é.

Adicionalmente, um arquivo truncado no meio de um bloco (queda de energia durante a escrita)
deve devolver os registros íntegros lidos até ali, sem exceção.

## Consequências

- `--view-log`, `--audit` e a verificação do ADR-0007 passam a enxergar o log inteiro
  independentemente da mistura de formatos.
- Nenhuma mudança de formato de gravação: logs existentes continuam legíveis, e a correção é
  puramente de leitura.
- O laço fica um pouco mais longo, mas some a decisão global implícita que era a origem do bug.

## Nota sobre o formato em si

O formato "append-only com dois codificações intercaláveis e discriminação heurística" é frágil
por natureza — funciona aqui porque o discriminador é bem escolhido, não porque o desenho seja
robusto. Um cabeçalho de arquivo com versão, ou um byte de tipo por registro, seria mais
defensável. Não é feito agora porque exigiria migrar logs existentes para ganhar pouco: com a
detecção por registro, o caso que quebrava passa a funcionar. Fica registrado como o desenho
preferível se o formato do log for revisto por outro motivo.
