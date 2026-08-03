# ADR-0005 — Processamento em lote de arquivos de chaveiro

**Status:** Proposto
**Data:** 2026-08-03

## Contexto

O Passweird sabe **exportar** para sete formatos de chaveiro (`EXPORT_FORMATS`, storage.py:12),
mas não sabe **ler** nenhum deles. Quem já tem um cofre povoado com senhas de padrões antigos
não tem caminho de migração: teria que reprocessar entrada por entrada à mão.

O caso concreto que motivou isto: um arquivo do KeePassXC com dezenas de senhas em padrões
antigos, a ser reprocessado para gerar um arquivo novo sob o padrão atual, com o usuário sendo
consultado senha por senha e usando a URL de cada entrada como sugestão de nome de contexto.

Duas restrições vieram junto e moldam o desenho:

1. **Senha-mestra e segredo temporal não devem ir na linha de comando.** Ficam no histórico do
   shell e visíveis em `ps`. Em lote isso é pior que no uso avulso, porque um único comando
   passa a expor o segredo que destranca dezenas de contas.
2. **A troca é confirmada individualmente.** Migração de cofre é irreversível na prática — o
   usuário precisa poder pular entradas e interromper no meio sem perder o já feito.

## Decisão

Adicionar leitura de chaveiros como a operação inversa da exportação existente, e um pipeline
interativo por entrada.

- **`EXPORT_FORMATS` ganha um mapa `fields`** ligando nomes canônicos (`name`, `url`,
  `username`, `password`) às colunas de cada formato. Uma estrutura só descreve as duas
  direções, em vez de manter uma tabela separada de importação que poderia divergir da de
  exportação com o tempo.
- **Autodetecção pelo cabeçalho.** Os sete cabeçalhos são textualmente distintos
  (`Title`/`Name`/`title`/`name`, `Username`/`User Name`/`Login`), então casar o cabeçalho lido
  contra os conhecidos é inequívoco. `--vault-format` permite forçar.
- **Segredos pedidos uma única vez, no início, via `getpass`.** Inclusive o segredo temporal,
  que no fluxo avulso é lido com `input()` visível — em lote ele fica na tela por muito tempo.
  Se vierem por `--master-pass`/`-T`, o aviso existente
  (`storage.print_command_line_warning`) é disparado, mas a execução prossegue: quem decidiu
  automatizar já foi avisado.
- **Arquivo de saída sempre novo.** `--vault-out` é obrigatório e nunca pode ser igual à
  entrada. Criado com modo `0600`.
- **Cada confirmação também grava no log** (`build_and_log_line`), para que as entradas
  migradas fiquem verificáveis pela funcionalidade do ADR-0007.

## Consequências

**Positivas.** Existe caminho de migração para quem já usa um cofre. O usuário mantém controle
entrada a entrada, podendo pular o que não quer mexer. O formato de saída pode diferir do de
entrada, então isto também vira uma ferramenta de conversão entre chaveiros.

**Custo.** Sete mapas `fields` a manter em sincronia com os `header`. Mitigado por um teste de
round-trip por formato — escrever e reler tem que devolver o original.

**Limitação assumida: o arquivo gerado tem senhas em texto puro.** É inerente ao formato CSV
que todos esses chaveiros importam; não há como evitar sem deixar de interoperar. O modo `0600`
e um aviso explícito ao final ("importe e apague") são a mitigação possível. Não é aceitável
tratar isso como detalhe: é o momento de maior exposição de todo o fluxo do Passweird.

**Limitação assumida: `firefox` não tem coluna de título.** Nome canônico cai para a URL, o que
é fiel ao formato mas significa que um round-trip Firefox → Firefox perde o título original se
ele veio de outro chaveiro.

## Alternativas rejeitadas

- **Ler o `.kdbx` do KeePassXC diretamente.** Exigiria `pykeepass` e implementar a criptografia
  do cofre, além de manipular o arquivo real do usuário — risco muito maior. O export CSV é o
  denominador comum de todos os sete chaveiros e mantém o Passweird fora do arquivo original.
- **Reaproveitar `-f/--file`** (lote de contextos em texto/CSV). Ele resolve outro problema:
  gerar senhas para uma lista de nomes. Aqui a entrada é um cofre com estrutura própria, e a
  saída é outro cofre. Sobrecarregar a mesma flag confundiria os dois fluxos.
- **Modo não-interativo (processar tudo sem perguntar).** Rejeitado por ora: a sugestão de
  contexto derivada da URL erra em casos comuns (subdomínios, múltiplas contas no mesmo site),
  e um lote inteiro migrado com contexto errado é indetectável depois — as senhas simplesmente
  não regeneram mais.
