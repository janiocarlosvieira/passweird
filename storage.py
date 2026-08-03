# storage.py
# Passweird - Persistent Cryptographic Storage, Hosts & Localization Engine
# Licensed under the GNU General Public License v3.0

import os
import csv
import hashlib
import locale
import math
import re
import secrets
import string
import crypto
from datetime import datetime

EXPORT_FORMATS = {
    "bitwarden": {
        "filename_prefix": "bitwarden",
        "header": ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"],
        "row": lambda name, url, username, pwd: ["", "false", "login", name, "", "", "", url, username, pwd, ""]
    },
    "keepassxc": {
        "filename_prefix": "keepassxc",
        "header": ["Title", "Username", "Password", "URL", "Notes"],
        "row": lambda name, url, username, pwd: [name, username, pwd, url, ""]
    },
    "protonpass": {
        "filename_prefix": "protonpass",
        "header": ["title", "username", "password", "website", "note"],
        "row": lambda name, url, username, pwd: [name, username, pwd, url, ""]
    },
    "chrome": {
        "filename_prefix": "chrome",
        "header": ["name", "url", "username", "password"],
        "row": lambda name, url, username, pwd: [name, url, username, pwd]
    },
    "firefox": {
        "filename_prefix": "firefox",
        "header": ["url", "username", "password", "httpRealm", "formActionOrigin", "usernameField", "passwordField"],
        "row": lambda name, url, username, pwd: [url, username, pwd, "", "", "", ""]
    },
    "seahorse": {
        "filename_prefix": "seahorse",
        "header": ["Name", "User Name", "Password", "URL", "Notes"],
        "row": lambda name, url, username, pwd: [name, username, pwd, url, ""]
    },
    "kaspersky": {
        "filename_prefix": "kaspersky",
        "header": ["Name", "Login", "Password", "URL", "Notes"],
        "row": lambda name, url, username, pwd: [name, username, pwd, url, ""]
    }
}

# --- GLOBAL LOCALIZATION MAPS ---
TRANSLATIONS = {
    "pt": {
        "cli_desc": "Passweird: Suite Universal de Identidade Segura (GPLv3)",
        "arg_app": "Nome da aplicação ou contexto alvo (Ex: ufpb-sigaa)",
        "arg_ver": "Versão do algoritmo (Padrão: v2 HKDF)",
        "arg_temp": "Chave temporal ou versão (ex: 2026/01) — use uma passphrase forte com --ssl/--rsa/--pgp",
        "arg_len": "Comprimento da senha",
        "arg_para": "Modo Paranoico: oculta o nome do app ao digitar",
        "arg_upper": "Desativa letras maiúsculas",
        "arg_lower": "Desativa letras minúsculas",
        "arg_num": "Desativa números",
        "arg_spec": "Desativa símbolos especiais",
        "arg_reg": "Registra a senha-mestre atual nesta máquina",
        "arg_nocheck": "Pula a validação da senha-mestre salva",
        "arg_audit": "Modo Auditoria: valida dados contra o log local",
        "arg_save": "Salva parâmetros atuais como preferências",
        "arg_out": "Exporta dados diretamente para formatos de gerenciadores",
        "arg_force": "Pula a confirmação de divergência de flags em relação ao último uso",
        "arg_generate": "Cria um arquivo de configuração padrão comentado e sai",
        "arg_no_print_hash": "Não imprime a linha de resumo de hash no terminal",
        "arg_write": "Desativa a gravação de resumos de hash no log",
        "arg_invisible": "Imprime a senha usando uma cor invisível/igual ao fundo do terminal",
        "arg_master_file": "Lê a senha-mestre de um arquivo em texto puro (INSEGURO)",
        "arg_master_pass": "Passa a senha-mestre diretamente na linha de comando (INSEGURO)",
        "arg_temporal_file": "Lê o segredo temporal de um arquivo",
        "arg_change": "Modo de troca: gera um par de senha antiga/nova",
        "arg_file": "Processa em lote um arquivo de texto ou CSV com vários contextos",
        "arg_mass_rekey": "Regera as senhas de todos os contextos da lista de hosts sob uma nova senha-mestre",
        "arg_old_keyfile": "Keyfile física antiga a usar durante --mass-rekey",
        "arg_new_keyfile": "Keyfile física nova a usar durante --mass-rekey",
        "arg_ssh": "Gera chaves SSH Ed25519 determinísticas baseadas em contexto",
        "arg_ssl": "Gera certificados SSL/TLS autoassinados determinísticos",
        "arg_rsa": "Especifica geração SSL usando RSA e define tamanho de bits",
        "arg_totp": "Gera um segredo TOTP determinístico",
        "arg_pgp": "Gera um par de chaves PGP/OpenPGP determinístico",
        "arg_plain_log": "Desativa a criptografia AES no histórico de logs",
        "arg_keyfile": "Caminho do arquivo-chave de segundo fator",
        "arg_gen_keyfile": "Gera uma nova keyfile externa em CAMINHO (ver --recoverable)",
        "arg_recoverable": "Com --gen-keyfile: deriva da senha-mestre + frase de recuperação em vez de puro aleatório",
        "arg_fido2_register": "Registra uma nova credencial de chave de segurança FIDO2",
        "arg_fido2": "Usa a chave de segurança FIDO2 registrada como fator adicional",
        "arg_encrypt_list": "Criptografa uma lista externa de sites/sistemas (hosts)",
        "arg_view_list": "Descriptografa e exibe a lista salva de sites/sistemas",
        "temporal_weak_empty": "ATENÇÃO: sem segredo temporal. Sua senha-mestra passa a ser o único segredo protegendo esta chave publicada.",
        "temporal_weak_numeric": "ATENÇÃO: segredo temporal em forma de data ('2026/01', '08/2026') quase não acrescenta entropia — valores assim se esgotam em segundos.",
        "temporal_weak_short": "ATENÇÃO: segredo temporal muito curto. Comprimento sozinho não é força, mas abaixo de 12 caracteres não há espaço para nenhuma.",
        "temporal_weak_hint": "Prefira 6+ palavras sorteadas ao acaso (~78 bits, e esse número vale mesmo que o atacante conheça o método). Desconfie de frases espertas: um medidor de força daria ~147 bits para '[mYpAsswordiSaUgustoF26]', enquanto um ataque por regras a alcança em ~40. Veja docs/adr/0003 e o README.",
        "temporal_weak_cn": "O nome do contexto é publicado junto com este artefato (CN do certificado / UID do PGP), então ele também não acrescenta entropia aqui.",
        "rsa_slow": "Derivando primos RSA, isso pode levar alguns segundos...",
        "arg_gen_temporal": "Sorteia um segredo temporal de N palavras (padrão 6) e informa sua entropia",
        "gen_temporal_title": "=== Segredo Temporal Sorteado ===",
        "gen_temporal_bits": "Entropia: {:.0f} bits (origem: {})",
        "gen_temporal_warn": "Anote em lugar seguro antes de usar: ele não é recuperável, e perdê-lo significa perder todo segredo derivado com ele.",
        "arg_view_log": "Descriptografa e exibe todo o histórico de logs local",

        "master_prompt": "Senha-mestre: ",
        "master_prompt_confirm": "Confirme a Senha-mestre: ",
        "master_mismatch": "ERRO: As senhas digitadas não coincidem. Abortando.",
        "app_prompt": "Contexto do Aplicativo: ",
        "app_hidden": "Contexto do Aplicativo (OCULTO): ",
        "err_master_match": "ERRO CRÍTICO: A senha-mestre digitada NÃO coincide com a registrada!",
        "err_empty_app": "Erro: O contexto não pode ser vazio.",
        "master_registered": "Senha-mestre mapeada com sucesso para validações locais!",
        "warn_disabled_chars": "AVISO: Configuração personalizada desativou uma ou mais classes de caracteres.",
        "warn_disabled_remind": "Lembre-se das flags utilizadas para poder regenerar essa senha no futuro.",
        "audit_cli": "Modo Auditoria (Linha de Comando)...",
        "audit_inter": "Modo Auditoria Ativo (Interativo & Oculto)...",
        "audit_app_prompt": "Digite o Contexto do Aplicativo (Oculto): ",
        "audit_time_prompt": "Digite a Chave Temporal se houver (Oculto): ",
        "audit_match": "✔ COINCIDÊNCIA ENCONTRADA NO LOG HISTÓRICO:",
        "audit_no_match": "❌ NENHUM REGISTRO ENCONTRADO para os parâmetros informados.",
        "cfg_saved": "Configurações salvas com sucesso em: ",
        "gen_pwd": "Senha Gerada: ",
        "context": "Contexto: ",
        "time_flag": "Temporal (-T): ",
        "export_success": "Arquivo exportado com sucesso para: ",
        "export_prompt_title": "-- Informações da Entrada para o Gerenciador de Senhas --",
        "export_title": "Título/Descrição do Site: ",
        "export_url": "URL do Site: ",
        "export_user": "Usuário (Login): ",
        "confirm_mismatch": "Continuar mesmo assim? [s/N]: ",
        "old_master_prompt": "Senha-mestre antiga: ",
        "new_master_prompt": "Nova senha-mestre (Enter repete a antiga): ",
        "new_master_prompt_plain": "Nova senha-mestre: ",
        "old_app_prompt": "Senha antiga do aplicativo: ",
        "new_app_prompt": "Nova senha do aplicativo (Enter repete a antiga): ",
        "old_pwd": "Senha antiga: ",
        "new_pwd": "Nova senha: ",
        "please_old_entry": "Informe os dados da entrada ANTIGA:",
        "please_new_entry": "Informe os dados da entrada NOVA:",
        "temporal_prompt_default": "Segredo temporal (terceiro segredo) [{}]: ",
        "temporal_prompt_none": "Segredo temporal (terceiro segredo) [nenhum]: ",
        "recovery_phrase_prompt": "Frase de recuperação (necessária para regenerar esta keyfile depois): ",
        "recovery_phrase_confirm": "Confirme a frase de recuperação: ",
        "cli_secret_warning": (
            "\n*** AVISO DE SEGURANÇA ***\n"
            "Passar um segredo diretamente na linha de comando é inseguro: ele pode ficar\n"
            "no histórico do shell ou ser visível a outros usuários via lista de processos.\n"
            "Use isso apenas se entender os riscos.\n"
            "****************************\n"
        ),
        "master_file_warning": (
            "\n*** AVISO DE SEGURANÇA ***\n"
            "Guardar sua senha-mestre em um arquivo em texto puro não é recomendado.\n"
            "Esses arquivos podem ser facilmente acessados ou copiados por outros, malware,\n"
            "ou qualquer um com acesso físico ao seu dispositivo. Use isso apenas se entender\n"
            "os riscos e proteger o arquivo adequadamente.\n"
            "****************************\n"
        ),
    },
    "es": {
        "cli_desc": "Passweird: Suite Universal de Identidad Segura (GPLv3)",
        "arg_app": "Nombre de la aplicación o contexto (Ej: ufpb-sigaa)",
        "arg_ver": "Versión del algoritmo (Predeterminado: v2 HKDF)",
        "arg_temp": "Clave temporal o versión (ej: 2026/01) — use una frase fuerte con --ssl/--rsa/--pgp",
        "arg_len": "Longitud de la contraseña",
        "arg_para": "Modo paranoico: oculta el nombre de la app al escribir",
        "arg_upper": "Desactiva letras mayúsculas",
        "arg_lower": "Desactiva letras minúsculas",
        "arg_num": "Desactiva números",
        "arg_spec": "Desactiva símbolos especiales",
        "arg_reg": "Registra el hash de la contraseña maestra actual en esta máquina",
        "arg_nocheck": "Omite la verificación de la contraseña maestra guardada",
        "arg_audit": "Modo auditoría: valida datos contra el historial local",
        "arg_save": "Guarda los parámetros actuales como preferencias",
        "arg_out": "Exporta directamente a formatos de gestores de contraseñas",
        "arg_force": "Omite la confirmación de discrepancia de opciones respecto al último uso",
        "arg_generate": "Crea un archivo de configuración predeterminado comentado y sale",
        "arg_no_print_hash": "No imprime la línea de resumen de hash en la terminal",
        "arg_write": "Desactiva la escritura de resúmenes de hash en el log",
        "arg_invisible": "Imprime la contraseña usando un color invisible/igual al fondo",
        "arg_master_file": "Lee la contraseña maestra de un archivo en texto plano (INSEGURO)",
        "arg_master_pass": "Pasa la contraseña maestra directamente en la línea de comandos (INSEGURO)",
        "arg_temporal_file": "Lee el secreto temporal de un archivo",
        "arg_change": "Modo cambio: genera un par de contraseña antigua/nueva",
        "arg_file": "Procesa en lote un archivo de texto o CSV con varios contextos",
        "arg_mass_rekey": "Regenera las contraseñas de todos los contextos de la lista de hosts con una nueva contraseña maestra",
        "arg_old_keyfile": "Keyfile física antigua para usar durante --mass-rekey",
        "arg_new_keyfile": "Keyfile física nueva para usar durante --mass-rekey",
        "arg_ssh": "Genera claves SSH Ed25519 determinísticas basadas en el contexto",
        "arg_ssl": "Genera certificados SSL/TLS autofirmados determinísticos",
        "arg_rsa": "Especifica generación SSL usando RSA y define el tamaño en bits",
        "arg_totp": "Genera un secreto TOTP determinístico",
        "arg_pgp": "Genera un par de claves PGP/OpenPGP determinístico",
        "arg_plain_log": "Desactiva el cifrado AES en el historial de logs",
        "arg_keyfile": "Ruta del archivo-clave de segundo factor",
        "arg_gen_keyfile": "Genera una nueva keyfile externa en RUTA (ver --recoverable)",
        "arg_recoverable": "Con --gen-keyfile: deriva de la contraseña maestra + frase de recuperación en vez de puro azar",
        "arg_fido2_register": "Registra una nueva credencial de llave de seguridad FIDO2",
        "arg_fido2": "Usa la llave de seguridad FIDO2 registrada como factor adicional",
        "arg_encrypt_list": "Cifra una lista externa de sitios/sistemas (hosts)",
        "arg_view_list": "Descifra y muestra la lista guardada de sitios/sistemas",
        "arg_view_log": "Descifra y muestra todo el historial de logs local",

        "master_prompt": "Contraseña maestra: ",
        "master_prompt_confirm": "Confirme la contraseña maestra: ",
        "master_mismatch": "ERROR: Las contraseñas no coinciden. Abortando.",
        "app_prompt": "Contexto de la aplicación: ",
        "app_hidden": "Contexto de la aplicación (OCULTO): ",
        "err_master_match": "ERROR CRÍTICO: ¡La contraseña maestra ingresada NO coincide con la registrada!",
        "err_empty_app": "Error: el contexto no puede estar vacío.",
        "master_registered": "¡Contraseña maestra registrada con éxito para validaciones locales!",
        "warn_disabled_chars": "AVISO: la configuración personalizada desactivó una o más clases de caracteres.",
        "warn_disabled_remind": "Recuerde las opciones usadas para poder regenerar esta contraseña en el futuro.",
        "audit_cli": "Modo auditoría (línea de comandos)...",
        "audit_inter": "Modo auditoría activo (interactivo y oculto)...",
        "audit_app_prompt": "Ingrese el contexto de la aplicación (oculto): ",
        "audit_time_prompt": "Ingrese la clave temporal si aplica (oculto): ",
        "audit_match": "✔ COINCIDENCIA ENCONTRADA EN EL HISTORIAL:",
        "audit_no_match": "❌ NO SE ENCONTRÓ NINGÚN REGISTRO para los datos proporcionados.",
        "cfg_saved": "Configuración guardada con éxito en: ",
        "gen_pwd": "Contraseña Generada: ",
        "context": "Contexto: ",
        "time_flag": "Temporal (-T): ",
        "export_success": "Archivo exportado con éxito a: ",
        "export_prompt_title": "-- Información de la entrada para el gestor de contraseñas --",
        "export_title": "Título/Descripción del sitio: ",
        "export_url": "URL del sitio: ",
        "export_user": "Usuario (Login): ",
        "confirm_mismatch": "¿Continuar de todas formas? [s/N]: ",
        "old_master_prompt": "Contraseña maestra antigua: ",
        "new_master_prompt": "Nueva contraseña maestra (Enter repite la antigua): ",
        "new_master_prompt_plain": "Nueva contraseña maestra: ",
        "old_app_prompt": "Contraseña antigua de la aplicación: ",
        "new_app_prompt": "Nueva contraseña de la aplicación (Enter repite la antigua): ",
        "old_pwd": "Contraseña antigua: ",
        "new_pwd": "Contraseña nueva: ",
        "please_old_entry": "Ingrese los datos de la entrada ANTIGUA:",
        "please_new_entry": "Ingrese los datos de la entrada NUEVA:",
        "temporal_prompt_default": "Secreto temporal (tercer secreto) [{}]: ",
        "temporal_prompt_none": "Secreto temporal (tercer secreto) [ninguno]: ",
        "recovery_phrase_prompt": "Frase de recuperación (necesaria para regenerar esta keyfile luego): ",
        "recovery_phrase_confirm": "Confirme la frase de recuperación: ",
        "cli_secret_warning": (
            "\n*** AVISO DE SEGURIDAD ***\n"
            "Pasar un secreto directamente en la línea de comandos es inseguro: puede quedar\n"
            "en el historial de la shell o ser visible para otros usuarios vía la lista de procesos.\n"
            "Use esto solo si entiende los riesgos.\n"
            "****************************\n"
        ),
        "master_file_warning": (
            "\n*** AVISO DE SEGURIDAD ***\n"
            "Guardar su contraseña maestra en un archivo de texto plano no es recomendable.\n"
            "Esos archivos pueden ser fácilmente accedidos o copiados por otros, malware, o\n"
            "cualquiera con acceso físico a su dispositivo. Use esto solo si entiende los\n"
            "riesgos y protege el archivo adecuadamente.\n"
            "****************************\n"
        ),
    },
    "fr": {
        "cli_desc": "Passweird : suite universelle d'identité sécurisée (GPLv3)",
        "arg_app": "Nom de l'application ou du contexte (ex : ufpb-sigaa)",
        "arg_ver": "Version de l'algorithme (par défaut : v2 HKDF)",
        "arg_temp": "Clé/sel temporel (ex : 2026/01) — utilisez une phrase forte avec --ssl/--rsa/--pgp",
        "arg_len": "Longueur du mot de passe",
        "arg_para": "Mode paranoïaque : masque la saisie du nom de l'application",
        "arg_upper": "Désactive les lettres majuscules",
        "arg_lower": "Désactive les lettres minuscules",
        "arg_num": "Désactive les chiffres",
        "arg_spec": "Désactive les caractères spéciaux",
        "arg_reg": "Enregistre le hash du mot de passe maître actuel sur cette machine",
        "arg_nocheck": "Ignore la vérification du mot de passe maître enregistré",
        "arg_audit": "Mode audit : vérifie si les identifiants existent dans l'historique local",
        "arg_save": "Enregistre les options actuelles comme préférences par défaut",
        "arg_out": "Exporte directement au format CSV d'un gestionnaire de mots de passe",
        "arg_force": "Ignore la confirmation en cas de divergence avec les options précédentes",
        "arg_generate": "Crée un fichier de configuration par défaut commenté et quitte",
        "arg_no_print_hash": "N'affiche pas la ligne de résumé de hash dans le terminal",
        "arg_write": "Désactive l'écriture des résumés de hash dans le journal",
        "arg_invisible": "Affiche le mot de passe avec une couleur invisible/identique au fond",
        "arg_master_file": "Lit le mot de passe maître depuis un fichier en texte clair (NON SÉCURISÉ)",
        "arg_master_pass": "Passe le mot de passe maître directement en ligne de commande (NON SÉCURISÉ)",
        "arg_temporal_file": "Lit le secret temporel depuis un fichier",
        "arg_change": "Mode changement : génère une paire ancien/nouveau mot de passe",
        "arg_file": "Traite en lot un fichier texte ou CSV contenant plusieurs contextes",
        "arg_mass_rekey": "Régénère les mots de passe de tous les contextes de la liste d'hôtes sous un nouveau mot de passe maître",
        "arg_old_keyfile": "Ancien fichier-clé physique à utiliser pendant --mass-rekey",
        "arg_new_keyfile": "Nouveau fichier-clé physique à utiliser pendant --mass-rekey",
        "arg_ssh": "Génère une paire de clés SSH Ed25519 déterministe basée sur le contexte",
        "arg_ssl": "Génère des certificats SSL/TLS auto-signés déterministes",
        "arg_rsa": "Spécifie une génération SSL utilisant RSA et définit la taille en bits",
        "arg_totp": "Génère un secret TOTP déterministe",
        "arg_pgp": "Génère une paire de clés PGP/OpenPGP déterministe",
        "arg_plain_log": "Désactive le chiffrement AES de l'historique des journaux",
        "arg_keyfile": "Chemin du fichier-clé utilisé comme second facteur",
        "arg_gen_keyfile": "Génère un nouveau fichier-clé externe à CHEMIN (voir --recoverable)",
        "arg_recoverable": "Avec --gen-keyfile : dérive du mot de passe maître + une phrase de récupération au lieu d'être purement aléatoire",
        "arg_fido2_register": "Enregistre une nouvelle clé de sécurité FIDO2",
        "arg_fido2": "Utilise la clé de sécurité FIDO2 enregistrée comme facteur supplémentaire",
        "arg_encrypt_list": "Chiffre un fichier texte externe contenant des hôtes/systèmes",
        "arg_view_list": "Déchiffre et affiche la liste enregistrée d'hôtes/systèmes",
        "arg_view_log": "Déchiffre et affiche tout l'historique local des journaux",

        "master_prompt": "Mot de passe maître : ",
        "master_prompt_confirm": "Confirmez le mot de passe maître : ",
        "master_mismatch": "ERREUR : les mots de passe ne correspondent pas. Abandon.",
        "app_prompt": "Contexte de l'application : ",
        "app_hidden": "Contexte de l'application (MODE MASQUÉ) : ",
        "err_master_match": "ERREUR CRITIQUE : le mot de passe maître saisi NE correspond PAS à celui enregistré !",
        "err_empty_app": "Erreur : le contexte ne peut pas être vide.",
        "master_registered": "Hash du mot de passe maître enregistré avec succès pour les validations locales !",
        "warn_disabled_chars": "AVERTISSEMENT : la configuration personnalisée a désactivé une ou plusieurs classes de caractères.",
        "warn_disabled_remind": "Retenez les options utilisées pour pouvoir régénérer ce mot de passe plus tard.",
        "audit_cli": "Mode audit (ligne de commande)...",
        "audit_inter": "Mode audit actif (interactif et masqué)...",
        "audit_app_prompt": "Entrez le contexte de l'application (masqué) : ",
        "audit_time_prompt": "Entrez la clé temporelle si applicable (masqué) : ",
        "audit_match": "✔ CORRESPONDANCE TROUVÉE DANS L'HISTORIQUE :",
        "audit_no_match": "❌ AUCUN ENREGISTREMENT TROUVÉ pour les identifiants fournis.",
        "cfg_saved": "Préférences enregistrées avec succès dans : ",
        "gen_pwd": "Mot de passe généré : ",
        "context": "Contexte : ",
        "time_flag": "Temporel (-T) : ",
        "export_success": "Fichier exporté avec succès vers : ",
        "export_prompt_title": "-- Informations de l'entrée pour le gestionnaire de mots de passe --",
        "export_title": "Titre/Description du site : ",
        "export_url": "URL du site : ",
        "export_user": "Nom d'utilisateur (identifiant) : ",
        "confirm_mismatch": "Continuer quand même ? [o/N] : ",
        "old_master_prompt": "Ancien mot de passe maître : ",
        "new_master_prompt": "Nouveau mot de passe maître (Entrée pour répéter l'ancien) : ",
        "new_master_prompt_plain": "Nouveau mot de passe maître : ",
        "old_app_prompt": "Ancien mot de passe de l'application : ",
        "new_app_prompt": "Nouveau mot de passe de l'application (Entrée pour répéter l'ancien) : ",
        "old_pwd": "Ancien mot de passe : ",
        "new_pwd": "Nouveau mot de passe : ",
        "please_old_entry": "Veuillez saisir les informations de l'entrée ANCIENNE :",
        "please_new_entry": "Veuillez saisir les informations de l'entrée NOUVELLE :",
        "temporal_prompt_default": "Secret temporel (troisième secret) [{}] : ",
        "temporal_prompt_none": "Secret temporel (troisième secret) [aucun] : ",
        "recovery_phrase_prompt": "Phrase de récupération (nécessaire pour régénérer ce fichier-clé plus tard) : ",
        "recovery_phrase_confirm": "Confirmez la phrase de récupération : ",
        "cli_secret_warning": (
            "\n*** AVERTISSEMENT DE SÉCURITÉ ***\n"
            "Passer un secret directement en ligne de commande est non sécurisé : il peut se\n"
            "retrouver dans l'historique du shell ou être visible via la liste des processus.\n"
            "N'utilisez ceci que si vous comprenez les risques.\n"
            "****************************\n"
        ),
        "master_file_warning": (
            "\n*** AVERTISSEMENT DE SÉCURITÉ ***\n"
            "Stocker votre mot de passe maître dans un fichier en texte clair n'est pas\n"
            "recommandé. Ces fichiers peuvent être facilement consultés ou copiés par\n"
            "d'autres, un logiciel malveillant, ou toute personne ayant un accès physique à\n"
            "votre appareil. N'utilisez ceci que si vous comprenez les risques.\n"
            "****************************\n"
        ),
    },
    "de": {
        "cli_desc": "Passweird: Universelle sichere Identitäts-Suite (GPLv3)",
        "arg_app": "Name der Anwendung oder des Kontexts (z. B. ufpb-sigaa)",
        "arg_ver": "Algorithmusversion (Standard: v2 HKDF)",
        "arg_temp": "Temporäres Salt/Schlüsselversion (z. B. 2026/01) — für --ssl/--rsa/--pgp starke Passphrase verwenden",
        "arg_len": "Passwortlänge",
        "arg_para": "Paranoider Modus: verbirgt die Eingabe des App-Namens",
        "arg_upper": "Deaktiviert Großbuchstaben",
        "arg_lower": "Deaktiviert Kleinbuchstaben",
        "arg_num": "Deaktiviert Zahlen",
        "arg_spec": "Deaktiviert Sonderzeichen",
        "arg_reg": "Registriert den aktuellen Master-Passwort-Hash auf diesem Rechner",
        "arg_nocheck": "Überspringt die Prüfung des gespeicherten Master-Passworts",
        "arg_audit": "Audit-Modus: prüft, ob Zugangsdaten im lokalen Verlauf existieren",
        "arg_save": "Speichert die aktuellen Optionen als Standardeinstellungen",
        "arg_out": "Exportiert direkt in ein Passwortmanager-CSV-Format",
        "arg_force": "Überspringt die Bestätigung bei Abweichung von zuletzt verwendeten Optionen",
        "arg_generate": "Erstellt eine kommentierte Standard-Konfigurationsdatei und beendet",
        "arg_no_print_hash": "Zeigt die Hash-Zusammenfassungszeile nicht im Terminal an",
        "arg_write": "Deaktiviert das Schreiben von Hash-Zusammenfassungen ins Protokoll",
        "arg_invisible": "Zeigt das Passwort in einer unsichtbaren/hintergrundgleichen Farbe an",
        "arg_master_file": "Liest das Master-Passwort aus einer Klartextdatei (UNSICHER)",
        "arg_master_pass": "Übergibt das Master-Passwort direkt über die Kommandozeile (UNSICHER)",
        "arg_temporal_file": "Liest das temporäre Geheimnis aus einer Datei",
        "arg_change": "Änderungsmodus: erzeugt ein altes/neues Passwortpaar",
        "arg_file": "Verarbeitet eine Text- oder CSV-Datei mit mehreren Kontexten im Batch-Modus",
        "arg_mass_rekey": "Regeneriert die Passwörter aller Kontexte der Hosts-Liste unter einem neuen Master-Passwort",
        "arg_old_keyfile": "Alte physische Schlüsseldatei für --mass-rekey",
        "arg_new_keyfile": "Neue physische Schlüsseldatei für --mass-rekey",
        "arg_ssh": "Erzeugt deterministische SSH-Ed25519-Schlüssel basierend auf dem Kontext",
        "arg_ssl": "Erzeugt deterministische selbstsignierte SSL/TLS-Zertifikate",
        "arg_rsa": "Legt die SSL-Erzeugung mit RSA fest und definiert die Schlüssellänge in Bit",
        "arg_totp": "Erzeugt ein deterministisches TOTP-Geheimnis",
        "arg_pgp": "Erzeugt ein deterministisches PGP/OpenPGP-Schlüsselpaar",
        "arg_plain_log": "Deaktiviert die AES-Verschlüsselung des Protokollverlaufs",
        "arg_keyfile": "Pfad zur physischen Schlüsseldatei als zweiter Faktor",
        "arg_gen_keyfile": "Erzeugt eine neue externe Schlüsseldatei unter PFAD (siehe --recoverable)",
        "arg_recoverable": "Mit --gen-keyfile: Ableitung aus Master-Passwort + Wiederherstellungsphrase statt reinem Zufall",
        "arg_fido2_register": "Registriert einen neuen FIDO2-Sicherheitsschlüssel",
        "arg_fido2": "Verwendet den registrierten FIDO2-Sicherheitsschlüssel als zusätzlichen Faktor",
        "arg_encrypt_list": "Verschlüsselt eine externe Textdatei mit Hosts/Systemen",
        "arg_view_list": "Entschlüsselt und zeigt die gespeicherte Hosts-/Systemliste an",
        "arg_view_log": "Entschlüsselt und zeigt den gesamten lokalen Protokollverlauf an",

        "master_prompt": "Master-Passwort: ",
        "master_prompt_confirm": "Master-Passwort bestätigen: ",
        "master_mismatch": "FEHLER: Die Passwörter stimmen nicht überein. Abbruch.",
        "app_prompt": "Anwendungskontext: ",
        "app_hidden": "Anwendungskontext (VERBORGENER MODUS): ",
        "err_master_match": "KRITISCHER FEHLER: Das eingegebene Master-Passwort stimmt NICHT mit dem registrierten überein!",
        "err_empty_app": "Fehler: Der Kontext darf nicht leer sein.",
        "master_registered": "Master-Passwort-Hash erfolgreich für lokale Prüfungen registriert!",
        "warn_disabled_chars": "WARNUNG: Die benutzerdefinierte Konfiguration hat eine oder mehrere Zeichenklassen deaktiviert.",
        "warn_disabled_remind": "Merken Sie sich die verwendeten Optionen, um dieses Passwort später erneut erzeugen zu können.",
        "audit_cli": "Audit-Modus (Kommandozeile)...",
        "audit_inter": "Audit-Modus aktiv (interaktiv & verborgen)...",
        "audit_app_prompt": "Anwendungskontext eingeben (verborgen): ",
        "audit_time_prompt": "Temporären Schlüssel eingeben, falls zutreffend (verborgen): ",
        "audit_match": "✔ ÜBEREINSTIMMUNG IM PROTOKOLLVERLAUF GEFUNDEN:",
        "audit_no_match": "❌ KEIN EINTRAG für die angegebenen Daten gefunden.",
        "cfg_saved": "Einstellungen erfolgreich gespeichert unter: ",
        "gen_pwd": "Erzeugtes Passwort: ",
        "context": "Kontext: ",
        "time_flag": "Temporal (-T): ",
        "export_success": "Datei erfolgreich exportiert nach: ",
        "export_prompt_title": "-- Eintragsinformationen für den Passwortmanager --",
        "export_title": "Titel/Beschreibung der Seite: ",
        "export_url": "URL der Seite: ",
        "export_user": "Benutzername (Login): ",
        "confirm_mismatch": "Trotzdem fortfahren? [j/N]: ",
        "old_master_prompt": "Altes Master-Passwort: ",
        "new_master_prompt": "Neues Master-Passwort (Enter, um das alte zu wiederholen): ",
        "new_master_prompt_plain": "Neues Master-Passwort: ",
        "old_app_prompt": "Altes Anwendungspasswort: ",
        "new_app_prompt": "Neues Anwendungspasswort (Enter, um das alte zu wiederholen): ",
        "old_pwd": "Altes Passwort: ",
        "new_pwd": "Neues Passwort: ",
        "please_old_entry": "Bitte Informationen für den ALTEN Eintrag angeben:",
        "please_new_entry": "Bitte Informationen für den NEUEN Eintrag angeben:",
        "temporal_prompt_default": "Temporäres Geheimnis (drittes Geheimnis) [{}]: ",
        "temporal_prompt_none": "Temporäres Geheimnis (drittes Geheimnis) [keins]: ",
        "recovery_phrase_prompt": "Wiederherstellungsphrase (nötig, um diese Schlüsseldatei später neu zu erzeugen): ",
        "recovery_phrase_confirm": "Wiederherstellungsphrase bestätigen: ",
        "cli_secret_warning": (
            "\n*** SICHERHEITSWARNUNG ***\n"
            "Ein Geheimnis direkt in der Kommandozeile zu übergeben ist unsicher: es kann im\n"
            "Shell-Verlauf landen oder für andere Nutzer über die Prozessliste sichtbar sein.\n"
            "Verwenden Sie dies nur, wenn Sie die Risiken verstehen.\n"
            "****************************\n"
        ),
        "master_file_warning": (
            "\n*** SICHERHEITSWARNUNG ***\n"
            "Das Speichern Ihres Master-Passworts in einer Klartextdatei wird nicht empfohlen.\n"
            "Solche Dateien können leicht von anderen, von Schadsoftware oder von jemandem mit\n"
            "physischem Zugriff auf Ihr Gerät eingesehen oder kopiert werden. Verwenden Sie dies\n"
            "nur, wenn Sie die Risiken verstehen und die Datei angemessen schützen.\n"
            "****************************\n"
        ),
    },
    "zh": {
        "cli_desc": "Passweird：通用安全身份套件 (GPLv3)",
        "arg_app": "应用程序或上下文名称（例如：ufpb-sigaa）",
        "arg_ver": "算法版本（默认：v2 HKDF）",
        "arg_temp": "临时盐值/密钥版本（例如：2026/01）——用于 --ssl/--rsa/--pgp 时请使用高强度口令",
        "arg_len": "密码长度",
        "arg_para": "偏执模式：输入时隐藏应用名称",
        "arg_upper": "禁用大写字母",
        "arg_lower": "禁用小写字母",
        "arg_num": "禁用数字",
        "arg_spec": "禁用特殊符号",
        "arg_reg": "将当前主密码哈希注册为本机默认值",
        "arg_nocheck": "跳过已保存主密码的校验",
        "arg_audit": "审计模式：在本地日志历史中验证凭据",
        "arg_save": "将当前选项保存为默认首选项",
        "arg_out": "直接导出为密码管理器的CSV格式",
        "arg_force": "跳过与上次使用选项不一致时的确认提示",
        "arg_generate": "创建一个带注释的默认配置文件并退出",
        "arg_no_print_hash": "不在终端中打印哈希摘要行",
        "arg_write": "禁止将哈希摘要写入日志",
        "arg_invisible": "使用隐形/与背景相同的颜色打印密码",
        "arg_master_file": "从纯文本文件读取主密码（不安全）",
        "arg_master_pass": "直接在命令行中传递主密码（不安全）",
        "arg_temporal_file": "从文件读取临时密钥",
        "arg_change": "更改模式：生成新旧密码对",
        "arg_file": "批量处理包含多个上下文的文本或CSV文件",
        "arg_mass_rekey": "在新主密码下重新生成主机列表中所有上下文的密码",
        "arg_old_keyfile": "--mass-rekey 期间使用的旧物理密钥文件",
        "arg_new_keyfile": "--mass-rekey 期间使用的新物理密钥文件",
        "arg_ssh": "基于上下文生成确定性的SSH Ed25519密钥",
        "arg_ssl": "生成确定性的自签名SSL/TLS证书",
        "arg_rsa": "指定使用RSA生成SSL并定义位数",
        "arg_totp": "生成确定性的TOTP密钥",
        "arg_pgp": "生成确定性的PGP/OpenPGP密钥对",
        "arg_plain_log": "禁用历史日志的AES加密",
        "arg_keyfile": "作为第二因素的物理密钥文件路径",
        "arg_gen_keyfile": "在路径PATH处生成新的外部密钥文件（参见--recoverable）",
        "arg_recoverable": "配合--gen-keyfile：由主密码+恢复短语派生，而非纯随机生成",
        "arg_fido2_register": "注册新的FIDO2安全密钥凭据",
        "arg_fido2": "使用已注册的FIDO2安全密钥作为附加因素",
        "arg_encrypt_list": "加密包含主机/系统的外部文本文件",
        "arg_view_list": "解密并显示已保存的主机/系统列表",
        "arg_view_log": "解密并显示完整的本地日志历史",

        "master_prompt": "主密码：",
        "master_prompt_confirm": "确认主密码：",
        "master_mismatch": "错误：两次输入的密码不一致。正在中止。",
        "app_prompt": "应用程序上下文：",
        "app_hidden": "应用程序上下文（隐藏模式）：",
        "err_master_match": "严重错误：输入的主密码与已注册的不一致！",
        "err_empty_app": "错误：上下文不能为空。",
        "master_registered": "主密码哈希已成功注册用于本地校验！",
        "warn_disabled_chars": "警告：自定义配置禁用了一个或多个字符类别。",
        "warn_disabled_remind": "请记住所使用的选项，以便将来能重新生成此密码。",
        "audit_cli": "审计模式（命令行）...",
        "audit_inter": "审计模式已激活（交互式且隐藏）...",
        "audit_app_prompt": "输入应用程序上下文（隐藏）：",
        "audit_time_prompt": "如适用，输入临时密钥（隐藏）：",
        "audit_match": "✔ 在日志历史中找到匹配项：",
        "audit_no_match": "❌ 未找到与所提供凭据匹配的记录。",
        "cfg_saved": "首选项已成功保存至：",
        "gen_pwd": "生成的密码：",
        "context": "上下文：",
        "time_flag": "临时（-T）：",
        "export_success": "文件已成功导出至：",
        "export_prompt_title": "-- 密码管理器条目信息 --",
        "export_title": "网站标题/描述：",
        "export_url": "网站URL：",
        "export_user": "用户名（登录名）：",
        "confirm_mismatch": "仍要继续吗？[y/N]：",
        "old_master_prompt": "旧主密码：",
        "new_master_prompt": "新主密码（按回车重复旧密码）：",
        "new_master_prompt_plain": "新主密码：",
        "old_app_prompt": "旧应用程序密码：",
        "new_app_prompt": "新应用程序密码（按回车重复旧密码）：",
        "old_pwd": "旧密码：",
        "new_pwd": "新密码：",
        "please_old_entry": "请输入旧条目的信息：",
        "please_new_entry": "请输入新条目的信息：",
        "temporal_prompt_default": "临时密钥（第三密钥）[{}]：",
        "temporal_prompt_none": "临时密钥（第三密钥）[无]：",
        "recovery_phrase_prompt": "恢复短语（稍后重新生成此密钥文件所需）：",
        "recovery_phrase_confirm": "确认恢复短语：",
        "cli_secret_warning": (
            "\n*** 安全警告 ***\n"
            "直接在命令行中传递密钥是不安全的：它可能会保留在shell历史记录中，\n"
            "或通过进程列表被其他用户看到。\n"
            "只有在了解风险的情况下才使用此选项。\n"
            "****************************\n"
        ),
        "master_file_warning": (
            "\n*** 安全警告 ***\n"
            "不建议将主密码存储在纯文本文件中。\n"
            "此类文件可能很容易被他人、恶意软件访问或复制，\n"
            "或被任何可物理接触您设备的人获取。请仅在了解风险并妥善保护该文件的情况下使用。\n"
            "****************************\n"
        ),
    },
}

try:
    sys_lang = locale.getdefaultlocale()[0]
    lang_code = sys_lang.split('_')[0] if sys_lang else 'en'
except Exception:
    lang_code = 'en'

LOCAL_MAP = TRANSLATIONS.get(lang_code, {})

def _(text_key, default_en):
    return LOCAL_MAP.get(text_key, default_en)

def load_settings():
    cfg_path = os.path.expanduser("~/.passweird/passweird.cfg")
    settings = {}
    if not os.path.exists(cfg_path):
        return settings
    try:
        with open(cfg_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if v.lower() in ["true", "yes"]: v = True
                elif v.lower() in ["false", "no"]: v = False
                else:
                    try: v = int(v)
                    except ValueError: pass
                settings[k] = v
    except Exception as e:
        print(f"Warning: Could not read settings file: {e}")
    return settings

def create_default_config(config_path):
    """
    Create a default configuration file with commented-out options for user
    customization, if it doesn't already exist.
    """
    default_content = """\
# passweird configuration file
# Password generation algorithm is fixed to v2 (HKDF-SHA512).
# Default password length (minimum 8, or 6 for numeric-only passwords).
# length=18
# Paranoid mode: hide the app/context name input.
# paranoid=False
# Disable use of uppercase letters (True/False).
# no_uppercase=False
# Disable use of lowercase letters (True/False).
# no_lowercase=False
# Disable use of digits (True/False).
# no_numbers=False
# Disable use of special characters (True/False).
# no_specials=False
# Enable password change mode (old/new) by default (True/False).
# change=False
# Disable writing hash summaries to the log (True/False).
# write=False
# Disable printing the hash-summary line in the terminal (True/False).
# no_print_hash=False
# Invisible password printing color (e.g. black, red, blue...).
# invisible_password=black
# Batch file path for bulk operations (plain text or CSV).
# file=~/.passweird/passweird.pwd
# Temporal secret file path (third secret).
# temporal_secret_file=~/.passweird/passweird.temporal
"""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    if not os.path.exists(config_path):
        with open(config_path, "w") as f:
            f.write(default_content)
        print(f"Default configuration file created at '{config_path}'.")
    else:
        print(f"Config file '{config_path}' already exists; skipping creation.")

def save_settings(settings_dict):
    log_dir = os.path.expanduser("~/.passweird")
    os.makedirs(log_dir, exist_ok=True)
    cfg_path = os.path.join(log_dir, "passweird.cfg")
    with open(cfg_path, "w") as f:
        f.write("# Passweird automatic configuration file\n")
        for k, v in settings_dict.items():
            f.write(f"{k}={v}\n")
    return cfg_path

def print_command_line_warning():
    """Warns that passing secrets directly on the command line is insecure
    (shell history / process list exposure)."""
    print(_(
        "cli_secret_warning",
        "\n*** SECURITY WARNING ***\n"
        "Passing a secret directly on the command line is insecure: it may end up\n"
        "in your shell history or be visible to other users via the process list.\n"
        "Use this only if you understand the risks.\n"
        "****************************\n"
    ))

def read_master_password_file(file_path):
    """Reads the master password from a plaintext file; prints a security warning."""
    print(_(
        "master_file_warning",
        "\n*** SECURITY WARNING ***\n"
        "Storing your master password in a plaintext file is not recommended.\n"
        "Such files may be easily accessed or copied by others, malware, or anyone\n"
        "with physical access to your device. Use this only if you understand the\n"
        "risks and protect the file properly.\n"
        "****************************\n"
    ))
    with open(os.path.expanduser(file_path), 'r') as f:
        return f.read().strip()

def read_temporal_secret_file(file_path):
    """Reads a temporal secret from a file. Returns None if missing/unreadable."""
    try:
        with open(os.path.expanduser(file_path), 'r') as f:
            return f.read().strip()
    except Exception:
        return None

def prompt_temporal_secret(default_value=''):
    """Prompts for a temporal secret, allowing Enter to repeat default_value."""
    response = input(_('temporal_prompt_default', "Temporal secret (third secret) [{}]: ").format(default_value)).strip()
    return response if response else default_value

# Deliberately conservative: flags shapes that are unarguably guessable and stays
# silent about everything else.
_DATE_OR_NUMERIC = re.compile(r"^[\d\W_]+$")

_WORDLIST_PATHS = (
    "/usr/share/dict/words",
    "/usr/share/dict/american-english",
    "/usr/share/dict/british-english",
)

def _load_wordlist(minimum=2048):
    """Loads a system wordlist, keeping only plain lowercase words of usable length."""
    for path in _WORDLIST_PATHS:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = {
                    w for w in (line.strip().lower() for line in f)
                    if 3 <= len(w) <= 8 and w.isascii() and w.isalpha()
                }
        except OSError:
            continue
        if len(words) >= minimum:
            return sorted(words)
    return None

def generate_temporal_secret(words=6):
    """
    Draws a temporal secret at random and reports how many bits it actually carries.

    This exists because no wording in the documentation fixes the underlying problem.
    Human "free" choice clusters hard — the classic red-hammer result — and suggesting
    a different shape only moves the cluster somewhere else. Worse, any pattern the
    documentation suggests becomes a rule the attacker can enumerate, while the user
    is merely nudged by it: suggestions help the attacker more than the user. The only
    way out is to take the choice away from the human, which is what this does.

    Returns (secret, bits, source). Uses secrets, never random.
    """
    if words < 1:
        raise ValueError("At least one word is required.")

    pool = _load_wordlist()
    if pool:
        chosen = [secrets.choice(pool) for _ in range(words)]
        return " ".join(chosen), words * math.log2(len(pool)), "wordlist"

    # No system wordlist: fall back to characters, sized to match the same entropy
    # target so the caller never silently gets a weaker secret than it asked for.
    alphabet = string.ascii_lowercase + string.digits
    target_bits = words * math.log2(7776)
    length = math.ceil(target_bits / math.log2(len(alphabet)))
    raw = "".join(secrets.choice(alphabet) for _ in range(length))
    grouped = "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))
    return grouped, length * math.log2(len(alphabet)), "charset"

def weak_temporal_secret_reason(temporal_salt):
    """
    Returns 'empty', 'short' or 'numeric' when the temporal secret is obviously
    guessable, or None otherwise.

    There is intentionally no strength score here. A charset-times-length estimate
    would rate "[mYpAsswordiSaUgustoF26]" at ~147 bits, while a dictionary of
    plausible phrases crossed with a standard transformation rule set reaches it in
    around 40 — the score would actively bless the weakest kind of "strong-looking"
    secret. Categorical guidance plus a pointer to the docs is more honest than a
    number that is wrong in the direction of false confidence.

    Returning None therefore means "not obviously weak", never "strong".
    """
    if not temporal_salt:
        return 'empty'
    if _DATE_OR_NUMERIC.match(temporal_salt):
        return 'numeric'
    if len(temporal_salt) < 12:
        return 'short'
    return None

# --- HOSTS / SITES ENCRYPTED LIST MANAGEMENT ---

def encrypt_and_save_hosts(master_hash, source_file_path):
    """Encrypts a plain text file containing hosts/systems into ~/.passweird/hosts.enc."""
    if not os.path.exists(source_file_path):
        raise FileNotFoundError(f"Source file not found: {source_file_path}")
        
    with open(source_file_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    encrypted_payload = crypto.encrypt_data(master_hash, content)
    
    target_dir = os.path.expanduser("~/.passweird")
    os.makedirs(target_dir, exist_ok=True)
    target_file = os.path.join(target_dir, "hosts.enc")
    
    with open(target_file, "wb") as f:
        f.write(encrypted_payload)
        
    return target_file

def read_encrypted_hosts(master_hash):
    """Decrypts and returns the stored list of systems/hosts from ~/.passweird/hosts.enc."""
    target_file = os.path.expanduser("~/.passweird/hosts.enc")
    if not os.path.exists(target_file):
        return None
        
    with open(target_file, "rb") as f:
        encrypted_payload = f.read()
        
    return crypto.decrypt_data(master_hash, encrypted_payload)

# --- LOGS STORAGE PIPELINES ---

def log_hashes_to_file(line, master_hash=None, encrypt=True):
    log_dir = os.path.expanduser("~/.passweird")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "passweird.log")
    
    if encrypt and master_hash:
        try:
            encrypted_payload = crypto.encrypt_data(master_hash, line)
            with open(log_path, "ab") as f:
                f.write(len(encrypted_payload).to_bytes(4, byteorder='big') + encrypted_payload)
        except Exception as e:
            print(f"Warning: Could not write encrypted log: {e}")
    else:
        try:
            with open(log_path, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            print(f"Warning: Could not write plaintext log: {e}")

def read_logs_from_file(master_hash=None):
    """
    Reads the log, auto-detecting plaintext (--plain-log) vs AES-GCM-encrypted
    (default) format. Plaintext log lines always start with a 14-digit
    YYYYMMDDHHMMSS date_str (see build_and_log_line), which can never
    coincide with an encrypted block's raw 4-byte length prefix — used here
    as an unambiguous format discriminator. (Previously this tried to detect
    the format via exception-based fallback, but misparsing plaintext bytes
    as fake binary length-prefixed blocks doesn't actually raise — it just
    silently reads garbage until EOF, so the plaintext fallback never fired.)
    """
    log_path = os.path.expanduser("~/.passweird/passweird.log")
    if not os.path.exists(log_path):
        return []

    with open(log_path, "rb") as f:
        raw = f.read()
    if not raw:
        return []

    if raw[:14].isascii() and raw[:14].decode("ascii").isdigit():
        return [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]

    records = []
    offset = 0
    while offset + 4 <= len(raw):
        block_len = int.from_bytes(raw[offset:offset + 4], byteorder="big")
        offset += 4
        encrypted_payload = raw[offset:offset + block_len]
        offset += block_len
        if master_hash:
            try:
                records.append(crypto.decrypt_data(master_hash, encrypted_payload))
            except ValueError:
                continue
    return records

def build_and_log_line(date_str, length, master_hash, app_hash, password, features_bin,
                       temporal_secret="", change_mode=False, log_enabled=True,
                       print_hash=True, encrypt=True, keyfile_path=None):
    """
    Build the canonical hash-summary line, optionally print it to the terminal
    and optionally append it to the log — the single call site shared by the
    plain/change/batch/mass-rekey generation pipelines so their log format
    never drifts apart. Only summarized (truncated double-hash) fingerprints
    are ever stored, never the actual password/master password/temporal secret.
    """
    length_str = str(length).zfill(3)
    master_summary = crypto.summarize_hash(master_hash)
    app_summary = crypto.summarize_hash(app_hash)
    if temporal_secret:
        temporal_summary = crypto.summarize_hash(hashlib.sha256(temporal_secret.encode()).hexdigest())
        temporal_part = f"temporal:{temporal_summary}"
    else:
        temporal_part = "temporal:"
    pwd_summary = crypto.summarize_password_hash(password)

    line = (f"{date_str} ver:v2 len:{length_str} feat:{features_bin} "
            f"{temporal_part} master:{master_summary} app:{app_summary} pwd:{pwd_summary}")

    if keyfile_path:
        with open(keyfile_path, "rb") as kf:
            key_summary = crypto.summarize_hash(hashlib.sha256(kf.read()).hexdigest())
        line += f" key:{key_summary}"

    if change_mode:
        line += " C"

    if print_hash:
        print(line)

    if log_enabled:
        log_hashes_to_file(line, master_hash, encrypt=encrypt)

    return line

def export_to_csv(export_format, name, url, username, pwd):
    export_dir = os.path.expanduser("~/.passweird")
    os.makedirs(export_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d%H%M%S')
    prefix = EXPORT_FORMATS[export_format]["filename_prefix"]
    export_file = os.path.join(export_dir, f"password-{prefix}-{ts}.csv")
    with open(export_file, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(EXPORT_FORMATS[export_format]["header"])
        writer.writerow(EXPORT_FORMATS[export_format]["row"](name, url, username, pwd))
    return export_file

def get_export_writer(export_format, export_file=None):
    """
    Open (or create) a CSV file for accumulating multiple export rows across a
    single run (change mode, batch mode, mass rekey) — unlike export_to_csv,
    which always starts a brand-new timestamped file per call.
    """
    export_dir = os.path.expanduser("~/.passweird")
    os.makedirs(export_dir, exist_ok=True)
    if export_file is None:
        ts = datetime.now().strftime('%Y%m%d%H%M%S')
        prefix = EXPORT_FORMATS[export_format]["filename_prefix"]
        export_file = os.path.join(export_dir, f"password-{prefix}-{ts}.csv")
    is_new = not os.path.exists(export_file)
    fhandle = open(export_file, "a", newline='', encoding='utf-8')
    writer = csv.writer(fhandle)
    if is_new:
        writer.writerow(EXPORT_FORMATS[export_format]["header"])
    return writer, fhandle, export_file

def save_master_hash(master_hash):
    log_dir = os.path.expanduser("~/.passweird")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "master.hash"), "w") as f:
        f.write(master_hash)

def check_master_hash(master_hash):
    hash_path = os.path.expanduser("~/.passweird/master.hash")
    if not os.path.exists(hash_path):
        return None
    with open(hash_path, "r") as f:
        return f.read().strip() == master_hash

def find_in_log(app_summary, temporal_salt, master_hash=None):
    records = read_logs_from_file(master_hash)
    if temporal_salt:
        temporal_summary = crypto.summarize_hash(hashlib.sha256(temporal_salt.encode()).hexdigest())
        temporal_token = f"temporal:{temporal_summary}"
    else:
        temporal_token = "temporal:"
    app_token = f"app:{app_summary}"
    matches = []
    for line in records:
        tokens = line.split()
        if app_token in tokens and temporal_token in tokens:
            matches.append(line)
    return matches

def find_last_features(app_summary, master_hash=None):
    """
    Scan the log for the most recent entry matching app_summary (any temporal
    value) and return (length, features_bin) parsed from it, or None if no
    prior entry exists. Used to warn the user when the character-class/length
    flags they're about to use differ from what they used last time.
    """
    records = read_logs_from_file(master_hash)
    app_token = f"app:{app_summary}"
    last_match = None
    for line in records:
        tokens = line.split()
        if app_token in tokens:
            last_match = tokens
    if last_match is None:
        return None
    fields = {}
    for tok in last_match:
        if ":" in tok:
            k, _, v = tok.partition(":")
            fields[k] = v
    if "len" not in fields or "feat" not in fields:
        return None
    return int(fields["len"]), fields["feat"]