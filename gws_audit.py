#!/usr/bin/env python3

# GWS Audit : outil d'audit sécurité (non intrusif) d'environnement Google Workspace
# Ph. VIALLE
# Script under GPLv3 license (https://www.gnu.org/licenses/gpl-3.0.fr.html#license-text)

# Imports
from zoneinfo import ZoneInfo
import subprocess
import csv
import json
import os
import sys
import importlib
import shutil
from io import StringIO
import datetime as dt
import checkdmarc
import dns.resolver


# =============================
# Configuration de l'audit GWS
# =============================

RULES = {

    #************* /!\ IMPORTANT  /!\ *****************
    # Déclaration du domaine GWS à auditer : 
    # "internal_domain" = suffixe de messagerie du GWS, précédé de '@'
    # "DNS_domain" = nom de domaine DNS du GWS.
    
    "internal_domain": "@domainegws.fr", 
    "DNS_domain": "domainegws.fr",
    #**************************************************
    
    
    #************* /!\ IMPORTANT  /!\ *****************
    # Activer ("True") ou désactiver ("False") chaque audit souhaité ou non

    # SPF/DKIM/DMARC
    "require_dmarc_enforced": True,   # pas implémenté
    "DNS_SPF_DKIM_DMARC": True,
    
    # Identités / Comptes
    "check_identites": True,
    "mfa_required_for_admins": True,
    "mfa_required_for_all_users": True,
    "audit_sms_mfa": True,
    "inactive_days_threshold": 30,
    "max_super_admins": 3,
    "audit_shared_accounts_patterns": ["admin@", "support@", "info@", "contact@", "rgpd@", "administrateur@", "helpdesk@", "cse@", "drive@", "meetings@", "rh@", "sales@", "commerce@", "comptabilite@"],
    "audit_recovery_external_email": True,
    "audit_recovery_external_phone": True,

    # Gmail / Exfiltration
    "forbid_external_forwarding": True,
    "audit_suspicious_filters": True,  # marquer comme lu + transférer + supprimer
    "check_gmail_delegation": True,

    # GDrive
    "check_drives": False,  # /!\ Peut être très long !
    "forbid_public_drive_shares": True,
    "audit_anyone_with_link": True,
    "audit_external_domain_shares": True,

    # Devices / périphériques
    "check_devices": True,  
    "device_inactive_days_threshold": 60,

    # Groupes
    "audit_external_groups": True,
    "audit_anyone_can_post": True,
    
    # Fichiers sensibles partagés
    "audit_sensitive_files" : True,
    "audit_keywords": ["password", "mdp", "mot de passe", "confidentiel", "confidential", "numéro de sécurité sociale", "médical", "IBAN", "disciplinaire", "judiciaire", "contentieux"],
    
}

OUTPUT_DIR = "output"
RAW_DIR = os.path.join(OUTPUT_DIR, "raw")
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")


# =========================
# Fonctions utilitaires
# =========================


def ensure_dirs():
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)


def check_gam() -> bool:
    """
    Vérifie la présence et l'exécutabilité de GAM.
    Retourne True si GAM est disponible, False sinon.
    """
    print("[i] Vérification de GAM...")

    # Noms possibles de l'exécutable
    gam_commands = ["gam", "gam.cmd"]

    gam_path = None
    for cmd in gam_commands:
        gam_path = shutil.which(cmd)
        if gam_path:
            break

    if not gam_path:
        print("[ERREUR] GAM non trouvé dans le PATH")
        print("        → https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7")
        return False

    try:
        subprocess.run(
            [gam_path, "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10
        )
        print(f"[OK] GAM disponible ({gam_path})")  
        return True

    except Exception:
        print("[ERREUR] GAM trouvé mais non exécutable")
        return False



def check_prereq() -> bool:
    """
    Vérifie la présence des prérequis nécessaires.
    Retourne True si tout est OK, False sinon.
    """
    ok = True

    print("\n[i] Vérification des prérequis...")

    # --- Python ---
    if sys.version_info >= (3, 8):
        print(f"[OK] Python {sys.version.split()[0]}")
    else:
        print(f"[ERREUR] Python >= 3.8 requis (actuel : {sys.version.split()[0]})")
        ok = False

    # --- pip ---
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        print("[OK] pip disponible")
    except Exception:
        print("[ERREUR] pip non disponible")
        ok = False

    # --- checkdmarc ---
    if importlib.util.find_spec("checkdmarc") is not None:
        print("[OK] checkdmarc installé")
    else:
        print("[ERREUR] checkdmarc non installé")
        print("        → python -m pip install checkdmarc")
        ok = False

    # --- GAM ---
    if not check_gam():
        ok = False
    
    return ok




def run_gam(command, outfile=None):
    print(f"[+] Exécution : {command}")
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"   # évite les UnicodeDecodeError

    )
    if result.returncode != 0:
        print(f"[!] Erreur GAM : {result.stderr}")
        return ""

    output = result.stdout or ""


    if outfile:
        with open(outfile, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)

    return output


def parse_csv(text):
    if not text.strip():
        return []
    reader = csv.DictReader(StringIO(text))
    return list(reader)


def add_finding(findings, severity, category, item, issue, recommendation, details=None):
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    if severity.upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError(f"Invalid severity: {severity}")

    finding = {
        "severity": severity.upper(),
        "category": str(category),
        "item": str(item),
        "issue": str(issue),
        "recommendation": str(recommendation),
        "details": details if isinstance(details, dict) else {},
    }

    findings.append(finding)



# =========================
# Audit : Comptes & Identités
# =========================

def audit_identities(findings):
    # Utilisateurs avec état MFA inclus
    if not RULES.get("check_identites", False):
        print("\n[i] Audit des utilisateurs désactivé (RULES.check_identites = False).")
        return

    allowed_domain = RULES.get("internal_domain", "@domainegws.fr")

    print("\n[i] Audit utilisateurs : analyse des configurations MFA…")
    users_csv = run_gam(
        "gam print users"
        " fields primaryEmail,isAdmin,suspended,orgUnitPath,lastLoginTime,"
        "recoveryEmail,recoveryPhone,isEnrolledIn2Sv",
        outfile=os.path.join(RAW_DIR, "users.csv")
    )
    users = parse_csv(users_csv)

    super_admin_count = 0
    inactive_threshold_days = RULES.get("inactive_days_threshold", 90)
    inactive_cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=inactive_threshold_days)

    for u in users:
        email = (u.get("primaryEmail") or "").lower()
        if not email:
            continue

        is_admin = (u.get("isAdmin") or "").upper() == "TRUE"
        suspended = (u.get("suspended") or "").upper() == "TRUE"
        last_login = u.get("lastLoginTime") or ""
        recovery_email = u.get("recoveryEmail") 
        recovery_phone = u.get("recoveryPhone") or ""
        mfa_enrolled = (u.get("isEnrolledIn2Sv") or "").lower() == "true"

        # Comptes super-admin
        if is_admin and not suspended:
            super_admin_count += 1

        # MFA pour admins
        if RULES.get("mfa_required_for_admins", True) and is_admin and not suspended:
            if not mfa_enrolled:
                add_finding(
                    findings,
                    severity="CRITICAL",
                    category="Identities",
                    item=email,
                    issue="Compte super-admin sans MFA actif",
                    recommendation="Imposer l’activation MFA pour tous les comptes super-admin."
                )

        # MFA pour tous les utilisateurs (optionnel)
        if RULES.get("mfa_required_for_all_users", False) and not suspended:
            if not mfa_enrolled:
                add_finding(
                    findings,
                    severity="HIGH",
                    category="Identities",
                    item=email,
                    issue="Compte utilisateur sans MFA actif",
                    recommendation="Imposer l’activation MFA pour tous les comptes utilisateurs."
                )

        # Comptes inactifs
        if last_login and last_login != "1970-01-01T00:00:00.000Z":
            try:
                last_login_dt = dt.datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                if last_login_dt < inactive_cutoff and not suspended:
                    add_finding(
                        findings,
                        severity="MEDIUM",
                        category="Identities",
                        item=email,
                        issue=f"Compte inactif depuis plus de {inactive_threshold_days} jours",
                        recommendation="Désactiver ou supprimer les comptes inactifs non justifiés."
                    )
            except Exception:
                pass

        # Comptes partagés (pattern)
        for pattern in RULES.get("audit_shared_accounts_patterns", []):
            if pattern in email:
                add_finding(
                    findings,
                    severity="MEDIUM",
                    category="Identities",
                    item=email,
                    issue="Compte potentiellement partagé (motif générique)",
                    recommendation="Remplacer les comptes partagés par des comptes nominaux + groupes."
                )
                break

        # Recovery email externe
        if RULES.get("audit_recovery_external_email", True) and recovery_email:
            if not recovery_email.endswith(allowed_domain):
                add_finding(
                    findings,
                    severity="LOW",
                    category="Identities",
                    item=email,
                    issue="Email de récupération externe",
                    recommendation="Limiter les emails de récupération à des adresses internes ou contrôlées.",
                    details={"recovery_email": recovery_email}
                )

        # Recovery phone externe
        if RULES.get("audit_recovery_external_phone", True) and not recovery_phone:
            add_finding(
                findings,
                severity="MEDIUM",
                category="Identities",
                item=email,
                issue="Numéro de téléphone de récupération NON configuré",
                recommendation="Vérifier que les numéros de récupération sont configurés."
            )

    # Nombre de super-admins
    max_super_admins = RULES.get("max_super_admins", 5)
    if super_admin_count > max_super_admins:
        add_finding(
            findings,
            severity="HIGH",
            category="Identities",
            item="Global",
            issue=f"Trop de comptes super-admin ({super_admin_count})",
            recommendation=f"Réduire le nombre de super-admins à moins de {max_super_admins}."
        )

    print("[i] Audit des utilisateurs terminé.")

# =========================
# Audit : Groupes
# =========================

def audit_groups(findings):
    if not RULES.get("audit_external_groups", False):
        print("\n[i] Audit des groupes désactivé (RULES.audit_external_groups = False).")
        return
    
    print("\n[i] Audit Groupes : analyse des groupes…")
    
    print("[i] Audit Drive : analyse des fichiers et ACL…")
    groups_csv = run_gam(
        "gam print groups" 
        " fields email,whoCanJoin,whoCanViewMembership,whoCanViewGroup,whoCanPostMessage",
        outfile=os.path.join(RAW_DIR, "groups.csv")
    )
    groups = parse_csv(groups_csv)

    for g in groups:
        email = g.get("email")
        who_can_join = (g.get("whoCanJoin") or "").lower()
        who_can_post = (g.get("whoCanPostMessage") or "").lower()
        

        # Groupes ouverts à l'externe
        if RULES.get("audit_external_groups", True):
            if "anyone" in who_can_join or "external" in who_can_join:
                add_finding(
                    findings,
                    severity="MEDIUM",
                    category="Groups",
                    item=email,
                    issue="Groupe potentiellement ouvert à des membres externes ou non contrôlés",
                    recommendation="Limiter l’adhésion aux membres internes ou contrôlés."
                )

        # N'importe qui peut poster
        if RULES.get("audit_anyone_can_post", True):
            if "anyone" in who_can_post or "external" in who_can_post:
                add_finding(
                    findings,
                    severity="LOW",
                    category="Groups",
                    item=email,
                    issue="N’importe qui peut poster sur ce groupe",
                    recommendation="Restreindre l’envoi de messages aux membres ou à des expéditeurs approuvés."
                )

    print("[i] Audit des groupes terminé.")


# =========================
# Audit : GDrive (fichiers exposés avec ACL permissives)
# =========================
def audit_drive(findings):
    if not RULES.get("check_drives", False):
        print("\n[i] Audit GDrive de partages permissifs désactivé (RULES.check_drives = False).")
        return
    print("\n[i] Audit Drive : analyse des fichiers et ACL…")

    # ============================
    # 1. Récupération des utilisateurs
    # ============================
    users_raw = run_gam("gam print users", outfile=os.path.join(RAW_DIR, "users.csv"))
    users = parse_csv(users_raw)

    if not users:
        print("[!] Aucun utilisateur récupéré.")
        return

    # ============================
    # 2. Pour chaque utilisateur : récupérer les fichiers
    # ============================
    for user in users:
        email = user.get("primaryEmail")
        if not email:
            continue

        print(f"    → Fichiers de {email}")

        filelist_raw = run_gam(
            f"gam user {email} show filelist",
            outfile=os.path.join(RAW_DIR, f"filelist_{email}.csv")
        )
        filelist = parse_csv(filelist_raw)

        # ============================
        # 3. Pour chaque fichier : récupérer les ACL
        # ============================
        for f in filelist:
            file_id = f.get("id")
            title = f.get("title", file_id)

            if not file_id:
                continue

            acl_raw = run_gam(
                f"gam user {email} show fileacl {file_id}",
                outfile=os.path.join(RAW_DIR, f"acl_{file_id}.txt")
            )

            # GAM renvoie un texte, pas un CSV
            text = acl_raw.lower()

            # ============================
            # 4. Détection : public / anyone with link
            # ============================
            if RULES.get("forbid_public_drive_shares", True):
                if "anyonewithlink" in text or "anyone" in text:
                    add_finding(
                        findings,
                        severity="HIGH",
                        category="Drive",
                        item=title,
                        issue="Fichier Drive accessible publiquement",
                        recommendation="Supprimer l'accès public ou restreindre aux utilisateurs internes.",
                        details={"fileId": file_id, "owner": email}
                    )

            # ============================
            # 5. Détection : partage externe
            # ============================
            if RULES.get("audit_external_domain_shares", True):
                for line in text.splitlines():
                    if "user:" in line and not line.endswith(YOUR_DOMAIN.lower()):
                        add_finding(
                            findings,
                            severity="MEDIUM",
                            category="Drive",
                            item=title,
                            issue="Fichier partagé avec un utilisateur externe",
                            recommendation="Vérifier si ce partage est légitime.",
                            details={"fileId": file_id, "owner": email, "acl": line.strip()}
                        )

    print("[i] Audit Drive terminé.")

    # Pour aller plus loin : audit des fichiers/Drive partagés
    # Exemple (à adapter, car potentiellement très volumineux) :
    # gam user <admin> show filelist ... ou gam print filelist
    # Ici, on laisse un memento pour ne pas exploser le temps d’exécution.


# =========================
# Audit : Gmail
# =========================

def audit_gmail(findings):
    forbid_forwarding = RULES.get("forbid_external_forwarding", True)
    audit_suspicious = RULES.get("audit_suspicious_filters", True)
    allowed_domain = RULES.get("internal_domain", "@domainegws.fr")

    if not (forbid_forwarding or audit_suspicious):
        print("\n[i] Audit Gmail désactivé (aucune règle active).")
        return

    print("\n[i] Audit Gmail : récupération des utilisateurs…")

    # ============================
    # 1. Récupération propre des utilisateurs
    # ============================
    users_csv = run_gam("gam print users fields primaryEmail")
    users = parse_csv(users_csv)

    print(f"[i] {len(users)} utilisateurs à analyser.")

    # ============================
    # 2. Analyse utilisateur par utilisateur
    # ============================
    for u in users:
        user = (u.get("primaryEmail") or "").strip().lower()
        if not user:
            continue

        # ----------------------------
        # A. Transfert Gmail natif
        # ----------------------------
        if forbid_forwarding:
            forward_raw = run_gam(f"gam user {user} show forwardingaddress")

        if forward_raw:
            lines = [l.strip() for l in forward_raw.splitlines()]

            addr_line = next((l for l in lines if "Forwarding Address:" in l), None)
            if addr_line:
                forward_to = addr_line.split(":", 1)[1].strip()

                if not forward_to.endswith(allowed_domain):
                    add_finding(
                        findings,
                        severity="HIGH",
                        category="Gmail",
                        item=user,
                        issue="Transfert Gmail natif vers une adresse externe",
                        recommendation="Vérifier la légitimé et désactiver le transfert externe dans Gmail.",   
                        details={"forward_to": forward_to},
                    ) 
                else:
                    add_finding(
                        findings,
                        severity="MEDIUM",
                        category="Gmail",
                        item=user,
                        issue="Transfert Gmail natif vers une autre adresse Gmail interne",
                        recommendation="Vérifier la légitimité d'un transfert vers une autre BAL Gmail interne.",   
                        details={"forward_to": forward_to},
                    )

        # ----------------------------
        # B. Filtres Gmail
        # ----------------------------
        if audit_suspicious or forbid_forwarding:
            filters_raw = run_gam(f"gam user {user} show filters")

            if not filters_raw:
                continue

            current_filter = None
            filters = []

            # Parsing GAM (format textuel)
            for line in filters_raw.splitlines():
                line = line.strip()

                if line.startswith("Filter:"):
                    current_filter = {
                        "filter_id": line.replace("Filter:", "").strip(),
                        "criteria": [],
                        "actions": []
                    }
                    filters.append(current_filter)

                elif line.startswith("Criteria:") and current_filter:
                    crit = line.replace("Criteria:", "").strip()
                    current_filter["criteria"].append(crit)

                elif line.startswith("Action:") and current_filter:
                    act = line.replace("Action:", "").strip()
                    current_filter["actions"].append(act)

            # Analyse des filtres
            for f in filters:
                actions = [a.lower() for a in f["actions"]]
                criteria = [c.lower() for c in f["criteria"]]

                # --- Forwarding externe via filtre ---
                if forbid_forwarding:
                    for act in actions:
                        if "forward" in act and "@" in act:
                            # extraction simple de l'adresse email
                            parts = act.split()
                            forward_to = next((p for p in parts if "@" in p), None)

                            if forward_to and not forward_to.endswith(allowed_domain):
                                add_finding(
                                    findings,
                                    severity="HIGH",
                                    category="Gmail",
                                    item=user,
                                    issue="Filtre Gmail transférant vers une adresse externe",
                                    recommendation="Supprimer ou modifier ce filtre.",
                                    details={
                                        "filter_id": f["filter_id"],
                                        "forward_to": forward_to,
                                        "criteria": criteria,
                                        "actions": actions
                                    }
                                )

                # --- Filtres suspects ---
                if audit_suspicious:

                    # markAsRead + forward + delete
                    if ("markasread" in actions and
                        any("forward" in a for a in actions) and
                        "delete" in actions):

                        add_finding(
                            findings,
                            severity="CRITICAL",
                            category="Gmail",
                            item=user,
                            issue="Filtre suspect : lecture + transfert + suppression",
                            recommendation="Vérifier immédiatement ce filtre (risque de compromission).",
                            details={
                                "filter_id": f["filter_id"],
                                "criteria": criteria,
                                "actions": actions
                            }
                        )

                    # suppression automatique
                    if "delete" in actions:
                        add_finding(
                            findings,
                            severity="MEDIUM",
                            category="Gmail",
                            item=user,
                            issue="Filtre supprimant automatiquement des emails",
                            recommendation="Vérifier que ce filtre est légitime.",
                            details={
                                "filter_id": f["filter_id"],
                                "criteria": criteria,
                                "actions": actions
                            }
                        )

                    # archivage silencieux
                    if "archive" in actions and "markasread" in actions:
                        add_finding(
                            findings,
                            severity="LOW",
                            category="Gmail",
                            item=user,
                            issue="Filtre archivant automatiquement des emails",
                            recommendation="Vérifier que l’utilisateur ne masque pas involontairement des messages.",
                            details={
                                "filter_id": f["filter_id"],
                                "criteria": criteria,
                                "actions": actions
                            }
                        )

    print("[i] Audit Gmail terminé.")

# =========================
# Audit : Devices 
# =========================

def audit_devices(findings):
    if not RULES.get("check_devices", False):
        print("\n[i] Audit des périphériques ('devices') désactivé (RULES.check_devices = False).")
        return

    print("\n[i] Audit devices : récupération et analyse des appareils…")

    inactive_days = RULES.get("device_inactive_days_threshold", 60)
    now = dt.datetime.now(dt.UTC)

    # ============================
    # 1. Récupération des mobiles
    # ============================
    mobile_file = os.path.join(RAW_DIR, "mobile_devices.csv")
    mobile_raw = run_gam("gam print mobile", outfile=mobile_file)
    mobile_devices = parse_csv(mobile_raw)

    # ============================
    # 2. Récupération des ChromeOS
    # ============================
    chrome_file = os.path.join(RAW_DIR, "chrome_devices.csv")
    chrome_raw = run_gam("gam print cros", outfile=chrome_file)
    chrome_devices = parse_csv(chrome_raw)

    # ============================
    # 3. Analyse des appareils
    # ============================

    # --- Mobiles ---
    for dev in mobile_devices:
        dev_id = dev.get("resourceId", "unknown")
        user = dev.get("email", "unknown")

        # Non chiffré
        enc = (dev.get("encryptionStatus") or "").lower().strip()
    
        if enc == "":
            add_finding(
                findings,
                severity="LOW",
                category="devices",
                item=dev_id,
                issue="Statut de chiffrement inconnu",
                recommendation="Vérifier si l’appareil est géré via Android Enterprise ou iOS supervisé.",
                details={"user": user, "encryptionStatus": enc},
        )

        elif enc not in ["encrypted", "device_encrypted"]:
            add_finding(
                findings,
                severity="HIGH",
                category="devices",
                item=dev_id,
                issue="Appareil mobile non chiffré",
                recommendation="Exiger le chiffrement du device via la politique MDM.",
                details={"user": user, "encryptionStatus": enc},
        )

        # Rooté / compromis
        compromised = dev.get("deviceCompromisedStatus", "").lower()
        if compromised in ["compromised", "rooted", "jailbroken"]:
            add_finding(
                findings,
                severity="critical",
                category="devices",
                item=dev_id,
                issue="Appareil compromis (root/jailbreak)",
                recommendation="Bloquer l'accès et exiger une remise en conformité.",
                details={"user": user, "status": compromised},
        )
        
        # Inactif
        last_sync = dev.get("lastSync", "")
        if last_sync:
            try:
                sync_dt = dt.datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                delta = (now - sync_dt).days
                if delta > inactive_days:
                    add_finding(
                        findings,
                        severity="medium",
                        category="devices",
                        item=dev_id,
                        issue=f"Appareil inactif depuis {delta} jours",
                        recommendation="Vérifier si l'appareil est encore utilisé ou le retirer.",
                        details={"user": user, "lastSync": last_sync, "days": delta},
                    )
            except Exception:
                pass

    # --- ChromeOS ---
    for dev in chrome_devices:
        dev_id = dev.get("deviceId", "unknown")
        user = dev.get("annotatedUser", "unknown")

        # Chiffrement
        enc = dev.get("diskEncryptionStatus", "").lower()
        if enc not in ["encrypted"]:
            add_finding(
                findings,
                severity="high",
                category="devices",
                item=dev_id,
                issue="ChromeOS non chiffré",
                recommendation="Activer le chiffrement forcé dans la console Google Admin.",
                details={"user": user, "diskEncryptionStatus": enc},
            )

        # Inactivité
        last_sync = dev.get("lastSync", "")
        if last_sync:
            try:
                sync_dt = dt.datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                delta = (now - sync_dt).days
                if delta > inactive_days:
                    add_finding(
                        findings,
                        severity="medium",
                        category="devices",
                        item=dev_id,
                        issue=f"ChromeOS inactif depuis {delta} jours",
                        recommendation="Vérifier si l'appareil est encore utilisé.",
                        details={"user": user, "lastSync": last_sync, "days": delta},
                    )
            except Exception:
                pass

    print("[i] Audit des périphériques terminé.")


# =========================
# GDrive : Recherche d'infos sensibles (exposées)
# =========================

def audit_sensitive(findings):
    
    if not RULES.get("audit_sensitive_files", False):
        print("\n[i] Audit fichiers sensibles désactivé (RULES.audit_sensitive_files = False).")
        return

    print("\n[i] Audit GDrive : recherche de fichiers sensibles…")

    keywords = RULES.get("audit_keywords", [])
    query = " or ".join([f"name contains '{kw}'" for kw in keywords])

    fields = (
    "id,name,owners,shared,shareable,webViewLink,"
    "permissions.role,permissions.type,permissions.emailAddress,permissions.domain"
    )

    gam_cmd = (
        f'gam all users print filelist '
        f'fields {fields} '
        f'query "{query}"'
    )

    outfile = os.path.join(RAW_DIR, "drive_sensitive_files.csv")
    drive_csv = run_gam(gam_cmd, outfile=outfile)
    files = parse_csv(drive_csv)

    print(f"[i] {len(files)} fichiers suspects trouvés.")

    internal_domain = RULES.get("internal_domain", "@domainegws.fr")

    for f in files:
        title = f.get("name", "Sans nom")
        file_id = f.get("id", "Identité inconnue")
        owner = f.get("owners", "Propriétaire inconnu")
        shared = (f.get("shared") or "").lower()
        shareable = (f.get("shareable") or "").lower()

        # ----------------------------------------------------------------------
        # Reconstruction FIABLE des permissions Drive
        # ----------------------------------------------------------------------
        shared_with_list = []

        for k, v in f.items():
            if not k.startswith("permissions."):
                continue

            parts = k.split(".")
            if len(parts) < 3:
                continue

            perm_id = parts[1]
            field = parts[2]

            perm_type = f.get(f"permissions.{perm_id}.type", "").lower()
            email = f.get(f"permissions.{perm_id}.emailAddress", "")
            domain = f.get(f"permissions.{perm_id}.domain", "")

            # Utilisateur externe
            if perm_type == "user" and email and internal_domain not in email:
                shared_with_list.append(email)

            # Groupe externe
            elif perm_type == "group" and email and internal_domain not in email:
                shared_with_list.append(f"{email} (groupe)")

            # Partage de domaine externe
            elif perm_type == "domain" and domain and internal_domain not in domain:
                shared_with_list.append(f"Tous les utilisateurs du domaine {domain}")

            # Partage public
            elif perm_type == "anyone":
                shared_with_list.append("Lien public (anyoneWithLink)")

        shared_with_str = ", ".join(shared_with_list)

        # ----------------------------------------------------------------------
        # Détection fichier sensible (nom contient un mot-clé critique)
        # ----------------------------------------------------------------------
        add_finding(
            findings,
            severity="MEDIUM",
            category="Drive",
            item=title,
            issue="Fichier potentiellement sensible (nom contient un mot-clé critique)",
            recommendation="Vérifier le contenu du fichier et le sécuriser si nécessaire.",
            details={
                "owner": owner,
                "file_id": file_id,
                "shared": shared,
                "shareable": shareable,
                "shared_with": shared_with_str
            }
        )

        # ----------------------------------------------------------------------
        # Fichier public (anyoneWithLink)
        # ----------------------------------------------------------------------
        if "Lien public (anyoneWithLink)" in shared_with_list:
            add_finding(
                findings,
                severity="CRITICAL",
                category="Drive",
                item=title,
                issue="Fichier sensible accessible publiquement",
                recommendation="Restreindre immédiatement les permissions de partage.",
                details={
                    "owner": owner,
                    "file_id": file_id
                }
            )

        # ----------------------------------------------------------------------
        # Fichier partagé en externe
        # ----------------------------------------------------------------------
        if shared_with_list:
            add_finding(
                findings,
                severity="HIGH",
                category="Drive",
                item=title,
                issue="Fichier sensible partagé avec des utilisateurs externes",
                recommendation="Restreindre les destinataires externes.",
                details={
                    "owner": owner,
                    "file_id": file_id,
                    "shared_with": shared_with_str
                }
            )

    print("[i] Audit fichiers sensibles terminé.")
    
    
    
# =========================
# Audit : SPF / DKIM / DMARC
# =========================

def audit_SPF_DKIM(findings):
    # Activation via RULES
    if not RULES.get("audit_spf_dkim", True):
        print("\n[i] Audit SPF/DKIM désactivé (RULES.audit_spf_dkim = False).")
        return

    domaine_SMTP = RULES.get("DNS_domain")
    if not domaine_SMTP:
        print("\n[!] Aucun domaine défini dans RULES.DNS_domain — audit ignoré.")
        return

    print(f"\n[i] Audit SPF/DKIM : analyse du domaine {domaine_SMTP}…")

    # ----------------------------------------------------------------------
    # Correctif DNS temporaire (INDISPENSABLE pour éviter les blocages Checkdmarc)
    # ----------------------------------------------------------------------
    print ("[+] Correctif temporaire du module DNS dns.resolver, pour forcer des DNS publics spécifiques")
    _original_resolver_init = dns.resolver.Resolver.__init__

    def patched_resolver_init(self, *args, **kwargs):
        _original_resolver_init(self, configure=False)
        self.nameservers = ["8.8.8.8", "1.1.1.1"]
        self.timeout = 5
        self.lifetime = 5

    dns.resolver.Resolver.__init__ = patched_resolver_init

    dns_params = {
        "nameservers": ["8.8.8.8", "1.1.1.1"],
        "timeout": 10
    }
    
    
    # ---------------- SPF ----------------

    print ("[i] Vérification SPF...")
    try:
        spf = checkdmarc.check_spf(domaine_SMTP, **dns_params)
    except Exception as e:
        print(f"[!] Erreur SPF : {e}")
    spf = {"error": True}

    if isinstance(spf, dict):

        # Erreur explicite renvoyée par checkdmarc (ex : 12/10 lookups)
        if spf.get("error"):
            print ("[+] SPF invalide : dépassement de la limite RFC (10 DNS lookups)")
            add_finding(
                findings,
                severity="HIGH",
                category="Email",
                item=domaine_SMTP,
                issue="SPF invalide : dépassement de la limite RFC (10 DNS lookups)",
                recommendation="Réduire le nombre d'includes pour revenir sous la limite RFC 7208."
            )

        # SPF invalide (valid=False)
        if not spf.get("valid", True):
            print ("[+] SPF invalide ou non conforme")
            add_finding(
                findings,
                severity="HIGH",
                category="Email",
                item=domaine_SMTP,
                issue="SPF invalide ou non conforme",
                recommendation="Corriger la structure du SPF."
            )

        # SPF se termine par ?all
        record = spf.get("record", "") or ""
        if record.endswith("?all"):
            print ("[+] Mécanisme final SPF incohérent ('?all')")
            add_finding(
                findings,
                severity="HIGH",
                category="Email",
                item=domaine_SMTP,
                issue="Mécanisme final SPF incohérent ('?all')",
                recommendation="Remplacer '?all' par '~all' ou '-all'."
            )

    # ---------------- DMARC ----------------
    print ("[i] Vérification DMARC...")
    try:
        dmarc = checkdmarc.check_dmarc(domaine_SMTP, **dns_params)
    except Exception as e:
        print(f"[!] Erreur DMARC : {e}")
        dmarc = {"error": True}

    if isinstance(dmarc, dict) and dmarc.get("valid"):

        tags = dmarc.get("tags", {})

        pct = tags.get("pct", {}).get("value", 100)
        if pct < 100:
            print ("[+] DMARC partiellement appliqué")
            add_finding(
                findings,
                severity="MEDIUM",
                category="Email",
                item=domaine_SMTP,
                issue=f"DMARC partiellement appliqué (pct={pct}%)",
                recommendation="Passer pct=100 pour une application complète."
            )

        sp = tags.get("sp", {}).get("value", "none")
        if sp == "none":
            print ("[+] DMARC non appliqué aux sous-domaines (sp=none)")
            add_finding(
                findings,
                severity="MEDIUM",
                category="Email",
                item=domaine_SMTP,
                issue="DMARC non appliqué aux sous-domaines (sp=none)",
                recommendation="Définir sp=quarantine ou sp=reject."
            )

        if "rua" not in tags:
            print ("[+] Absence de tag DMARC 'rua'")
            add_finding(
                findings,
                severity="LOW",
                category="Email",
                item=domaine_SMTP,
                issue="Absence de tag DMARC 'rua'",
                recommendation="Ajouter rua=mailto:adresse@domaine."
            )

    # ---------------- DKIM ----------------
    print("[i] Vérification DKIM…")

    selectors_found = []
    selectors_test = [
        "google", "selector1", "selector2",
        "mailjet", "smtp", "krs", "mg",
        "smtpapi", "s1", "s2",
        "default", "dkim", "mail"
    ]

    # Découverte automatique dans _domainkey
    try:
        subkeys = dns.resolver.resolve(f"_domainkey.{domaine_SMTP}", "TXT")
        for r in subkeys:
            txt = b"".join(r.strings).decode()
            # Exemple : "t=s; o=~; n=; r=postmaster; s=selector1:selector2"
            if "s=" in txt:
                parts = txt.split("s=")[1].split(";")[0]
                for sel in parts.split(":"):
                    selectors_test.append(sel.strip())
    except:
        pass

    # Test des sélecteurs
    for sel in set(selectors_test):
        try:
            rec = dns.resolver.resolve(f"{sel}._domainkey.{domaine_SMTP}", "TXT")
            selectors_found.append(sel)
        except:
            continue

    if not selectors_found:
        add_finding(
            findings,
            severity="HIGH",
            category="Email",
            item=domaine_SMTP,
            issue="Aucun enregistrement DKIM détecté",
            recommendation="Configurer au moins un sélecteur DKIM actif."
        )
    else:
        for sel in selectors_found:
            add_finding(
                findings,
                severity="INFO",
                category="Email",
                item=f"{sel}._domainkey.{domaine_SMTP}",
                issue="Sélecteur DKIM détecté",
                recommendation="Vérifier que la clé DKIM est bien alignée avec DMARC."
            )


    # ---------------- BIMI ----------------
    print("[i] Vérification BIMI…")

    bimi_selector = f"default._bimi.{domaine_SMTP}"
    bimi_record = None

    try:
        answers = dns.resolver.resolve(bimi_selector, "TXT")
        for r in answers:
            bimi_record = b"".join(r.strings).decode()
    except:
        bimi_record = None

    if not bimi_record:
        add_finding(
            findings,
            severity="LOW",
            category="Email",
            item=bimi_selector,
            issue="Aucun enregistrement BIMI détecté",
            recommendation="Ajouter un enregistrement BIMI pour afficher le logo de la marque dans les boîtes de réception compatibles."
        )
    else:
        # BIMI trouvé → analyse du contenu
        print("[+] Enregistrement BIMI détecté !")
        add_finding(
            findings,
            severity="INFO",
            category="Email",
            item=bimi_selector,
            issue="Enregistrement BIMI détecté",
            recommendation="Vérifier que le logo SVG et le certificat VMC sont valides."
        )

        # Vérification du logo (l=)
        if "l=" not in bimi_record:
            print("[+] BIMI présent mais sans URL de logo (l=)")
            add_finding(
                findings,
                severity="LOW",
                category="Email",
                item=bimi_selector,
                issue="BIMI présent mais sans URL de logo (l=)",
                recommendation="Ajouter l’URL du logo SVG dans le champ l=."
            )

        # Vérification du certificat VMC (a=)
        if "a=" not in bimi_record:
            print("[+] BIMI présent mais sans certificat VMC (a=)")
            add_finding(
                findings,
                severity="LOW",
                category="Email",
                item=bimi_selector,
                issue="BIMI présent mais sans certificat VMC (a=)",
                recommendation="Ajouter un certificat VMC pour activer BIMI sur Gmail."
            )


    print("[i] Audit SPF/DKIM terminé.")


    
   
# =========================
# Consolidation 
# =========================

def compute_summary(findings):
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": len(findings),
    }
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in summary:
            summary[sev] += 1
        else:
            summary["LOW"] += 1
    return summary


# =========================
# Génération rapports
# =========================

def save_reports(findings):
    timestamp = dt.datetime.now(ZoneInfo("Europe/Paris")).strftime("%Y%m%d-%H%M%S")
    DNS_domain = RULES.get("DNS_domain", "domaine-inconnu")

    json_path = os.path.join(REPORTS_DIR, f"report-{timestamp}.json")
    md_path = os.path.join(REPORTS_DIR, f"report-{timestamp}.md")
    html_path = os.path.join(REPORTS_DIR, f"report-{timestamp}.html")

    # Tri par sévérité
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    findings_sorted = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "LOW").upper(), 0),
        reverse=True
    )

    summary = compute_summary(findings_sorted)

    # ---------------- JSON ----------------
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at_local": timestamp,
            "domain": DNS_domain,
            "summary": summary,
            "findings": findings_sorted,
        }, f, indent=2, ensure_ascii=False)

    # ---------------- MARKDOWN ----------------
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Rapport d’audit Google Workspace\n\n")
        f.write(f"- Domaine audité : **{DNS_domain}**\n")
        f.write(f"- Généré (Fuseau France) : {timestamp}\n")
        f.write(f"- Total findings : {summary['TOTAL']}\n")
        f.write(f"- CRITICAL : {summary['CRITICAL']}\n")
        f.write(f"- HIGH : {summary['HIGH']}\n")
        f.write(f"- MEDIUM : {summary['MEDIUM']}\n")
        f.write(f"- LOW : {summary['LOW']}\n")
        f.write(f"- INFO : {summary['INFO']}\n\n")

        for fnd in findings_sorted:
            f.write(f"## [{fnd['severity']}] {fnd['category']} — {fnd['item']}\n")
            f.write(f"- **Issue** : {fnd['issue']}\n")
            f.write(f"- **Recommendation** : {fnd['recommendation']}\n")
            if fnd.get("details"):
                f.write(f"- **Details** : `{json.dumps(fnd['details'], ensure_ascii=False)}`\n")
            f.write("\n")

    # ---------------- HTML ----------------
    html_head = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Rapport d’audit Google Workspace - {DNS_domain}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 20px; background:#0b1020; color:#e5e9f0; }}
    h1, h2, h3 {{ color:#88c0d0; }}
    .meta {{ margin-bottom:20px; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.8rem; font-weight:bold; }}
    .sev-CRITICAL {{ background:#bf616a; color:#fff; }}
    .sev-HIGH {{ background:#d08770; color:#fff; }}
    .sev-MEDIUM {{ background:#ebcb8b; color:#2e3440; }}
    .sev-LOW {{ background:#a3be8c; color:#2e3440; }}
    .sev-INFO {{ background:#81a1c1; color:#2e3440; }}
    .finding {{ border:1px solid #3b4252; border-radius:6px; padding:10px 12px; margin-bottom:10px; background:#2e3440; }}
    .details {{ font-family: "JetBrains Mono", "Fira Code", monospace; font-size:0.8rem; background:#3b4252; padding:6px 8px; border-radius:4px; white-space:pre-wrap; }}
    .summary-list li {{ margin-bottom:4px; }}
  </style>
</head>
<body>
<h1>Rapport d’audit Google Workspace</h1>
<div class="meta">
  <p><strong>Domaine audité</strong> : {DNS_domain}</p>
  <p><strong>Généré (Fuseau France)</strong> : {timestamp}</p>
  <ul class="summary-list">
    <li><strong>Total findings</strong> : {summary['TOTAL']}</li>
    <li><strong>CRITICAL</strong> : {summary['CRITICAL']}</li>
    <li><strong>HIGH</strong> : {summary['HIGH']}</li>
    <li><strong>MEDIUM</strong> : {summary['MEDIUM']}</li>
    <li><strong>LOW</strong> : {summary['LOW']}</li>
    <li><strong>INFO</strong> : {summary['INFO']}</li>
  </ul>
</div>
"""

    html_body = []
    for fnd in findings_sorted:
        sev = fnd.get("severity", "LOW").upper()
        cat = fnd.get("category", "Unknown")
        item = fnd.get("item", "Unknown")
        issue = fnd.get("issue", "N/A")
        rec = fnd.get("recommendation", "N/A")
        details = fnd.get("details") or {}

        block = f"""
<div class="finding">
  <div>
    <span class="badge sev-{sev}">{sev}</span>
    <strong> {cat} — {item}</strong>
  </div>
  <p><strong>Issue :</strong> {issue}</p>
  <p><strong>Recommendation :</strong> {rec}</p>"""

        if details:
            block += f"""
  <div class="details">{json.dumps(details, ensure_ascii=False, indent=2)}</div>"""

        block += "\n</div>\n"
        html_body.append(block)

    html_footer = "</body>\n</html>\n"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_head)
        f.writelines(html_body)
        f.write(html_footer)

    print("\n *** FIN DE L'AUDIT ***")
    print(f"[+] Rapport JSON : {json_path}")
    print(f"[+] Rapport Markdown : {md_path}")
    print(f"[+] Rapport HTML : {html_path}")



# =========================
# Main
# =========================

def main():
    
    print("\033[2J\033[H", end="")

    ascii_art = r"""

     _____ _    _ _____             ___            _ _ _   
    |  __ \ |  | /  ___|           / _ \          | (_) |  
    | |  \/ |  | \ `--.   ______  / /_\ \_   _  __| |_| |_ 
    | | __| |/\| |`--. \ |______| |  _  | | | |/ _` | | __|
    | |_\ \  /\  /\__/ /          | | | | |_| | (_| | | |_ 
     \____/\/  \/\____/           \_| |_/\__,_|\__,_|_|\__|
    """
                                                 
    print(ascii_art)
                                          
    print("                ******* Ph VIALLE *******\n             * github.com/cyb3rxp/GWS-Audit *\n                    * Licence GPLv3 *\n                     * Version 0.1 * ")
    
    while True:
        choix = input("\n\n================ Menu ===============\n[+] Lancer l'exécution du script : O \n[+] Afficher les prérequis : P \n[+] Vérifier les prérequis : V \n[+] Quitter : Q\n\n[i] Taper la touche correspondante à votre choix : \n").strip().upper()

        if choix == "O":
            print("OK, poursuite du script.\n")
            break
        elif choix == "Q":
            print("\n[i] Fin du script.\n")
            sys.exit(0)
        elif choix == "P":
            print("\n[i] Prérequis pour pouvoir exécuter ce script : ")
            print("1) Python3 + PIP installés et à jour : https://www.python.org/downloads/")
            print("2) le module Python Checkdmarc installé. Commande d'installation : python -m pip install checkdmarc ")
            print("3) un compte utilisateur administrateur de l'environnement GWS à auditer ")
            print("4) GAM installé : https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7, configuré avec le nom de domaine GWS et compte admin du GWS à auditer")
            print("5) le domaine de l'environnement GWS à auditer défini au niveau des variables 'DNS_domain' et 'internal_domain' dans le script")
            print("6) /!\\ l'accord préalable à l'audit par l'entité ayant contractualisé l'environnement Google Workspace à auditer.")
            print("\n[i] Fin du script.\n")
            sys.exit(0)
        elif choix == "V":
            if not check_prereq():
                print("[i] Tous les prérequis ne sont pas satisfaits.")
                print("[i] Corrigez les erreurs puis relancez le script.\n")
            sys.exit(1)
        else:
            print("\nSaisie invalide. Tapez O, N, ou P.\n")
    
    
    print("[i] Vérification des répertoires de travail...")
    ensure_dirs()
    if not check_prereq():
        print("[i] Tous les prérequis ne sont pas satisfaits.")
        print("[i] Corrigez les erreurs puis relancez le script.\n")
        sys.exit(1)

    print("[i] Tous les prérequis sont valides.")
    print("[i] Poursuite du script...\n")
    
    findings = []

    print("[i] Lancement des audits activés...\n")
    sys.exit(0)
    audit_identities(findings)
    audit_groups(findings)
    audit_drive(findings)
    audit_gmail(findings)
    audit_devices(findings)
    audit_sensitive(findings)
    audit_SPF_DKIM(findings)

    save_reports(findings)


if __name__ == "__main__":
    main()