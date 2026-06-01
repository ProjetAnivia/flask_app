"""
app.py — Backend Flask IRM Préclinique
Équipe 3 : Interface Web & Backend API

Lancer :
  pip install flask flask-login
  python3 app.py

Accéder : http://localhost:5000
Comptes démo : admin/admin123  |  operateur/op123  |  chercheur/ch123
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, make_response, send_from_directory, Response, stream_with_context
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from pathlib import Path
import json, sqlite3, hashlib, os, re, csv, io, socket, threading, bcrypt as _bcrypt, secrets, calendar as _cal, random, time, shutil
import smtplib, urllib.request as _urllib_req, urllib.parse as _urllib_parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

def sanitize_animal_id(raw: str) -> str:
    """
    Normalise un ID animal — convention F2 client :
      Rat-1, Rat-2, animal_bis, animal_VRAI, date_nomanimal
      Espaces et étoiles → tiret. Caractères spéciaux → supprimés.
    """
    s = re.sub(r"[* ]+", "-", str(raw).strip())
    s = re.sub(r"[^a-zA-Z0-9_\-]", "", s)
    s = re.sub(r"-{2,}", "-", s).strip("-_")
    return s if s else "UNKNOWN"

def build_animal_folder(animal_id: str, date_acq: str) -> str:
    """
    Construit le nom du dossier animal selon convention FAIR :
      Format : AAAAMMJJ_AnimalID
      Ex : 20250312_Rat-1, 20250401_B3, 20250501_animal_bis
    """
    date_clean  = re.sub(r"[^0-9]", "", date_acq)[:8].ljust(8, "0")
    animal_clean = sanitize_animal_id(animal_id)
    return f"{date_clean}_{animal_clean}"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_change_in_prod")

# ── Sécurité des cookies ──────────────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY  = True,
    SESSION_COOKIE_SAMESITE  = "Lax",
    # Passer HTTPS_ENABLED=true en production (reverse proxy Synology avec TLS)
    SESSION_COOKIE_SECURE    = os.environ.get("HTTPS_ENABLED", "").lower() == "true",
)

# ── Email (Brevo API, Resend API, ou SMTP fallback) ──────────────────────────
BREVO_API_KEY  = os.environ.get("BREVO_API_KEY", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@irm-fair.local")
EMAIL_FROM_NAME  = os.environ.get("EMAIL_FROM_NAME", "IRM.FAIR")
EMAIL_FROM_ADDR  = os.environ.get("EMAIL_FROM_ADDR", "")
APP_URL   = os.environ.get("APP_URL",   "http://localhost:5001")
EMAIL_CONFIGURED = bool(BREVO_API_KEY or RESEND_API_KEY or SMTP_HOST)

# ── reCAPTCHA v3 (optionnel — désactivé si clés absentes) ───────────────────
RECAPTCHA_SITE_KEY      = os.environ.get("RECAPTCHA_SITE_KEY",   "")
RECAPTCHA_SECRET_KEY    = os.environ.get("RECAPTCHA_SECRET_KEY", "")
RECAPTCHA_MIN_SCORE     = float(os.environ.get("RECAPTCHA_MIN_SCORE", "0.5"))
RECAPTCHA_ENABLED       = bool(RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY)

def verify_recaptcha(token: str, expected_action: str = "login") -> tuple[bool, str]:
    """
    Vérifie un token reCAPTCHA v3 auprès de l'API Google.
    Retourne (succès, message d'erreur si échec).
    v3 retourne un score 0.0–1.0 + le nom de l'action exécutée.
    """
    if not token:
        return False, "Token absent"
    try:
        data = f"secret={RECAPTCHA_SECRET_KEY}&response={token}".encode()
        req  = _urllib_req.Request(
            "https://www.google.com/recaptcha/api/siteverify",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with _urllib_req.urlopen(req, timeout=5) as r:
            result = json.loads(r.read())

        if not result.get("success"):
            errors = ",".join(result.get("error-codes", []))
            return False, f"Échec Google ({errors})"

        score  = float(result.get("score", 0))
        action = result.get("action", "")

        if action != expected_action:
            return False, f"Action inattendue : {action}"
        if score < RECAPTCHA_MIN_SCORE:
            return False, f"Score trop bas ({score:.2f} < {RECAPTCHA_MIN_SCORE})"
        return True, ""
    except Exception as exc:
        print(f"[reCAPTCHA] vérification échouée : {exc}", flush=True)
        return False, "Erreur réseau"

# ── Protection anti-brute-force ──────────────────────────────────────────────
BRUTEFORCE_MAX_ATTEMPTS = 5   # tentatives max
BRUTEFORCE_WINDOW_MIN   = 10  # fenêtre de détection (minutes)
BRUTEFORCE_LOCKOUT_MIN  = 15  # durée de blocage (minutes)

# ── CAPTCHA ──────────────────────────────────────────────────────────────────
CAPTCHA_VALIDITY_MIN = 30          # minutes avant de re-demander un captcha
_captcha_cleared : dict[str, datetime] = {}   # ip → dernier captcha validé
_captcha_lock    = threading.Lock()

def captcha_is_cleared(ip: str) -> bool:
    """Retourne True si l'IP a déjà résolu un captcha récemment."""
    if not ip:
        return False
    with _captcha_lock:
        ts = _captcha_cleared.get(ip)
    if ts is None:
        return False
    return datetime.utcnow() - ts < timedelta(minutes=CAPTCHA_VALIDITY_MIN)

def captcha_clear_ip(ip: str):
    """Enregistre que l'IP vient de valider un captcha."""
    if not ip:
        return
    with _captcha_lock:
        _captcha_cleared[ip] = datetime.utcnow()
        # Nettoyage des entrées expirées (évite la croissance infinie)
        cutoff = datetime.utcnow() - timedelta(minutes=CAPTCHA_VALIDITY_MIN * 2)
        expired = [k for k, v in _captcha_cleared.items() if v < cutoff]
        for k in expired:
            del _captcha_cleared[k]

def captcha_generate() -> tuple[str, int]:
    """Génère une question arithmétique simple. Retourne (question, réponse)."""
    ops = [('+', lambda a, b: a + b), ('-', lambda a, b: a - b), ('×', lambda a, b: a * b)]
    sym, fn = random.choice(ops)
    if sym == '×':
        a, b = random.randint(2, 9), random.randint(2, 9)
    elif sym == '-':
        a = random.randint(5, 20)
        b = random.randint(1, a)
    else:
        a, b = random.randint(1, 20), random.randint(1, 20)
    return f"{a} {sym} {b}", fn(a, b)

# ── Cache géolocalisation IP ─────────────────────────────────────────────────
_geo_cache : dict[str, str] = {}
_geo_lock  = threading.Lock()

# IPs privées/réservées — pas de résolution géo
_PRIVATE_IP_RE = re.compile(
    r'^(127\.|10\.|192\.168\.|169\.254\.'
    r'|172\.(1[6-9]|2[0-9]|3[01])\.'
    r'|::1$|fe80:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)',
    re.IGNORECASE
)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# En local  : ./db/irm_fair.db
# En Docker : /data/irm_fair.db (volume persisté)
_db_dir = Path(os.environ.get("DB_DIR", "./db"))
_db_dir.mkdir(parents=True, exist_ok=True)
DB_PATH = _db_dir / "irm_fair.db"

# En local  : ./nas_simule/structured
# En Docker : /nas/structured (volume docker-compose)
NAS_ROOT = Path(os.environ.get("NAS_ROOT", "./nas_simule/structured"))
NAS_ROOT.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────
#  BASE DE DONNÉES (SQLite)
# ─────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'chercheur'
        );

        CREATE TABLE IF NOT EXISTS projets (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            nom  TEXT UNIQUE NOT NULL,
            resp TEXT,
            nb_animaux_prevus INTEGER DEFAULT 0,
            seq_par_animal    INTEGER DEFAULT 3
        );

        CREATE TABLE IF NOT EXISTS animaux (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            animal_id  TEXT NOT NULL,
            espece     TEXT,
            projet     TEXT,
            date_premiere_acq TEXT,
            nb_acquisitions   INTEGER DEFAULT 0,
            statut     TEXT DEFAULT 'en_attente'
        );

        CREATE TABLE IF NOT EXISTS acquisitions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            animal_id   TEXT NOT NULL,
            projet      TEXT NOT NULL,
            sequence    TEXT,
            date_acq    TEXT,
            fichier_dest TEXT,
            md5         TEXT,
            statut      TEXT DEFAULT 'ok',
            importé_par TEXT,
            importé_le  TEXT
        );

        CREATE TABLE IF NOT EXISTS pipeline_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            source     TEXT,
            dest       TEXT,
            animal_id  TEXT,
            sequence   TEXT,
            statut     TEXT,
            md5        TEXT,
            erreur     TEXT
        );

        CREATE TABLE IF NOT EXISTS commentaires (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            animal_id  TEXT NOT NULL,
            projet     TEXT NOT NULL,
            auteur     TEXT NOT NULL,
            type       TEXT DEFAULT 'note',
            contenu    TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connexions_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            action     TEXT NOT NULL,
            ip         TEXT,
            timestamp  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS volumetries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            animal_id   TEXT NOT NULL,
            projet      TEXT NOT NULL,
            acq_id      INTEGER NOT NULL,
            sequence    TEXT,
            statut      TEXT DEFAULT 'en_cours',
            methode     TEXT DEFAULT 'kmeans_3classes',
            resultats   TEXT,
            fichier_csv TEXT,
            calcule_le  TEXT,
            calcule_par TEXT,
            erreur      TEXT
        );

        CREATE TABLE IF NOT EXISTS dti_analyses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            animal_id   TEXT NOT NULL,
            projet      TEXT NOT NULL,
            acq_id      INTEGER NOT NULL,
            sequence    TEXT,
            statut      TEXT DEFAULT 'en_cours',
            commandes   TEXT,
            resultats   TEXT,
            calcule_le  TEXT,
            calcule_par TEXT,
            erreur      TEXT
        );
        """)

        db.executescript("""
        CREATE TABLE IF NOT EXISTS user_aliases (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            real_path  TEXT NOT NULL,
            alias_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, real_path)
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            username   TEXT NOT NULL,
            token      TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            type       TEXT NOT NULL,
            payload    TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projet_membres (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            projet      TEXT NOT NULL,
            user_id     INTEGER NOT NULL,
            role_projet TEXT NOT NULL DEFAULT 'membre',
            added_by    TEXT,
            added_at    TEXT NOT NULL,
            UNIQUE(projet, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_projet_membres_projet  ON projet_membres(projet);
        CREATE INDEX IF NOT EXISTS idx_projet_membres_userid  ON projet_membres(user_id);

        CREATE TABLE IF NOT EXISTS projet_notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            projet     TEXT NOT NULL,
            auteur     TEXT NOT NULL,
            titre      TEXT,
            contenu    TEXT NOT NULL,
            type       TEXT DEFAULT 'note',
            epinglee   INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_projet_notes_projet ON projet_notes(projet);

        CREATE TABLE IF NOT EXISTS notifications (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            type       TEXT NOT NULL,
            titre      TEXT NOT NULL,
            corps      TEXT,
            url        TEXT,
            projet     TEXT,
            lue        INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, lue);

        CREATE TABLE IF NOT EXISTS notifications_sent (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            kind         TEXT NOT NULL,
            ref_date     TEXT NOT NULL,
            sent_at      TEXT NOT NULL,
            UNIQUE(user_id, kind, ref_date)
        );
        """)

        # Migration douce — ajoute les colonnes si absentes (SQLite ne supporte pas IF NOT EXISTS sur ALTER)
        for col_sql in [
            "ALTER TABLE projets ADD COLUMN seq_par_animal INTEGER DEFAULT 3",
            "ALTER TABLE projets ADD COLUMN statut TEXT DEFAULT 'actif'",
            "ALTER TABLE projets ADD COLUMN date_debut TEXT",
            "ALTER TABLE projets ADD COLUMN date_fin_prevue TEXT",
            "ALTER TABLE connexions_log ADD COLUMN pays TEXT DEFAULT '—'",
            "ALTER TABLE users ADD COLUMN totp_secret TEXT",
            "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN inactivity_timeout INTEGER DEFAULT 30",
            "ALTER TABLE projets ADD COLUMN protocole_ethique TEXT",
            "ALTER TABLE users ADD COLUMN email TEXT",
            "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN email_verify_token TEXT",
            "ALTER TABLE projets ADD COLUMN acq_prevues_override INTEGER",
            # ── Suivi expérimental enrichi (cahier des charges) ───────────────
            "ALTER TABLE acquisitions ADD COLUMN poids_g REAL",
            "ALTER TABLE acquisitions ADD COLUMN qualite TEXT",
            "ALTER TABLE acquisitions ADD COLUMN probleme_type TEXT",
            "ALTER TABLE acquisitions ADD COLUMN probleme_desc TEXT",
            # ── Planification (créneau réservé sur l'IRM) ─────────────────────
            "ALTER TABLE acquisitions ADD COLUMN heure_debut TEXT",
            "ALTER TABLE acquisitions ADD COLUMN duree_min INTEGER",
        ]:
            try:
                db.execute(col_sql)
            except sqlite3.OperationalError:
                pass

        # Utilisateurs démo — toujours resynchronisés au démarrage pour garantir
        # que les mots de passe correspondent à ceux affichés sur la page de login.
        # (les comptes créés par l'utilisateur final ne sont PAS impactés)
        users_demo = [
            ("admin",      "admin123",   "admin"),
            ("nicolas",    "nico123",    "admin"),
            ("clemence",   "clem123",    "admin"),
            ("florent",    "flo123",     "admin"),
            ("pauline",    "Pauline45",  "operateur"),
            ("chercheur",  "ch123",      "chercheur"),
        ]
        for username, plain_pw, role in users_demo:
            existing = db.execute(
                "SELECT id FROM users WHERE username=?", (username,)
            ).fetchone()
            if existing:
                # Resynchronise mot de passe + rôle pour rester cohérent avec login.html
                db.execute(
                    "UPDATE users SET password=?, role=? WHERE username=?",
                    (hash_pw(plain_pw), role, username)
                )
            else:
                db.execute(
                    "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                    (username, hash_pw(plain_pw), role)
                )

        # Projets et animaux démo — uniquement si la base est vide (évite d'écraser les données réelles)
        if db.execute("SELECT COUNT(*) FROM projets").fetchone()[0] == 0:
            projets_demo = [
                ("tumorigenese",       "Clémence", 20),
                ("inflammation",       "Florent",  15),
                ("neuro_dev",          "Nicolas",  12),
            ]
            for p in projets_demo:
                db.execute("INSERT OR IGNORE INTO projets (nom,resp,nb_animaux_prevus) VALUES (?,?,?)", p)

            animaux_demo = [
                ("B3",  "Rat",   "tumorigenese", "20250301", 3, "ok"),
                ("B5",  "Rat",   "tumorigenese", "20250301", 2, "en_attente"),
                ("R09", "Rat",   "inflammation", "20250305", 1, "en_cours"),
                ("R12", "Rat",   "inflammation", "20250308", 1, "a_refaire"),
                ("S07", "Souris","neuro_dev",    "20250310", 1, "en_attente"),
            ]
            for a in animaux_demo:
                db.execute("INSERT OR IGNORE INTO animaux (animal_id,espece,projet,date_premiere_acq,nb_acquisitions,statut) VALUES (?,?,?,?,?,?)", a)

        # ── Données demo mai 2026 ─────────────────────────────────────────────
        # Injectées au démarrage si absentes — permet de visualiser l'historique
        if db.execute(
            "SELECT COUNT(*) FROM acquisitions WHERE date_acq LIKE '2026-05%'"
        ).fetchone()[0] == 0:
            # S'assurer que les projets démo existent
            for p_nom, p_resp, p_nb in [
                ("tumorigenese", "Clémence", 20),
                ("inflammation",  "Florent",  15),
                ("neuro_dev",     "Nicolas",  12),
            ]:
                db.execute(
                    "INSERT OR IGNORE INTO projets (nom,resp,nb_animaux_prevus) VALUES (?,?,?)",
                    (p_nom, p_resp, p_nb)
                )
            # S'assurer que les animaux démo existent
            for a_id, esp, proj, d, nb, st in [
                ("B3",  "Rat",    "tumorigenese", "20250301", 3, "ok"),
                ("B5",  "Rat",    "tumorigenese", "20250301", 2, "en_attente"),
                ("R09", "Rat",    "inflammation", "20250305", 1, "en_cours"),
                ("R12", "Rat",    "inflammation", "20250308", 1, "a_refaire"),
                ("S07", "Souris", "neuro_dev",    "20250310", 1, "en_attente"),
            ]:
                db.execute(
                    "INSERT OR IGNORE INTO animaux "
                    "(animal_id,espece,projet,date_premiere_acq,nb_acquisitions,statut) "
                    "VALUES (?,?,?,?,?,?)",
                    (a_id, esp, proj, d, nb, st)
                )

            now_str = datetime.now().isoformat()
            may_acq = [
                # (animal_id, projet, sequence, date_acq, statut, user)
                ("B3",  "tumorigenese", "T1_RARE",   "2026-05-05", "ok",        "nicolas"),
                ("B3",  "tumorigenese", "T2_MSME",   "2026-05-05", "ok",        "nicolas"),
                ("B3",  "tumorigenese", "DTI_30dir",  "2026-05-05", "ok",        "nicolas"),
                ("B5",  "tumorigenese", "T1_RARE",   "2026-05-06", "ok",        "clemence"),
                ("B5",  "tumorigenese", "T2_MSME",   "2026-05-06", "a_refaire", "clemence"),
                ("R09", "inflammation", "T2_MSME",   "2026-05-07", "ok",        "florent"),
                ("R09", "inflammation", "BOLD_REST",  "2026-05-07", "ok",        "florent"),
                ("R12", "inflammation", "T2_MSME",   "2026-05-08", "ok",        "florent"),
                ("R12", "inflammation", "T1_RARE",   "2026-05-08", "a_refaire", "florent"),
                ("B3",  "tumorigenese", "T1_RARE",   "2026-05-12", "ok",        "nicolas"),
                ("B3",  "tumorigenese", "T2_MSME",   "2026-05-12", "ok",        "nicolas"),
                ("R09", "inflammation", "T2_MSME",   "2026-05-14", "ok",        "florent"),
                ("R12", "inflammation", "T2_MSME",   "2026-05-15", "ok",        "florent"),
                ("R12", "inflammation", "T1_RARE",   "2026-05-15", "ok",        "florent"),
                ("S07", "neuro_dev",    "T2_MSME",   "2026-05-19", "ok",        "nicolas"),
                ("S07", "neuro_dev",    "DTI_30dir",  "2026-05-19", "ok",        "nicolas"),
                ("S07", "neuro_dev",    "T1_RARE",   "2026-05-20", "ok",        "nicolas"),
                ("B5",  "tumorigenese", "T1_RARE",   "2026-05-21", "ok",        "clemence"),
                ("B5",  "tumorigenese", "T2_MSME",   "2026-05-21", "ok",        "clemence"),
                ("B3",  "tumorigenese", "T1_RARE",   "2026-05-26", "ok",        "clemence"),
                ("B3",  "tumorigenese", "T2_MSME",   "2026-05-26", "ok",        "clemence"),
                ("B3",  "tumorigenese", "DTI_30dir",  "2026-05-26", "ok",        "clemence"),
                ("R09", "inflammation", "T2_MSME",   "2026-05-27", "ok",        "florent"),
                ("R09", "inflammation", "BOLD_REST",  "2026-05-27", "ok",        "florent"),
                ("S07", "neuro_dev",    "T2_MSME",   "2026-05-28", "ok",        "nicolas"),
            ]
            for a_id, proj, seq, date_acq, statut, user in may_acq:
                date_clean = re.sub(r"[^0-9]", "", date_acq)[:8]
                animal_folder = f"{date_clean}_{sanitize_animal_id(a_id)}"
                seq_folder    = sanitize_animal_id(seq)
                fiche         = f"{proj}/{animal_folder}/{seq_folder}/{a_id}_{seq}.nii.gz"
                db.execute(
                    "INSERT INTO acquisitions "
                    "(animal_id,projet,sequence,date_acq,fichier_dest,statut,importé_par,importé_le) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (a_id, proj, seq, date_acq, fiche, statut, user, now_str)
                )
                # Créer la structure de dossiers sur le NAS simulé
                nas_folder = NAS_ROOT / proj / animal_folder / seq_folder
                nas_folder.mkdir(parents=True, exist_ok=True)
                nii = nas_folder / f"{a_id}_{seq}.nii.gz"
                if not nii.exists():
                    nii.touch()

            # Mettre à jour nb_acquisitions des animaux concernés
            for a_id in {r[0] for r in may_acq}:
                db.execute(
                    "UPDATE animaux SET nb_acquisitions=("
                    "  SELECT COUNT(*) FROM acquisitions WHERE animal_id=?"
                    ") WHERE animal_id=?",
                    (a_id, a_id)
                )

        db.commit()

def hash_pw(pw: str) -> str:
    """Hache avec bcrypt (nouveau standard). Retourne un hash préfixé $2b$."""
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()

def verify_pw(pw: str, stored: str) -> bool:
    """
    Vérifie le mot de passe en supportant les deux schémas :
    - bcrypt ($2b$...) : nouveaux comptes et comptes migrés
    - SHA-256 (64 hex) : anciens comptes — acceptés et auto-migrés à la connexion
    """
    if stored.startswith("$2"):
        try:
            return _bcrypt.checkpw(pw.encode(), stored.encode())
        except Exception:
            return False
    # Schéma SHA-256 hérité
    return hashlib.sha256(pw.encode()).hexdigest() == stored

def get_real_ip() -> str:
    """Récupère la vraie IP client derrière un éventuel reverse-proxy."""
    for header in ("X-Forwarded-For", "X-Real-IP"):
        value = request.headers.get(header, "").strip()
        if value:
            return value.split(",")[0].strip()
    return request.remote_addr or ""


def get_country(ip: str) -> str:
    """Résout le pays depuis l'IP (cache mémoire, deux services en fallback)."""
    if not ip or _PRIVATE_IP_RE.match(ip):
        return "Local"
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    country = "—"
    apis = [
        (
            f"http://ip-api.com/json/{ip}?fields=status,country",
            lambda d: d.get("country") if d.get("status") == "success" else None,
        ),
        (
            f"https://ipinfo.io/{ip}/json",
            lambda d: d.get("country") or None,
        ),
    ]
    for url, extract in apis:
        try:
            req = _urllib_req.Request(url, headers={"User-Agent": "IRM-FAIR/1.0"})
            with _urllib_req.urlopen(req, timeout=4) as r:
                data = json.loads(r.read())
            result = extract(data)
            if result:
                country = result
                break
        except Exception as exc:
            print(f"[GEO] {url} → {exc}", flush=True)
    with _geo_lock:
        _geo_cache[ip] = country
    return country


def log_connexion(username: str, action: str, ip: str) -> None:
    """Enregistre un événement de connexion et résout le pays en arrière-plan."""
    ts = datetime.now().isoformat()
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO connexions_log (username, action, ip, timestamp, pays) VALUES (?,?,?,?,?)",
            (username, action, ip, ts, "—")
        )
        log_id = cur.lastrowid
        db.commit()

    def _resolve_geo():
        country = get_country(ip)
        with get_db() as db2:
            db2.execute("UPDATE connexions_log SET pays=? WHERE id=?", (country, log_id))
            db2.commit()

    threading.Thread(target=_resolve_geo, daemon=True).start()


def count_recent_failures(ip: str) -> int:
    """Compte les échecs de connexion de cette IP dans la fenêtre de détection."""
    cutoff = (datetime.now() - timedelta(minutes=BRUTEFORCE_WINDOW_MIN)).isoformat()
    with get_db() as db:
        return db.execute(
            "SELECT COUNT(*) FROM connexions_log "
            "WHERE ip=? AND action='login_failed' AND timestamp>?",
            (ip, cutoff)
        ).fetchone()[0]


def get_lockout_remaining(ip: str) -> int:
    """
    Retourne les secondes de blocage restantes (0 si pas bloqué).
    Bloqué si ≥ MAX_ATTEMPTS échecs dans la fenêtre de détection.
    Le compteur démarre à la Nième tentative et expire après LOCKOUT_MIN.
    """
    n = count_recent_failures(ip)
    if n < BRUTEFORCE_MAX_ATTEMPTS:
        return 0
    cutoff = (datetime.now() - timedelta(minutes=BRUTEFORCE_WINDOW_MIN)).isoformat()
    with get_db() as db:
        # Nième tentative la plus ancienne dans la fenêtre (index MAX_ATTEMPTS-1)
        row = db.execute(
            "SELECT timestamp FROM connexions_log "
            "WHERE ip=? AND action='login_failed' AND timestamp>? "
            "ORDER BY timestamp DESC LIMIT 1 OFFSET ?",
            (ip, cutoff, BRUTEFORCE_MAX_ATTEMPTS - 1)
        ).fetchone()
    if not row:
        return 0
    trigger = datetime.fromisoformat(row["timestamp"])
    end     = trigger + timedelta(minutes=BRUTEFORCE_LOCKOUT_MIN)
    secs    = (end - datetime.now()).total_seconds()
    return max(0, int(secs))


def _send_email(to_addr: str, subject: str, body: str) -> tuple[bool, str]:
    """Envoie un email via Brevo API (prioritaire), Resend API, ou SMTP fallback."""
    if not to_addr:
        return False, "Pas d'adresse destinataire"

    if BREVO_API_KEY:
        try:
            payload = json.dumps({
                "sender": {"name": EMAIL_FROM_NAME, "email": EMAIL_FROM_ADDR},
                "to": [{"email": to_addr}],
                "subject": subject,
                "textContent": body,
            }).encode()
            req = _urllib_req.Request(
                "https://api.brevo.com/v3/smtp/email",
                data=payload,
                headers={
                    "api-key": BREVO_API_KEY,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with _urllib_req.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    return True, ""
                return False, f"Brevo HTTP {resp.status}"
        except _urllib_req.HTTPError as e:
            err_body = e.read().decode(errors="replace")
            app.logger.error("Brevo API failed: %s %s", e, err_body)
            return False, f"Brevo {e.code}: {err_body}"
        except Exception as e:
            app.logger.error("Brevo API failed: %s", e)
            return False, str(e)

    if RESEND_API_KEY:
        try:
            from_str = f"{EMAIL_FROM_NAME} <{EMAIL_FROM_ADDR}>" if EMAIL_FROM_ADDR else EMAIL_FROM_NAME
            payload = json.dumps({
                "from": from_str,
                "to": [to_addr],
                "subject": subject,
                "text": body,
            }).encode()
            req = _urllib_req.Request(
                "https://api.resend.com/emails",
                data=payload,
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with _urllib_req.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    return True, ""
                return False, f"Resend HTTP {resp.status}"
        except _urllib_req.HTTPError as e:
            err_body = e.read().decode(errors="replace")
            app.logger.error("Resend API failed: %s %s", e, err_body)
            return False, f"Resend {e.code}: {err_body}"
        except Exception as e:
            app.logger.error("Resend API failed: %s", e)
            return False, str(e)

    if SMTP_HOST:
        try:
            msg = MIMEMultipart()
            msg["From"]    = SMTP_FROM
            msg["To"]      = to_addr
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.ehlo(); s.starttls()
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_USER or SMTP_FROM, to_addr, msg.as_string())
            return True, ""
        except Exception as e:
            app.logger.error("SMTP failed: %s", e)
            return False, str(e)

    return False, "Email non configuré (BREVO_API_KEY, RESEND_API_KEY, ou SMTP_HOST)"


def send_reset_email(to_addr: str, username: str, token: str) -> tuple[bool, str]:
    reset_url = f"{APP_URL}/reset-password/{token}"
    body = (
        f"Bonjour {username},\n\n"
        f"Une demande de réinitialisation de mot de passe a été effectuée pour votre compte IRM.FAIR.\n\n"
        f"Cliquez sur ce lien (valable 1 heure) :\n{reset_url}\n\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n\n"
        f"— IRM.FAIR"
    )
    return _send_email(to_addr, "IRM.FAIR — Réinitialisation de mot de passe", body)


def send_verification_email(to_addr: str, username: str, token: str) -> tuple[bool, str]:
    link = f"{APP_URL}/verify-email/{token}"
    body = (
        f"Bonjour {username},\n\n"
        f"Cliquez sur le lien suivant pour vérifier votre adresse email :\n{link}\n\n"
        f"Ce lien expire dans 24 heures.\n\n— IRM.FAIR"
    )
    return _send_email(to_addr, "IRM.FAIR — Vérification de votre adresse email", body)


def validate_password(pw: str) -> str | None:
    """Retourne un message d'erreur ou None si le mot de passe est valide."""
    if len(pw) < 10:
        return "Mot de passe trop court (10 caractères minimum)"
    if not re.search(r"[A-Z]", pw):
        return "Le mot de passe doit contenir au moins une majuscule"
    if not re.search(r"[0-9]", pw):
        return "Le mot de passe doit contenir au moins un chiffre"
    if not re.search(r"[^a-zA-Z0-9]", pw):
        return "Le mot de passe doit contenir au moins un caractère spécial (@, #, !, …)"
    return None


# ─────────────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if row:
        return User(row["id"], row["username"], row["role"])
    return None

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                return jsonify({"error": "Accès refusé"}), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ─────────────────────────────────────────────────
#  DROITS PAR PROJET
# ─────────────────────────────────────────────────
#
# Modèle (strict, par défaut) :
#   • Les admins globaux ont accès à TOUS les projets, toujours.
#   • Tout autre utilisateur (opérateur, chercheur) doit être explicitement
#     ajouté comme membre du projet pour y avoir accès.
#   • Un projet sans aucun membre déclaré n'est visible que par les admins.
#
# Rôles projet : 'responsable' (gère membres + édite) / 'membre' (édite) /
#                'lecteur' (lecture seule)
# ─────────────────────────────────────────────────

def projet_membres(projet: str) -> list[sqlite3.Row]:
    """Liste des membres d'un projet (rows {user_id, username, role_projet, added_by, added_at})."""
    with get_db() as db:
        return db.execute(
            """SELECT pm.id, pm.user_id, u.username, pm.role_projet, pm.added_by, pm.added_at
               FROM projet_membres pm
               JOIN users u ON u.id = pm.user_id
               WHERE pm.projet = ?
               ORDER BY pm.role_projet, u.username""",
            (projet,)
        ).fetchall()

def projet_is_restricted(projet: str) -> bool:
    """True si le projet a au moins un membre déclaré (mode restreint)."""
    with get_db() as db:
        n = db.execute(
            "SELECT COUNT(*) FROM projet_membres WHERE projet = ?", (projet,)
        ).fetchone()[0]
    return n > 0

def user_projet_role(user, projet: str) -> str | None:
    """Retourne le rôle projet de l'utilisateur ('responsable'/'membre'/'lecteur') ou None."""
    if not user or not getattr(user, "is_authenticated", False):
        return None
    with get_db() as db:
        r = db.execute(
            "SELECT role_projet FROM projet_membres WHERE projet=? AND user_id=?",
            (projet, user.id)
        ).fetchone()
    return r["role_projet"] if r else None

def user_can_view_projet(user, projet: str) -> bool:
    """Accès lecture : admin global OU membre déclaré (n'importe quel rôle projet)."""
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.role == "admin":
        return True
    return user_projet_role(user, projet) is not None

def user_can_edit_projet(user, projet: str) -> bool:
    """Édition acquisitions / commentaires : admin global OU membre/responsable du projet."""
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.role == "admin":
        return True
    return user_projet_role(user, projet) in ("responsable", "membre")

def user_can_manage_projet(user, projet: str) -> bool:
    """Gestion des membres et settings du projet."""
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.role == "admin":
        return True
    return user_projet_role(user, projet) == "responsable"

def projet_require_view(projet: str):
    """Retourne une réponse 403 si l'utilisateur n'a pas le droit de voir, sinon None."""
    if not user_can_view_projet(current_user, projet):
        return jsonify({"error": "Accès refusé à ce projet"}), 403
    return None


# ─────────────────────────────────────────────────
#  NOTIFICATIONS — inbox in-app + emails optionnels
# ─────────────────────────────────────────────────
#
# Toutes les notifications sont stockées en base (inbox visible dans l'app).
# Si l'utilisateur a un email et que SMTP est configuré, un email est aussi envoyé.
# ─────────────────────────────────────────────────

def notify(user_id: int, type_: str, titre: str, corps: str = "",
           url: str | None = None, projet: str | None = None,
           send_email: bool = True) -> int:
    """
    Crée une notification pour `user_id`. Retourne l'ID créé.
    Si send_email=True et l'utilisateur a un email vérifié + SMTP configuré, envoie un mail.
    """
    now_iso = datetime.now().isoformat()
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO notifications (user_id, type, titre, corps, url, projet, lue, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?)""",
            (user_id, type_, titre, corps, url, projet, now_iso)
        )
        notif_id = cur.lastrowid

        if send_email and EMAIL_CONFIGURED:
            row = db.execute(
                "SELECT username, email FROM users WHERE id=?", (user_id,)
            ).fetchone()
        else:
            row = None
        db.commit()

    if row and row["email"]:
        link = f"{APP_URL}{url}" if url else APP_URL
        body = (
            f"<p>Bonjour {row['username']},</p>"
            f"<p>{corps or titre}</p>"
            + (f'<p><a href="{link}">Ouvrir dans IRM FAIR</a></p>' if url else '')
            + "<p style='color:#999;font-size:12px;'>Notification automatique IRM FAIR.</p>"
        )
        try:
            _send_email(row["email"], f"[IRM FAIR] {titre}", body)
        except Exception as exc:
            print(f"[notify] email échoué : {exc}", flush=True)

    return notif_id


def notify_projet_members(projet: str, type_: str, titre: str, corps: str = "",
                          url: str | None = None, exclude_user_id: int | None = None) -> int:
    """Notifie tous les membres d'un projet + les admins globaux. Retourne le nb envoyé."""
    with get_db() as db:
        members = db.execute(
            "SELECT user_id FROM projet_membres WHERE projet=?", (projet,)
        ).fetchall()
        admins  = db.execute(
            "SELECT id FROM users WHERE role='admin'"
        ).fetchall()

    targets = {m["user_id"] for m in members} | {a["id"] for a in admins}
    if exclude_user_id is not None:
        targets.discard(exclude_user_id)

    for uid in targets:
        notify(uid, type_, titre, corps, url, projet, send_email=True)
    return len(targets)


# ── Scheduler quotidien (rappel J-1 à 8h) ────────────────────────────────────
def _send_tomorrow_reminders():
    """Pour chaque utilisateur, envoie un récap des acquisitions planifiées demain."""
    tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
    today_iso = datetime.now().strftime("%Y-%m-%d")

    with get_db() as db:
        rows = db.execute(
            """SELECT animal_id, projet, sequence, heure_debut, duree_min, importé_par
               FROM acquisitions
               WHERE date_acq = ? AND statut IN ('en_attente', 'en_cours')
               ORDER BY projet, heure_debut""",
            (tomorrow,)
        ).fetchall()
        if not rows:
            return

        # Groupe par utilisateur destinataire (membres des projets concernés + admins)
        users = db.execute(
            "SELECT id, username, email FROM users WHERE COALESCE(email,'') != ''"
        ).fetchall()
        sent_already = {
            (r["user_id"], r["ref_date"]) for r in
            db.execute(
                "SELECT user_id, ref_date FROM notifications_sent WHERE kind='reminder_j1'"
            ).fetchall()
        }

    by_projet: dict[str, list] = {}
    for r in rows:
        by_projet.setdefault(r["projet"], []).append(dict(r))

    sent = 0
    for u in users:
        if (u["id"], tomorrow) in sent_already:
            continue
        # Récupère les projets accessibles
        user_obj = type("U", (), {"id": u["id"], "username": u["username"], "role": None,
                                  "is_authenticated": True})()
        # Recharge le rôle global
        with get_db() as db2:
            urow = db2.execute("SELECT role FROM users WHERE id=?", (u["id"],)).fetchone()
            user_obj.role = urow["role"] if urow else None

        accessible = [p for p in by_projet if user_can_view_projet(user_obj, p)]
        if not accessible:
            continue
        nb_acqs = sum(len(by_projet[p]) for p in accessible)

        lines = []
        for p in accessible:
            for a in by_projet[p]:
                heure = a["heure_debut"] or "—"
                duree = f" ({a['duree_min']} min)" if a["duree_min"] else ""
                lines.append(f"• {heure}{duree} — {a['animal_id']} · {a['sequence'] or '—'} ({p})")

        titre = f"{nb_acqs} acquisition(s) prévues demain ({tomorrow})"
        corps = "<br>".join(lines)
        notify(u["id"], "reminder_j1", titre, corps, url="/calendrier")

        # Mémorise l'envoi pour éviter les doublons
        with get_db() as db2:
            db2.execute(
                "INSERT OR IGNORE INTO notifications_sent (user_id, kind, ref_date, sent_at) "
                "VALUES (?, 'reminder_j1', ?, ?)",
                (u["id"], tomorrow, datetime.now().isoformat())
            )
            db2.commit()
        sent += 1
    print(f"[reminder_j1] {sent} email(s)/notification(s) pour {tomorrow}", flush=True)


def _scheduler_loop():
    """Boucle légère : check toutes les 10 min si on doit envoyer les rappels du lendemain."""
    last_run = None
    while True:
        try:
            time.sleep(60 * 10)
            now = datetime.now()
            if now.hour == 8 and last_run != now.date():
                _send_tomorrow_reminders()
                last_run = now.date()
        except Exception as exc:
            print(f"[scheduler] erreur : {exc}", flush=True)
            time.sleep(60)


# Lance le scheduler en daemon une seule fois
_scheduler_started = False
def _ensure_scheduler():
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True
    t = threading.Thread(target=_scheduler_loop, daemon=True, name="notif-scheduler")
    t.start()
    print("[scheduler] démarré", flush=True)


# ── API notifications ────────────────────────────────────────────────────────

@app.route("/api/notifications")
@login_required
def api_notifications():
    """Liste les notifications de l'utilisateur courant (50 dernières)."""
    with get_db() as db:
        rows = db.execute(
            """SELECT id, type, titre, corps, url, projet, lue, created_at
               FROM notifications
               WHERE user_id = ?
               ORDER BY created_at DESC LIMIT 50""",
            (current_user.id,)
        ).fetchall()
        nb_unread = db.execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id=? AND lue=0",
            (current_user.id,)
        ).fetchone()[0]

    return jsonify({
        "items":     [dict(r) for r in rows],
        "nb_unread": nb_unread,
    })


@app.route("/api/notifications/<int:nid>/read", methods=["POST"])
@login_required
def api_notification_mark_read(nid):
    with get_db() as db:
        db.execute(
            "UPDATE notifications SET lue=1 WHERE id=? AND user_id=?",
            (nid, current_user.id)
        )
        db.commit()
    return jsonify({"ok": True})


@app.route("/api/notifications/mark-all-read", methods=["POST"])
@login_required
def api_notifications_mark_all_read():
    with get_db() as db:
        db.execute(
            "UPDATE notifications SET lue=1 WHERE user_id=? AND lue=0",
            (current_user.id,)
        )
        db.commit()
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────
#  SERVER-SENT EVENTS — temps réel multi-utilisateurs
# ─────────────────────────────────────────────────

def emit_event(type_: str, payload: dict):
    """Publie un événement dans la table events (visible par tous les clients SSE)."""
    now    = datetime.utcnow().isoformat()
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO events (type, payload, created_at) VALUES (?, ?, ?)",
            (type_, json.dumps(payload, ensure_ascii=False), now)
        )
        db.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
        db.commit()


@app.route("/api/events")
@login_required
def api_sse():
    last_id = request.args.get("lastEventId", 0, type=int)

    def generate():
        nonlocal last_id
        # Message de connexion immédiat
        yield f"data: {json.dumps({'type': 'connected', 'user': current_user.username})}\n\n"
        while True:
            try:
                with get_db() as db:
                    rows = db.execute(
                        "SELECT id, type, payload, created_at FROM events WHERE id > ? ORDER BY id LIMIT 20",
                        (last_id,)
                    ).fetchall()
                for row in rows:
                    last_id = row["id"]
                    data = json.dumps({
                        "type":       row["type"],
                        "payload":    json.loads(row["payload"]),
                        "created_at": row["created_at"],
                    })
                    yield f"id: {row['id']}\ndata: {data}\n\n"
            except Exception:
                pass
            # Heartbeat toutes les 2 s pour maintenir la connexion
            yield ": heartbeat\n\n"
            time.sleep(2)

    resp = Response(stream_with_context(generate()), mimetype="text/event-stream")
    resp.headers["Cache-Control"]     = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"   # désactive le buffer nginx/Synology
    return resp


# ─────────────────────────────────────────────────
#  ROUTES AUTH
# ─────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_real_ip()

    def _render(error=None):
        """Rend login.html avec le bon type de captcha selon la config."""
        # reCAPTCHA v2 : toujours affiché (pas d'optimisation IP — évite les
        # problèmes de load-balancer multi-instances et navigation privée)
        if RECAPTCHA_ENABLED:
            return render_template("login.html", error=error,
                                   recaptcha_site_key=RECAPTCHA_SITE_KEY)
        # Fallback : captcha arithmétique uniquement si reCAPTCHA désactivé
        if captcha_is_cleared(ip):
            return render_template("login.html", error=error)
        q, ans = captcha_generate()
        session["_captcha_answer"] = ans
        return render_template("login.html", error=error, captcha_question=q)

    if request.method == "POST":
        # ── Protection anti-brute-force ──────────────────────────────────────
        secs = get_lockout_remaining(ip)
        if secs > 0:
            mins = (secs + 59) // 60
            return _render(error=f"Trop de tentatives échouées. Compte temporairement bloqué — réessayez dans {mins} min.")

        # ── Vérification CAPTCHA ──────────────────────────────────────────────
        if RECAPTCHA_ENABLED:
            # reCAPTCHA v3 : score + action
            token = request.form.get("g-recaptcha-response", "")
            ok, err = verify_recaptcha(token, expected_action="login")
            if not ok:
                print(f"[reCAPTCHA v3] refus : {err}", flush=True)
                return _render(error="Vérification reCAPTCHA échouée. Veuillez recommencer.")
        elif not captcha_is_cleared(ip):
            # Fallback arithmétique
            user_ans = request.form.get("captcha_answer", "").strip()
            expected = session.pop("_captcha_answer", None)
            try:
                correct = (int(user_ans) == expected)
            except (ValueError, TypeError):
                correct = False
            if not correct:
                return _render(error="Réponse au captcha incorrecte.")
            captcha_clear_ip(ip)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if row and verify_pw(password, row["password"]):
            # Migration transparente SHA-256 → bcrypt au premier login
            if not row["password"].startswith("$2"):
                with get_db() as db2:
                    db2.execute("UPDATE users SET password=? WHERE id=?",
                                (hash_pw(password), row["id"]))
                    db2.commit()
            # 2FA activé → rediriger vers la page de vérification
            if row["totp_enabled"]:
                session["_2fa_user_id"]  = row["id"]
                session["_2fa_username"] = row["username"]
                return redirect(url_for("login_2fa"))
            login_user(User(row["id"], row["username"], row["role"]))
            session['_last_activity']      = datetime.utcnow().isoformat()
            session['_inactivity_timeout'] = int(row['inactivity_timeout']) if row['inactivity_timeout'] is not None else 30
            log_connexion(row["username"], "login", ip)
            return redirect(url_for("dashboard"))

        # Échec — logger et vérifier si on doit bloquer
        log_connexion(username or "—", "login_failed", ip)
        failures = count_recent_failures(ip)
        remaining = max(0, BRUTEFORCE_MAX_ATTEMPTS - failures)
        if remaining > 0:
            err = f"Identifiants incorrects. ({remaining} tentative(s) restante(s) avant blocage)"
        else:
            mins = BRUTEFORCE_LOCKOUT_MIN
            err  = f"Trop de tentatives échouées. Compte temporairement bloqué — réessayez dans {mins} min."
        return _render(error=err)

    return _render()

# ─────────────────────────────────────────────────
#  SÉCURITÉ — headers & CSRF
# ─────────────────────────────────────────────────

@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault("X-Frame-Options",          "SAMEORIGIN")
    resp.headers.setdefault("X-Content-Type-Options",   "nosniff")
    resp.headers.setdefault("X-XSS-Protection",         "1; mode=block")
    resp.headers.setdefault("Referrer-Policy",          "strict-origin-when-cross-origin")
    resp.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://www.google.com https://www.gstatic.com "
            "https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "frame-src https://www.google.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    return resp

@app.context_processor
def inject_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["csrf_token"]}

# Chemins exemptés de la vérification CSRF (flux non-authentifiés)
_CSRF_EXEMPT_PREFIXES = ("/reset-password/",)
_CSRF_EXEMPT_EXACT    = {"/forgot-password"}

@app.before_request
def csrf_protect():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    path = request.path
    if path in _CSRF_EXEMPT_EXACT:
        return
    if any(path.startswith(p) for p in _CSRF_EXEMPT_PREFIXES):
        return

    token_sent = (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
        or (request.is_json and (request.json or {}).get("csrf_token"))
    )
    if token_sent != session.get("csrf_token"):
        if path.startswith("/api/"):
            return jsonify({"error": "Token CSRF invalide — rechargez la page"}), 403
        return render_template("403.html"), 403


@app.before_request
def check_inactivity():
    _exempt = {'login', 'logout', 'unlock', 'static', 'login_2fa',
               'forgot_password', 'reset_password_token'}
    if not request.endpoint or request.endpoint in _exempt:
        return
    if not current_user.is_authenticated:
        return

    # Session verrouillée → JSON pour les appels API, redirect sinon
    if session.get('_locked'):
        if request.path.startswith('/api/'):
            return jsonify({"error": "session_locked"}), 401
        return redirect(url_for('unlock'))

    # Timeout mis en cache dans la session (évite une requête DB par hit)
    timeout_min = session.get('_inactivity_timeout')
    if timeout_min is None:
        with get_db() as db:
            row = db.execute(
                "SELECT inactivity_timeout FROM users WHERE id=?",
                (current_user.id,)
            ).fetchone()
        timeout_min = int(row['inactivity_timeout']) if row and row['inactivity_timeout'] is not None else 30
        session['_inactivity_timeout'] = timeout_min

    if timeout_min == 0:  # désactivé
        session['_last_activity'] = datetime.utcnow().isoformat()
        return

    last = session.get('_last_activity')
    if last:
        try:
            elapsed = (datetime.utcnow() - datetime.fromisoformat(last)).total_seconds()
            if elapsed > timeout_min * 60:
                session['_locked']      = True
                session['_lock_return'] = request.path
                return redirect(url_for('unlock'))
        except (ValueError, TypeError):
            pass

    session['_last_activity'] = datetime.utcnow().isoformat()


@app.route("/unlock", methods=["GET", "POST"])
@login_required
def unlock():
    # Verrouillage manuel depuis le menu (bouton "Verrouiller")
    if request.args.get('force') == '1' and not session.get('_locked'):
        session['_locked']      = True
        session['_lock_return'] = '/'

    if not session.get('_locked'):
        return redirect(url_for('dashboard'))

    error = None
    if request.method == "POST":
        # Bouton déconnexion
        if request.form.get('action') == 'logout':
            uname = current_user.username
            logout_user()
            session.clear()
            log_connexion(uname, "logout", get_real_ip())
            return redirect(url_for('login'))

        password = request.form.get("password", "")
        with get_db() as db:
            row = db.execute("SELECT * FROM users WHERE id=?",
                             (current_user.id,)).fetchone()
        if row and verify_pw(password, row["password"]):
            session.pop('_locked', None)
            session['_last_activity'] = datetime.utcnow().isoformat()
            return redirect(session.pop('_lock_return', '/'))
        error = "Mot de passe incorrect."

    return render_template("lock.html", error=error, username=current_user.username)


@app.route("/api/users/<int:user_id>/email", methods=["PATCH"])
@login_required
def api_update_email(user_id):
    if current_user.id != user_id:
        return jsonify({"error": "Accès refusé"}), 403
    data  = request.json or {}
    email = data.get("email", "").strip().lower()
    # Validation basique
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Adresse email invalide"}), 400
    token = secrets.token_urlsafe(32) if email else None
    with get_db() as db:
        db.execute(
            "UPDATE users SET email=?, email_verified=0, email_verify_token=? WHERE id=?",
            (email or None, token, user_id)
        )
        db.commit()
    if email and token:
        if not EMAIL_CONFIGURED:
            return jsonify({"ok": True, "verified": False,
                            "warning": "Email sauvegardé. Email non configuré — ajoutez BREVO_API_KEY."})
        sent, smtp_err = send_verification_email(email, current_user.username, token)
        if not sent:
            return jsonify({"ok": True, "verified": False,
                            "warning": f"Email sauvegardé mais l'envoi a échoué : {smtp_err}"})
    return jsonify({"ok": True, "verified": False,
                    "msg": "Un email de vérification a été envoyé." if email else "Email supprimé."})


@app.route("/verify-email/<token>")
@login_required
def verify_email(token):
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM users WHERE email_verify_token=? AND id=?",
            (token, current_user.id)
        ).fetchone()
        if not row:
            return render_template("404.html"), 404
        db.execute(
            "UPDATE users SET email_verified=1, email_verify_token=NULL WHERE id=?",
            (current_user.id,)
        )
        db.commit()
    return redirect(url_for("page_profil") + "?email_verified=1")


@app.route("/api/users/<int:user_id>/inactivity_timeout", methods=["PATCH"])
@login_required
def api_inactivity_timeout(user_id):
    if current_user.id != user_id:
        return jsonify({"error": "Non autorisé"}), 403
    data    = request.json or {}
    timeout = data.get("timeout")
    if timeout not in (0, 1, 2, 5, 10, 15, 30, 60, 120):
        return jsonify({"error": "Valeur invalide"}), 400
    with get_db() as db:
        db.execute("UPDATE users SET inactivity_timeout=? WHERE id=?",
                   (timeout, user_id))
        db.commit()
    session['_inactivity_timeout'] = timeout
    session['_last_activity']      = datetime.utcnow().isoformat()
    return jsonify({"ok": True, "timeout": timeout})


@app.route("/logout")
@login_required
def logout():
    log_connexion(current_user.username, "logout", get_real_ip())
    logout_user()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────
#  ROUTES INTERFACE — dynamiques
# ─────────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    f_projet     = request.args.get("projet", "")
    f_date_debut = request.args.get("date_debut", "")
    f_date_fin   = request.args.get("date_fin", "")

    with get_db() as db:
        nb_animaux  = db.execute("SELECT COUNT(*) FROM animaux").fetchone()[0]
        nb_acq      = db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0]
        nb_doublons = db.execute("SELECT COUNT(*) FROM pipeline_logs WHERE statut='DUPLICATE_SKIPPED'").fetchone()[0]
        projets_raw    = db.execute(
            "SELECT * FROM projets WHERE COALESCE(statut,'actif')='actif' ORDER BY nom"
        ).fetchall()
        acq_par_projet = db.execute("SELECT projet, COUNT(*) as n FROM acquisitions GROUP BY projet").fetchall()
        statuts_raw    = db.execute(
            "SELECT projet, statut, COUNT(*) as n FROM animaux GROUP BY projet, statut"
        ).fetchall()

    acq_map    = {r["projet"]: r["n"] for r in acq_par_projet}
    statut_map = {}
    for s in statuts_raw:
        statut_map.setdefault(s["projet"], {})[s["statut"]] = s["n"]

    today = datetime.now().strftime("%Y-%m-%d")
    # Filtrer les projets selon les droits utilisateur (projets restreints)
    projets_raw = [p for p in projets_raw if user_can_view_projet(current_user, p["nom"])]

    projets = []
    for p in projets_raw:
        if f_projet and p["nom"] != f_projet:
            continue
        debut = p["date_debut"] or ""
        fin   = p["date_fin_prevue"] or ""
        if f_date_debut and debut and debut < f_date_debut:
            continue
        if f_date_fin and fin and fin > f_date_fin:
            continue
        seq     = p["seq_par_animal"] or 3
        override = p["acq_prevues_override"]
        prevues = override if override else p["nb_animaux_prevus"] * seq
        faites  = acq_map.get(p["nom"], 0)
        pct     = round(faites / prevues * 100) if prevues else 0
        sm      = statut_map.get(p["nom"], {})
        retard  = bool(fin and fin < today and pct < 100)
        projets.append({
            "nom": p["nom"], "resp": p["resp"],
            "nb_prevus": p["nb_animaux_prevus"],
            "seq_par_animal": seq,
            "prevues": prevues, "faites": faites, "pct": pct,
            "couleur": "teal" if pct >= 75 else ("amber" if pct >= 40 else "red"),
            "nb_ok":      sm.get("ok", 0),
            "nb_attente": sm.get("en_attente", 0),
            "nb_cours":   sm.get("en_cours", 0),
            "nb_refaire": sm.get("a_refaire", 0),
            "date_debut": debut,
            "date_fin_prevue": fin,
            "retard": retard,
            "acq_prevues_override": override,
        })

    return render_template("dashboard.html",
        nb_animaux=nb_animaux, nb_acq=nb_acq, nb_doublons=nb_doublons,
        nas_to=11.2, nas_max=16, projets=projets,
        projets_all=[p["nom"] for p in projets_raw],
        f_projet=f_projet, f_date_debut=f_date_debut, f_date_fin=f_date_fin,
        updated_at=datetime.now().strftime("%Y-%m-%d à %Hh%M"))

@app.route("/animaux")
@login_required
def page_animaux():
    filtre_projet = request.args.get("projet", "")
    filtre_statut = request.args.get("statut", "")
    with get_db() as db:
        q, params = "SELECT * FROM animaux WHERE 1=1", []
        if filtre_projet: q += " AND projet=?"; params.append(filtre_projet)
        if filtre_statut: q += " AND statut=?"; params.append(filtre_statut)
        animaux = db.execute(q + " ORDER BY projet, animal_id", params).fetchall()
        projets = db.execute("SELECT nom FROM projets ORDER BY nom").fetchall()
        total   = db.execute("SELECT COUNT(*) FROM animaux").fetchone()[0]

    # Filtrer selon les droits par projet
    animaux = [a for a in animaux if user_can_view_projet(current_user, a["projet"])]
    projets = [p for p in projets if user_can_view_projet(current_user, p["nom"])]

    return render_template("animaux.html",
        animaux=[dict(a) for a in animaux], projets=[p["nom"] for p in projets],
        total=len(animaux), filtre_projet=filtre_projet, filtre_statut=filtre_statut)

@app.route("/projets")
@login_required
def page_projets():
    return redirect("/")


@app.route("/archive")
@login_required
def page_archive():
    with get_db() as db:
        projets_raw    = db.execute(
            "SELECT * FROM projets WHERE statut='terminé' ORDER BY nom"
        ).fetchall()
        acq_par_projet = db.execute("SELECT projet, COUNT(*) as n FROM acquisitions GROUP BY projet").fetchall()
        statuts        = db.execute("SELECT projet, statut, COUNT(*) as n FROM animaux GROUP BY projet, statut").fetchall()
    acq_map    = {r["projet"]: r["n"] for r in acq_par_projet}
    statut_map = {}
    for s in statuts:
        statut_map.setdefault(s["projet"], {})[s["statut"]] = s["n"]
    projets = []
    for p in projets_raw:
        seq     = p["seq_par_animal"] or 3
        prevues = p["nb_animaux_prevus"] * seq
        faites  = acq_map.get(p["nom"], 0)
        pct     = round(faites / prevues * 100) if prevues else 0
        sm      = statut_map.get(p["nom"], {})
        projets.append({"nom": p["nom"], "resp": p["resp"],
                        "nb_prevus": p["nb_animaux_prevus"],
                        "seq_par_animal": seq,
                        "prevues": prevues, "faites": faites, "pct": pct,
                        "nb_ok":      sm.get("ok", 0),
                        "nb_attente": sm.get("en_attente", 0),
                        "nb_cours":   sm.get("en_cours", 0),
                        "nb_refaire": sm.get("a_refaire", 0)})
    return render_template("archive.html", projets=projets)


@app.route("/api/projets/<nom>/dates", methods=["PATCH"])
@login_required
def api_projets_dates(nom):
    if not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Seul un admin ou un responsable peut modifier ce projet"}), 403
    data = request.json or {}
    updates, params = [], []
    for field in ("date_debut", "date_fin_prevue"):
        if field in data:
            val = (data[field] or "").strip()
            if val and not re.match(r"^\d{4}-\d{2}-\d{2}$", val):
                return jsonify({"error": "Format date invalide (AAAA-MM-JJ)"}), 400
            updates.append(f"{field}=?")
            params.append(val or None)
    if not updates:
        return jsonify({"error": "Aucune date fournie"}), 400
    params.append(nom)
    with get_db() as db:
        db.execute(f"UPDATE projets SET {','.join(updates)} WHERE nom=?", params)
        db.commit()
        p = db.execute("SELECT date_debut, date_fin_prevue FROM projets WHERE nom=?", (nom,)).fetchone()
    return jsonify({"ok": True, "nom": nom,
                    "date_debut": p["date_debut"] or "", "date_fin_prevue": p["date_fin_prevue"] or ""})


@app.route("/api/projets/<nom>/acq-prevues", methods=["PATCH"])
@login_required
def api_projets_acq_prevues(nom):
    if not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Seul un admin ou un responsable peut modifier ce projet"}), 403
    data = request.json or {}
    val  = data.get("acq_prevues_override")
    if val is not None:
        try:
            val = int(val)
            if val < 0:
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "Nombre invalide"}), 400
    with get_db() as db:
        p = db.execute("SELECT * FROM projets WHERE nom=?", (nom,)).fetchone()
        if not p:
            return jsonify({"error": "Projet introuvable"}), 404
        db.execute("UPDATE projets SET acq_prevues_override=? WHERE nom=?", (val, nom))
        db.commit()
        seq = p["seq_par_animal"] or 3
        prevues = val if val else p["nb_animaux_prevus"] * seq
        faites = db.execute("SELECT COUNT(*) FROM acquisitions WHERE projet=?", (nom,)).fetchone()[0]
        pct = round(faites / prevues * 100) if prevues else 0
    return jsonify({"ok": True, "nom": nom, "prevues": prevues, "faites": faites, "pct": pct})


@app.route("/api/projets/<nom>/ethique", methods=["PATCH"])
@login_required
def api_projets_ethique(nom):
    if not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Seul un admin ou un responsable peut modifier ce projet"}), 403
    data  = request.json or {}
    proto = data.get("protocole_ethique", "").strip()
    with get_db() as db:
        updated = db.execute(
            "UPDATE projets SET protocole_ethique=? WHERE nom=?", (proto or None, nom)
        ).rowcount
        db.commit()
    if not updated:
        return jsonify({"error": "Projet introuvable"}), 404
    return jsonify({"ok": True, "protocole_ethique": proto})


@app.route("/api/projets/<nom>/statut", methods=["PATCH"])
@login_required
def api_projets_statut(nom):
    if not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Seul un admin ou un responsable peut modifier ce projet"}), 403
    data   = request.json or {}
    statut = data.get("statut", "").strip()
    if statut not in ("actif", "terminé"):
        return jsonify({"error": "Statut invalide (actif ou terminé)"}), 400
    with get_db() as db:
        updated = db.execute(
            "UPDATE projets SET statut=? WHERE nom=?", (statut, nom)
        ).rowcount
        db.commit()
    if not updated:
        return jsonify({"error": "Projet introuvable"}), 404
    emit_event("projet_updated", {"nom": nom, "statut": statut, "par": current_user.username})
    return jsonify({"ok": True, "nom": nom, "statut": statut})


@app.route("/import")
@login_required
@role_required("admin", "operateur")
def page_import():
    with get_db() as db:
        projets     = db.execute("SELECT nom FROM projets ORDER BY nom").fetchall()
        last_import = db.execute("SELECT COUNT(*) as n, statut FROM pipeline_logs GROUP BY statut").fetchall()
        last_ts     = db.execute("SELECT timestamp FROM pipeline_logs ORDER BY timestamp DESC LIMIT 1").fetchone()
    stats = {r["statut"]: r["n"] for r in last_import}
    return render_template("import.html",
        projets=[p["nom"] for p in projets],
        nb_importes=stats.get("IMPORTED", 0),
        nb_doublons=stats.get("DUPLICATE_SKIPPED", 0),
        nb_erreurs=stats.get("ERROR", 0),
        last_ts=last_ts["timestamp"][:16] if last_ts else "—",
        today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/logs")
@login_required
@role_required("admin", "operateur")
def page_logs():
    try: page = max(1, int(request.args.get("page", 1)))
    except ValueError: page = 1
    per_page = 50
    offset   = (page - 1) * per_page

    with get_db() as db:
        total      = db.execute("SELECT COUNT(*) FROM pipeline_logs").fetchone()[0]
        logs       = db.execute(
            "SELECT * FROM pipeline_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ).fetchall()
        nb_erreurs = db.execute("SELECT COUNT(*) FROM pipeline_logs WHERE statut='ERROR'").fetchone()[0]
        last_ts    = db.execute("SELECT timestamp FROM pipeline_logs ORDER BY timestamp DESC LIMIT 1").fetchone()

    nb_pages = max(1, (total + per_page - 1) // per_page)
    return render_template("logs.html",
        logs=[dict(l) for l in logs], nb_erreurs=nb_erreurs,
        last_ts=last_ts["timestamp"][:16] if last_ts else "—",
        page=page, nb_pages=nb_pages, per_page=per_page, total=total)

@app.route("/users")
@login_required
@role_required("admin")
def page_users():
    with get_db() as db:
        users = db.execute("SELECT id, username, role FROM users ORDER BY role, username").fetchall()
        total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return render_template("users.html", users=[dict(u) for u in users], total=total)


# ─────────────────────────────────────────────────
#  API — DASHBOARD
# ─────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    with get_db() as db:
        nb_animaux     = db.execute("SELECT COUNT(*) FROM animaux").fetchone()[0]
        nb_acq         = db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0]
        nb_doublons    = db.execute("SELECT COUNT(*) FROM pipeline_logs WHERE statut='DUPLICATE_SKIPPED'").fetchone()[0]
        projets        = db.execute("SELECT nom, resp, nb_animaux_prevus FROM projets").fetchall()
        acq_par_projet = db.execute(
            "SELECT projet, COUNT(*) as n FROM acquisitions GROUP BY projet"
        ).fetchall()

    acq_map = {r["projet"]: r["n"] for r in acq_par_projet}

    return jsonify({
        "nb_animaux":  nb_animaux,
        "nb_acquisitions": nb_acq,
        "nb_doublons": nb_doublons,
        "nas_go":      11264,   # à remplacer par shutil.disk_usage() réel
        "projets": [
            {
                "nom":     p["nom"],
                "resp":    p["resp"],
                "prevues": p["nb_animaux_prevus"] * 3,
                "faites":  acq_map.get(p["nom"], 0)
            }
            for p in projets
        ]
    })


@app.route("/api/charts/dashboard")
@login_required
def api_charts_dashboard():
    """
    Données agrégées pour les graphes du dashboard :
      - acquisitions par mois (12 derniers mois)
      - acquisitions par projet (visibles seulement)
      - répartition statuts animaux
    """
    today      = datetime.now().date()
    months: list[tuple[str, str]] = []
    # Génère les 12 derniers mois (yyyy-mm) + label court
    for i in range(11, -1, -1):
        y = today.year
        m = today.month - i
        while m <= 0:
            m += 12
            y -= 1
        ym       = f"{y:04d}-{m:02d}"
        label_fr = ["Jan","Fév","Mar","Avr","Mai","Jun","Jul","Aoû","Sep","Oct","Nov","Déc"][m-1]
        if i >= 9:
            label_fr = f"{label_fr} {str(y)[-2:]}"
        months.append((ym, label_fr))

    with get_db() as db:
        rows_mois = db.execute(
            """SELECT substr(date_acq, 1, 7) AS ym, projet, COUNT(*) AS n
               FROM acquisitions
               WHERE date_acq >= ?
               GROUP BY ym, projet""",
            (months[0][0] + "-01",)
        ).fetchall()

        statuts_rows = db.execute(
            "SELECT projet, statut, COUNT(*) AS n FROM animaux GROUP BY projet, statut"
        ).fetchall()

        projets_rows = db.execute("SELECT nom FROM projets ORDER BY nom").fetchall()

    # ── Filtrage selon droits par projet ───────────────────────────────────
    projets_visibles = [
        p["nom"] for p in projets_rows
        if user_can_view_projet(current_user, p["nom"])
    ]

    # ── 1) Acquisitions par mois (somme tous projets visibles) ─────────────
    by_month = {ym: 0 for ym, _ in months}
    for r in rows_mois:
        if r["projet"] in projets_visibles:
            by_month[r["ym"]] = by_month.get(r["ym"], 0) + r["n"]
    acq_par_mois = {
        "labels": [lbl for _, lbl in months],
        "data":   [by_month[ym] for ym, _ in months],
    }

    # ── 2) Acquisitions par projet (total) ─────────────────────────────────
    by_projet: dict[str, int] = {p: 0 for p in projets_visibles}
    for r in rows_mois:
        if r["projet"] in projets_visibles:
            by_projet[r["projet"]] += r["n"]
    # Top 8, le reste dans "autres"
    sorted_projets = sorted(by_projet.items(), key=lambda x: -x[1])
    top = sorted_projets[:8]
    rest_sum = sum(n for _, n in sorted_projets[8:])
    acq_par_projet = {
        "labels": [n for n, _ in top] + (["autres"] if rest_sum else []),
        "data":   [n for _, n in top] + ([rest_sum]  if rest_sum else []),
    }

    # ── 3) Répartition statuts animaux ─────────────────────────────────────
    statuts_total: dict[str, int] = {"ok": 0, "en_cours": 0, "en_attente": 0, "a_refaire": 0}
    for r in statuts_rows:
        if r["projet"] in projets_visibles and r["statut"] in statuts_total:
            statuts_total[r["statut"]] += r["n"]
    statuts_animaux = {
        "labels": ["OK", "En cours", "En attente", "À refaire"],
        "data":   [statuts_total["ok"], statuts_total["en_cours"],
                   statuts_total["en_attente"], statuts_total["a_refaire"]],
    }

    return jsonify({
        "acq_par_mois":    acq_par_mois,
        "acq_par_projet":  acq_par_projet,
        "statuts_animaux": statuts_animaux,
    })


# ─────────────────────────────────────────────────
#  API — PROJETS
# ─────────────────────────────────────────────────

@app.route("/api/projets", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_add_projet():
    data = request.json or {}
    nom            = data.get("nom", "").strip()
    resp           = data.get("resp", "").strip()
    nb_animaux     = data.get("nb_animaux", 0)
    seq_par_animal = max(1, min(10, int(data.get("seq_par_animal", 3) or 3)))

    if not nom:
        return jsonify({"error": "Nom du projet requis"}), 400

    nom_clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", nom).strip("_").lower()
    if not nom_clean:
        return jsonify({"error": "Nom invalide après nettoyage"}), 400

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO projets (nom, resp, nb_animaux_prevus, seq_par_animal) VALUES (?,?,?,?)",
                (nom_clean, resp, int(nb_animaux), seq_par_animal)
            )
            db.commit()
        (NAS_ROOT / nom_clean).mkdir(parents=True, exist_ok=True)
        emit_event("projet_new", {"nom": nom_clean, "resp": resp, "par": current_user.username})
        return jsonify({"ok": True, "nom": nom_clean, "resp": resp, "seq_par_animal": seq_par_animal}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": f"Le projet « {nom_clean} » existe déjà"}), 409

@app.route("/api/projets/<nom>", methods=["DELETE"])
@login_required
@role_required("admin")
def api_delete_projet(nom):
    with get_db() as db:
        row = db.execute("SELECT * FROM projets WHERE nom=?", (nom,)).fetchone()
        if not row:
            return jsonify({"error": "Projet introuvable"}), 404
        nb_acq = db.execute("SELECT COUNT(*) FROM acquisitions WHERE projet=?", (nom,)).fetchone()[0]
        if nb_acq > 0:
            return jsonify({"error": f"Impossible : {nb_acq} acquisition(s) liée(s) à ce projet"}), 409
        db.execute("DELETE FROM projets WHERE nom=?", (nom,))
        db.execute("DELETE FROM projet_membres WHERE projet=?", (nom,))
        db.commit()
    return jsonify({"ok": True, "deleted": nom})


# ─────────────────────────────────────────────────
#  API — MEMBRES DE PROJET (droits par projet)
# ─────────────────────────────────────────────────

@app.route("/api/projets/<nom>/membres")
@login_required
def api_projet_membres(nom):
    """Liste les membres d'un projet (accessible à quiconque peut voir le projet)."""
    if not user_can_view_projet(current_user, nom):
        return jsonify({"error": "Accès refusé à ce projet"}), 403
    membres = projet_membres(nom)
    return jsonify({
        "projet":     nom,
        "restricted": projet_is_restricted(nom),
        "membres":    [dict(m) for m in membres],
    })


@app.route("/api/projets/<nom>/membres", methods=["POST"])
@login_required
def api_projet_add_membre(nom):
    if not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Seul un responsable ou un admin peut gérer les membres"}), 403
    d = request.json or {}
    username    = (d.get("username") or "").strip()
    role_projet = (d.get("role_projet") or "membre").strip()
    if not username:
        return jsonify({"error": "username requis"}), 400
    if role_projet not in ("responsable", "membre", "lecteur"):
        return jsonify({"error": "Rôle invalide"}), 400

    with get_db() as db:
        user = db.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            return jsonify({"error": "Utilisateur inconnu"}), 404
        try:
            db.execute(
                """INSERT INTO projet_membres (projet, user_id, role_projet, added_by, added_at)
                   VALUES (?,?,?,?,?)""",
                (nom, user["id"], role_projet, current_user.username, datetime.now().isoformat())
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Cet utilisateur est déjà membre"}), 409

    # Notification au membre ajouté
    try:
        notify(
            user_id = user["id"],
            type_   = "membre_ajoute",
            titre   = f"Ajouté au projet « {nom} »",
            corps   = (f"Vous avez été ajouté comme <strong>{role_projet}</strong> "
                       f"au projet « {nom} » par {current_user.username}."),
            url     = f"/projet/{nom}",
            projet  = nom,
        )
    except Exception as exc:
        print(f"[notify] échec notification ajout membre : {exc}", flush=True)

    return jsonify({"ok": True})


@app.route("/api/projets/<nom>/membres/<int:user_id>", methods=["PATCH"])
@login_required
def api_projet_update_membre(nom, user_id):
    if not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Seul un responsable ou un admin peut gérer les membres"}), 403
    d = request.json or {}
    role_projet = (d.get("role_projet") or "").strip()
    if role_projet not in ("responsable", "membre", "lecteur"):
        return jsonify({"error": "Rôle invalide"}), 400
    with get_db() as db:
        db.execute(
            "UPDATE projet_membres SET role_projet=? WHERE projet=? AND user_id=?",
            (role_projet, nom, user_id)
        )
        db.commit()
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────
#  API — JOURNAL DE PROJET (CR de réunions, notes)
# ─────────────────────────────────────────────────

@app.route("/api/projets/<nom>/notes")
@login_required
def api_projet_notes_list(nom):
    if not user_can_view_projet(current_user, nom):
        return jsonify({"error": "Accès refusé à ce projet"}), 403
    with get_db() as db:
        rows = db.execute(
            """SELECT * FROM projet_notes WHERE projet=?
               ORDER BY epinglee DESC, created_at DESC""",
            (nom,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/projets/<nom>/notes", methods=["POST"])
@login_required
def api_projet_notes_create(nom):
    if not user_can_edit_projet(current_user, nom):
        return jsonify({"error": "Droits insuffisants sur ce projet"}), 403
    d = request.json or {}
    titre   = (d.get("titre") or "").strip()
    contenu = (d.get("contenu") or "").strip()
    type_   = (d.get("type") or "note").strip()
    if not contenu:
        return jsonify({"error": "Contenu requis"}), 400
    if type_ not in ("note", "reunion", "compte_rendu", "decision"):
        type_ = "note"
    if len(contenu) > 10000:
        return jsonify({"error": "Contenu trop long (max 10 000 caractères)"}), 400
    if titre and len(titre) > 200:
        return jsonify({"error": "Titre trop long (max 200 caractères)"}), 400

    now_iso = datetime.now().isoformat()
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO projet_notes (projet, auteur, titre, contenu, type, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (nom, current_user.username, titre or None, contenu, type_, now_iso)
        )
        new_id = cur.lastrowid
        db.commit()

    # Notifie les autres membres de la nouvelle note
    try:
        type_labels = {"note":"Note","reunion":"Réunion","compte_rendu":"Compte-rendu","decision":"Décision"}
        notify_projet_members(
            projet = nom,
            type_  = "note_projet",
            titre  = f"Nouvelle {type_labels.get(type_, 'note').lower()} sur « {nom} »",
            corps  = (titre or contenu[:120] + ('…' if len(contenu) > 120 else '')) +
                     f"<br><small style='color:#999'>par {current_user.username}</small>",
            url    = f"/projet/{nom}",
            exclude_user_id = current_user.id,
        )
    except Exception as exc:
        print(f"[notify] échec notif nouvelle note : {exc}", flush=True)

    return jsonify({"ok": True, "id": new_id}), 201


@app.route("/api/projets/<nom>/notes/<int:note_id>", methods=["PATCH"])
@login_required
def api_projet_notes_update(nom, note_id):
    with get_db() as db:
        note = db.execute(
            "SELECT * FROM projet_notes WHERE id=? AND projet=?", (note_id, nom)
        ).fetchone()
    if not note:
        return jsonify({"error": "Note introuvable"}), 404

    is_author = note["auteur"] == current_user.username
    can_pin   = user_can_manage_projet(current_user, nom)
    can_edit  = is_author or current_user.role == "admin"

    d = request.json or {}
    updates: dict = {}

    if "titre" in d and can_edit:
        v = (d["titre"] or "").strip() or None
        if v and len(v) > 200:
            return jsonify({"error": "Titre trop long"}), 400
        updates["titre"] = v
    if "contenu" in d and can_edit:
        v = (d["contenu"] or "").strip()
        if not v: return jsonify({"error": "Contenu requis"}), 400
        if len(v) > 10000: return jsonify({"error": "Contenu trop long"}), 400
        updates["contenu"] = v
    if "type" in d and can_edit:
        v = (d["type"] or "note").strip()
        if v not in ("note", "reunion", "compte_rendu", "decision"):
            return jsonify({"error": "Type invalide"}), 400
        updates["type"] = v
    if "epinglee" in d and can_pin:
        updates["epinglee"] = 1 if d["epinglee"] else 0

    if not updates:
        return jsonify({"error": "Aucun champ à modifier ou droits insuffisants"}), 403

    set_clause = ", ".join(f"{k}=?" for k in updates)
    params     = list(updates.values()) + [datetime.now().isoformat(), note_id, nom]
    with get_db() as db:
        db.execute(
            f"UPDATE projet_notes SET {set_clause}, updated_at=? WHERE id=? AND projet=?",
            params
        )
        db.commit()
    return jsonify({"ok": True})


@app.route("/api/projets/<nom>/notes/<int:note_id>", methods=["DELETE"])
@login_required
def api_projet_notes_delete(nom, note_id):
    with get_db() as db:
        note = db.execute(
            "SELECT auteur FROM projet_notes WHERE id=? AND projet=?", (note_id, nom)
        ).fetchone()
    if not note:
        return jsonify({"error": "Note introuvable"}), 404
    if note["auteur"] != current_user.username and current_user.role != "admin" \
       and not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Droits insuffisants"}), 403
    with get_db() as db:
        db.execute("DELETE FROM projet_notes WHERE id=? AND projet=?", (note_id, nom))
        db.commit()
    return jsonify({"ok": True})


@app.route("/api/projets/<nom>/membres/<int:user_id>", methods=["DELETE"])
@login_required
def api_projet_remove_membre(nom, user_id):
    if not user_can_manage_projet(current_user, nom):
        return jsonify({"error": "Seul un responsable ou un admin peut gérer les membres"}), 403
    with get_db() as db:
        # Empêche de retirer le dernier responsable
        nb_resp = db.execute(
            "SELECT COUNT(*) FROM projet_membres WHERE projet=? AND role_projet='responsable'", (nom,)
        ).fetchone()[0]
        me = db.execute(
            "SELECT role_projet FROM projet_membres WHERE projet=? AND user_id=?", (nom, user_id)
        ).fetchone()
        if me and me["role_projet"] == "responsable" and nb_resp <= 1 and current_user.role != "admin":
            return jsonify({"error": "Impossible : dernier responsable du projet"}), 409
        db.execute("DELETE FROM projet_membres WHERE projet=? AND user_id=?", (nom, user_id))
        db.commit()
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────
#  API — ANIMAUX
# ─────────────────────────────────────────────────

@app.route("/api/animaux")
@login_required
def api_animaux():
    projet = request.args.get("projet")
    statut = request.args.get("statut")
    if projet and not user_can_view_projet(current_user, projet):
        return jsonify({"error": "Accès refusé à ce projet"}), 403
    q = "SELECT * FROM animaux WHERE 1=1"
    params = []
    if projet:
        q += " AND projet=?"; params.append(projet)
    if statut:
        q += " AND statut=?"; params.append(statut)
    with get_db() as db:
        rows = db.execute(q, params).fetchall()
    # Filtre les projets restreints quand pas de paramètre projet
    rows = [r for r in rows if user_can_view_projet(current_user, r["projet"])]
    return jsonify([dict(r) for r in rows])

@app.route("/api/animaux/<animal_id>")
@login_required
def api_animal_detail(animal_id):
    with get_db() as db:
        animal = db.execute("SELECT * FROM animaux WHERE animal_id=?", (animal_id,)).fetchone()
        acqs   = db.execute("SELECT * FROM acquisitions WHERE animal_id=?", (animal_id,)).fetchall()
    if not animal:
        return jsonify({"error": "Animal introuvable"}), 404
    if not user_can_view_projet(current_user, animal["projet"]):
        return jsonify({"error": "Accès refusé à ce projet"}), 403
    # Garde seulement les acquisitions accessibles (sécurité au cas où animal_id existe sur plusieurs projets)
    acqs = [a for a in acqs if user_can_view_projet(current_user, a["projet"])]
    return jsonify({"animal": dict(animal), "acquisitions": [dict(a) for a in acqs]})


# ─────────────────────────────────────────────────
#  PLANIFICATION — détection de conflits de créneaux
# ─────────────────────────────────────────────────

def _hhmm_to_min(s: str) -> int:
    """'HH:MM' → minutes depuis minuit. Retourne -1 si invalide."""
    try:
        h, m = s.split(":")
        return int(h) * 60 + int(m)
    except (ValueError, AttributeError):
        return -1

def _min_to_hhmm(m: int) -> str:
    return f"{m//60:02d}:{m%60:02d}"

def detect_conflicts(date_acq: str, heure_debut: str, duree_min: int,
                     exclude_id: int | None = None) -> list[dict]:
    """
    Retourne la liste des acquisitions qui chevauchent le créneau demandé
    (même jour, plages horaires en intersection).
    """
    start = _hhmm_to_min(heure_debut)
    if start < 0 or not duree_min:
        return []
    end = start + int(duree_min)

    with get_db() as db:
        rows = db.execute(
            """SELECT id, animal_id, projet, sequence, heure_debut, duree_min,
                      importé_par, statut
               FROM acquisitions
               WHERE date_acq = ?
                 AND heure_debut IS NOT NULL
                 AND duree_min IS NOT NULL""",
            (date_acq,)
        ).fetchall()

    conflicts = []
    for r in rows:
        if exclude_id is not None and r["id"] == exclude_id:
            continue
        r_start = _hhmm_to_min(r["heure_debut"])
        r_end   = r_start + int(r["duree_min"])
        # Chevauchement si [start, end) ∩ [r_start, r_end) non vide
        if start < r_end and r_start < end:
            d = dict(r)
            d["heure_fin"] = _min_to_hhmm(r_end)
            conflicts.append(d)
    return conflicts


@app.route("/api/planification/check", methods=["POST"])
@login_required
def api_planification_check():
    """Vérifie si un créneau est disponible. Retourne la liste des conflits."""
    data = request.json or {}
    date_acq    = data.get("date_acq")
    heure_debut = data.get("heure_debut")
    duree_min   = data.get("duree_min")
    exclude_id  = data.get("exclude_id")

    if not date_acq or not heure_debut or not duree_min:
        return jsonify({"error": "Champs requis : date_acq, heure_debut, duree_min"}), 400
    try:
        duree_min = int(duree_min)
    except (ValueError, TypeError):
        return jsonify({"error": "Durée invalide"}), 400

    conflicts = detect_conflicts(date_acq, heure_debut, duree_min,
                                 exclude_id=int(exclude_id) if exclude_id else None)

    # Propositions : 3 créneaux libres après la dernière acquisition du jour
    suggestions = []
    if conflicts:
        last_end = max(_hhmm_to_min(c["heure_debut"]) + int(c["duree_min"]) for c in conflicts)
        for offset in [0, 30, 60]:
            cand = last_end + offset
            if cand + duree_min <= 22 * 60:  # avant 22h
                suggestions.append({
                    "heure_debut": _min_to_hhmm(cand),
                    "heure_fin":   _min_to_hhmm(cand + duree_min),
                })

    return jsonify({
        "ok": len(conflicts) == 0,
        "conflicts": conflicts,
        "suggestions": suggestions,
    })


def _parse_frequence(freq: str, custom_days: int | None = None) -> timedelta | None:
    """
    Convertit un libellé de fréquence en timedelta.
    Valeurs acceptées : 24h, 48h, 72h, 1sem, 2sem, 1mois, custom (avec custom_days)
    """
    if freq == "24h":   return timedelta(hours=24)
    if freq == "48h":   return timedelta(hours=48)
    if freq == "72h":   return timedelta(hours=72)
    if freq == "1sem":  return timedelta(weeks=1)
    if freq == "2sem":  return timedelta(weeks=2)
    if freq == "1mois": return timedelta(days=30)
    if freq == "custom" and custom_days and 1 <= custom_days <= 365:
        return timedelta(days=int(custom_days))
    return None


@app.route("/api/planification/serie/preview", methods=["POST"])
@login_required
def api_planification_serie_preview():
    """
    Génère un aperçu d'une série d'acquisitions récurrentes.
    Retourne la liste des dates calculées + détection des conflits par créneau.
    N'écrit RIEN en base.
    """
    d = request.json or {}
    required = ("projet", "animal_id", "sequence", "date_debut",
                "heure_debut", "duree_min", "frequence", "nb_repetitions")
    if not all(k in d for k in required):
        return jsonify({"error": f"Champs requis : {', '.join(required)}"}), 400

    try:
        date_debut = datetime.strptime(d["date_debut"], "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "Date invalide (YYYY-MM-DD)"}), 400

    if not re.match(r"^\d{2}:\d{2}$", d["heure_debut"]):
        return jsonify({"error": "Heure invalide (HH:MM)"}), 400

    try:
        duree_min = int(d["duree_min"])
        nb        = int(d["nb_repetitions"])
        if not (1 <= duree_min <= 480): raise ValueError
        if not (1 <= nb <= 50):         raise ValueError("nb_repetitions doit être entre 1 et 50")
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Durée ou nombre invalide : {e}"}), 400

    delta = _parse_frequence(d["frequence"], d.get("custom_days"))
    if delta is None:
        return jsonify({"error": "Fréquence invalide"}), 400

    # Génère les dates
    items = []
    current = datetime.combine(date_debut, datetime.min.time())
    for i in range(nb):
        date_str = current.strftime("%Y-%m-%d")
        conflicts = detect_conflicts(date_str, d["heure_debut"], duree_min)
        items.append({
            "n":           i + 1,
            "date_acq":    date_str,
            "heure_debut": d["heure_debut"],
            "conflicts":   [{"animal_id": c["animal_id"], "sequence": c["sequence"],
                             "heure_debut": c["heure_debut"], "user": c["importé_par"]}
                            for c in conflicts],
        })
        current += delta

    nb_libres   = sum(1 for it in items if not it["conflicts"])
    nb_conflits = nb - nb_libres
    return jsonify({
        "items":       items,
        "nb_total":    nb,
        "nb_libres":   nb_libres,
        "nb_conflits": nb_conflits,
        "duree_min":   duree_min,
    })


@app.route("/api/planification/serie/confirm", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_planification_serie_confirm():
    """
    Confirme la création d'une série d'acquisitions planifiées (statut 'en_attente').
    Skip automatique des créneaux en conflit sauf si force=true.
    Retourne les IDs créés + ceux ignorés.
    """
    d = request.json or {}
    required = ("projet", "animal_id", "sequence", "items")
    if not all(k in d for k in required):
        return jsonify({"error": f"Champs requis : {', '.join(required)}"}), 400

    if not user_can_edit_projet(current_user, d["projet"]):
        return jsonify({"error": "Vous n'avez pas les droits d'édition sur ce projet"}), 403

    force      = bool(d.get("force", False))
    duree_min  = int(d.get("duree_min") or 0) or None
    created    = []
    skipped    = []
    now_iso    = datetime.now().isoformat()

    with get_db() as db:
        for it in d["items"]:
            date_acq    = it.get("date_acq")
            heure_debut = it.get("heure_debut")
            if not date_acq or not heure_debut:
                continue

            # Re-vérification serveur des conflits (la preview pourrait être obsolète)
            conflicts = detect_conflicts(date_acq, heure_debut, duree_min or 30)
            if conflicts and not force:
                skipped.append({"date_acq": date_acq, "heure_debut": heure_debut,
                                "reason": "conflit"})
                continue

            cur = db.execute(
                """INSERT INTO acquisitions
                   (animal_id,projet,sequence,date_acq,heure_debut,duree_min,
                    statut,importé_par,importé_le)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (d["animal_id"], d["projet"], d["sequence"], date_acq,
                 heure_debut, duree_min, "en_attente",
                 current_user.username, now_iso)
            )
            created.append({"id": cur.lastrowid, "date_acq": date_acq,
                            "heure_debut": heure_debut})
        db.commit()

    return jsonify({
        "ok":         True,
        "nb_created": len(created),
        "nb_skipped": len(skipped),
        "created":    created,
        "skipped":    skipped,
    })


@app.route("/api/planification/conflicts")
@login_required
def api_planification_conflicts():
    """
    Retourne tous les conflits actuellement présents en BDD
    (paires d'acquisitions qui se chevauchent).
    """
    with get_db() as db:
        rows = db.execute(
            """SELECT id, animal_id, projet, sequence, date_acq,
                      heure_debut, duree_min, importé_par, statut
               FROM acquisitions
               WHERE heure_debut IS NOT NULL AND duree_min IS NOT NULL
               ORDER BY date_acq, heure_debut"""
        ).fetchall()

    by_date: dict[str, list] = {}
    for r in rows:
        by_date.setdefault(r["date_acq"], []).append(dict(r))

    conflicts = []
    for date_acq, acqs in by_date.items():
        for i in range(len(acqs)):
            a = acqs[i]; a_start = _hhmm_to_min(a["heure_debut"])
            a_end = a_start + int(a["duree_min"])
            for j in range(i + 1, len(acqs)):
                b = acqs[j]; b_start = _hhmm_to_min(b["heure_debut"])
                b_end = b_start + int(b["duree_min"])
                if a_start < b_end and b_start < a_end:
                    conflicts.append({
                        "date_acq": date_acq,
                        "a": a, "b": b,
                    })
    return jsonify({"count": len(conflicts), "conflicts": conflicts})


@app.route("/api/search")
@login_required
def api_search():
    """
    Recherche globale (Cmd+K). Retourne jusqu'à 5 résultats par catégorie :
      - projets (par nom, responsable)
      - animaux (par animal_id, espèce)
      - acquisitions (par sequence, animal_id, projet — filtré par droits)
      - users (admin uniquement)
    Filtre selon les droits par projet.
    """
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"projets": [], "animaux": [], "acquisitions": [], "users": []})

    like = f"%{q.lower()}%"
    out  = {"projets": [], "animaux": [], "acquisitions": [], "users": []}

    with get_db() as db:
        # ── Projets ────────────────────────────────────────────────────────
        rows = db.execute(
            """SELECT nom, resp, statut FROM projets
               WHERE lower(nom) LIKE ? OR lower(COALESCE(resp,'')) LIKE ?
               ORDER BY nom LIMIT 20""",
            (like, like)
        ).fetchall()
        for r in rows:
            if not user_can_view_projet(current_user, r["nom"]):
                continue
            out["projets"].append({
                "nom":   r["nom"], "resp": r["resp"] or "",
                "statut": r["statut"] or "actif",
                "url":   f"/projet/{r['nom']}",
            })
            if len(out["projets"]) >= 5:
                break

        # ── Animaux ────────────────────────────────────────────────────────
        rows = db.execute(
            """SELECT animal_id, espece, projet, statut FROM animaux
               WHERE lower(animal_id) LIKE ? OR lower(COALESCE(espece,'')) LIKE ?
               ORDER BY animal_id LIMIT 30""",
            (like, like)
        ).fetchall()
        for r in rows:
            if not user_can_view_projet(current_user, r["projet"]):
                continue
            out["animaux"].append({
                "animal_id": r["animal_id"], "espece": r["espece"] or "—",
                "projet": r["projet"], "statut": r["statut"],
                "url":    f"/animal/{r['projet']}/{r['animal_id']}",
            })
            if len(out["animaux"]) >= 5:
                break

        # ── Acquisitions ───────────────────────────────────────────────────
        rows = db.execute(
            """SELECT id, animal_id, projet, sequence, date_acq, statut FROM acquisitions
               WHERE lower(COALESCE(sequence,'')) LIKE ?
                  OR lower(animal_id) LIKE ?
                  OR lower(projet) LIKE ?
               ORDER BY date_acq DESC LIMIT 30""",
            (like, like, like)
        ).fetchall()
        for r in rows:
            if not user_can_view_projet(current_user, r["projet"]):
                continue
            out["acquisitions"].append({
                "id": r["id"], "animal_id": r["animal_id"], "projet": r["projet"],
                "sequence": r["sequence"] or "—", "date_acq": r["date_acq"] or "",
                "statut": r["statut"],
                "url":    f"/animal/{r['projet']}/{r['animal_id']}",
            })
            if len(out["acquisitions"]) >= 5:
                break

        # ── Users (admin uniquement) ──────────────────────────────────────
        if current_user.role == "admin":
            rows = db.execute(
                "SELECT id, username, role FROM users WHERE lower(username) LIKE ? "
                "ORDER BY username LIMIT 5",
                (like,)
            ).fetchall()
            for r in rows:
                out["users"].append({
                    "id": r["id"], "username": r["username"], "role": r["role"],
                    "url": "/users",
                })

    return jsonify(out)


@app.route("/api/planification/mes-creneaux")
@login_required
def api_mes_creneaux():
    """
    Prochaines acquisitions accessibles à l'utilisateur courant.
    - Admin : toutes les acquisitions planifiées (en_attente ou en_cours)
    - Autres : seulement celles des projets dont ils sont membres
    - Aujourd'hui et futur uniquement, ordonné par date+heure
    """
    today_iso = datetime.now().strftime("%Y-%m-%d")
    limit     = max(1, min(20, int(request.args.get("limit", 8))))

    with get_db() as db:
        rows = db.execute(
            """SELECT id, animal_id, projet, sequence, date_acq, heure_debut,
                      duree_min, statut, importé_par, poids_g, qualite
               FROM acquisitions
               WHERE date_acq >= ?
                 AND statut IN ('en_attente', 'en_cours')
               ORDER BY date_acq ASC, COALESCE(heure_debut, '99:99') ASC
               LIMIT 200""",
            (today_iso,)
        ).fetchall()

    # Filtrage par droits projet
    creneaux = []
    for r in rows:
        if not user_can_view_projet(current_user, r["projet"]):
            continue
        creneaux.append(dict(r))
        if len(creneaux) >= limit:
            break

    return jsonify({
        "today":     today_iso,
        "creneaux":  creneaux,
        "count":     len(creneaux),
    })


# ─────────────────────────────────────────────────
#  API — ACQUISITIONS
# ─────────────────────────────────────────────────

@app.route("/api/acquisitions")
@login_required
def api_acquisitions():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM acquisitions ORDER BY date_acq DESC LIMIT 50"
        ).fetchall()
    # Filtre selon les droits par projet
    rows = [r for r in rows if user_can_view_projet(current_user, r["projet"])]
    return jsonify([dict(r) for r in rows])

@app.route("/api/acquisitions", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_add_acquisition():
    data = request.json
    required = ["animal_id", "projet", "sequence", "date_acq"]
    if not all(k in data for k in required):
        return jsonify({"error": "Champs manquants"}), 400

    # Vérif des droits d'édition sur le projet ciblé
    if not user_can_edit_projet(current_user, data["projet"]):
        return jsonify({"error": "Vous n'avez pas les droits d'édition sur ce projet"}), 403

    # ── Validation des champs enrichis (poids, qualité, problème, créneau) ───
    poids_g = data.get("poids_g")
    if poids_g is not None:
        try:
            poids_g = float(poids_g)
            if poids_g <= 0 or poids_g > 5000:
                return jsonify({"error": "Poids invalide (0–5000 g)"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Poids doit être un nombre"}), 400

    qualite_valides = {None, "", "excellente", "bonne", "degradee", "inutilisable"}
    qualite = data.get("qualite") or None
    if qualite not in qualite_valides:
        return jsonify({"error": "Qualité invalide"}), 400

    probleme_types = {None, "", "aucun", "positionnement", "artefact", "mouvement", "materiel", "autre"}
    probleme_type = data.get("probleme_type") or None
    if probleme_type not in probleme_types:
        return jsonify({"error": "Type de problème invalide"}), 400

    heure_debut = data.get("heure_debut") or None
    if heure_debut and not re.match(r"^\d{2}:\d{2}$", heure_debut):
        return jsonify({"error": "Heure invalide (format HH:MM)"}), 400

    duree_min = data.get("duree_min")
    if duree_min is not None and duree_min != "":
        try:
            duree_min = int(duree_min)
            if duree_min < 1 or duree_min > 480:
                return jsonify({"error": "Durée invalide (1–480 min)"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Durée doit être un entier"}), 400
    else:
        duree_min = None

    # ── Détection de conflit de créneau (si heure + durée fournies) ──────────
    if heure_debut and duree_min:
        conflicts = detect_conflicts(data["date_acq"], heure_debut, duree_min)
        if conflicts and not data.get("force"):
            return jsonify({
                "error": "Conflit de créneau détecté",
                "conflicts": conflicts,
            }), 409

    with get_db() as db:
        db.execute(
            """INSERT INTO acquisitions
               (animal_id,projet,sequence,date_acq,statut,importé_par,importé_le,
                poids_g,qualite,probleme_type,probleme_desc,heure_debut,duree_min)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (data["animal_id"], data["projet"], data["sequence"],
             data["date_acq"], data.get("statut","ok"),
             current_user.username, datetime.now().isoformat(),
             poids_g, qualite, probleme_type,
             data.get("probleme_desc") or None,
             heure_debut, duree_min)
        )
        db.execute(
            "UPDATE animaux SET nb_acquisitions=nb_acquisitions+1 WHERE animal_id=?",
            (data["animal_id"],)
        )
        db.commit()
    emit_event("acquisition_new", {
        "animal_id": data["animal_id"], "projet": data["projet"],
        "sequence": data["sequence"], "par": current_user.username
    })
    return jsonify({"ok": True}), 201


# ─────────────────────────────────────────────────
#  IMPORT DICOM → NIfTI (upload fichier local)
# ─────────────────────────────────────────────────

import shutil, tempfile
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {".dcm", ".ima", ".nii", ".nii.gz", ""}

def dicom_series_to_nifti(dcm_files: list, dest_dir: Path, stem: str = "series") -> tuple:
    """
    Empile plusieurs coupes DICOM (une série) en un volume 3D NIfTI.
    Retourne (nifti_path, metadata_dict).
    """
    import pydicom, nibabel as nib, numpy as np

    dest_dir.mkdir(parents=True, exist_ok=True)

    slices, meta = [], {}
    for f in dcm_files:
        try:
            ds = pydicom.dcmread(str(f), force=True)
            slices.append(ds)
        except Exception:
            pass

    if not slices:
        raise ValueError("Aucune coupe DICOM lisible dans la série")

    # Trier par InstanceNumber puis SliceLocation
    def _sort_key(ds):
        inst = getattr(ds, "InstanceNumber", None)
        loc  = getattr(ds, "SliceLocation",  None)
        return (int(inst) if inst is not None else 0,
                float(loc) if loc is not None else 0.0)
    slices.sort(key=_sort_key)

    # Lire les métadonnées du premier slice
    ds0 = slices[0]
    for attr, key in [("PatientID","animal_id"), ("StudyDate","date_acq"),
                       ("SeriesDescription","sequence"), ("Modality","modality")]:
        v = getattr(ds0, attr, None)
        if v:
            meta[key] = str(v)

    # Empiler les pixels
    arrays = []
    for ds in slices:
        try:
            arr = ds.pixel_array.astype(np.float32)
            if arr.ndim == 2:
                arrays.append(arr)
        except Exception:
            pass

    if not arrays:
        raise ValueError("Impossible de lire les pixels des coupes DICOM")

    volume = np.stack(arrays, axis=-1)   # (rows, cols, n_slices)

    # Affine depuis métadonnées
    affine = np.eye(4)
    try:
        ps = ds0.PixelSpacing
        st = float(getattr(ds0, "SliceThickness", 1.0))
        affine = np.diag([float(ps[0]), float(ps[1]), st, 1.0])
    except Exception:
        pass

    mn, mx = volume.min(), volume.max()
    if mx > mn:
        volume = (volume - mn) / (mx - mn) * 1000.0

    out_path = dest_dir / f"{stem}.nii.gz"
    nib.save(nib.Nifti1Image(volume, affine), str(out_path))
    return out_path, meta


def extract_dicom_from_zip(zip_path: Path, tmp_dir: Path) -> list:
    """Extrait tous les fichiers DICOM d'une archive zip."""
    import zipfile
    dcm_files = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            low = name.lower()
            if low.endswith((".dcm", ".ima")) or ("." not in Path(name).name):
                out = tmp_dir / Path(name).name
                out.write_bytes(zf.read(name))
                dcm_files.append(out)
    return dcm_files


def dicom_to_nifti(dicom_path: Path, dest_dir: Path) -> Path:
    """
    Convertit un fichier DICOM en NIfTI.
    Gère les DICOM compressés JPEG2000 (format Paravision courant).
    Stratégies dans l'ordre :
      1. pydicom natif (décompression automatique si plugins dispo)
      2. pydicom avec force=True + décompression manuelle gdcm
      3. Sauvegarde des métadonnées seules sans pixel data (fallback ultime)
    """
    import pydicom, nibabel as nib, numpy as np

    dest_dir.mkdir(parents=True, exist_ok=True)
    out_name = dicom_path.stem + ".nii.gz"
    out_path = dest_dir / out_name

    # Stratégie 1 : lecture normale avec décompression automatique
    pixel_array = None
    affine = np.eye(4)
    ds = None

    try:
        ds = pydicom.dcmread(str(dicom_path), force=True)
        pixel_array = ds.pixel_array.astype(np.float32)
    except Exception:
        pass

    # Stratégie 2 : décompression via gdcm si dispo
    if pixel_array is None:
        try:
            import gdcm  # noqa
            pydicom.config.pixel_data_handlers = ["gdcm"]
            ds = pydicom.dcmread(str(dicom_path), force=True)
            pixel_array = ds.pixel_array.astype(np.float32)
        except Exception:
            pass

    # Stratégie 3 : fallback sans pixel data — sauvegarde un NIfTI vide
    # avec les métadonnées correctes (au moins la structure est créée)
    if pixel_array is None:
        try:
            ds = pydicom.dcmread(str(dicom_path), stop_before_pixels=True, force=True)
            rows = int(getattr(ds, "Rows", 64))
            cols = int(getattr(ds, "Columns", 64))
            pixel_array = np.zeros((rows, cols), dtype=np.float32)
        except Exception:
            pixel_array = np.zeros((64, 64), dtype=np.float32)

    # Construire l'affine depuis les métadonnées si possible
    if ds is not None:
        try:
            ps = ds.PixelSpacing
            st = float(getattr(ds, "SliceThickness", 1.0))
            affine = np.diag([float(ps[0]), float(ps[1]), st, 1.0])
        except Exception:
            affine = np.eye(4)

    img = nib.Nifti1Image(pixel_array, affine)
    nib.save(img, str(out_path))
    return out_path


def process_uploaded_file(src: Path, project: str, animal_id: str,
                           sequence: str, date_acq: str) -> dict:
    """
    Traite un fichier uploadé :
      1. Détecte DICOM ou NIfTI
      2. Convertit en NIfTI si nécessaire
      3. Dépose dans l'arborescence locale NAS simulée
      4. Lit les métadonnées
      5. Retourne un dict de résultat
    """
    ext = "".join(src.suffixes).lower()
    is_nifti  = ext in {".nii", ".nii.gz"}
    is_dicom  = ext in {".dcm", ".ima"} or ext == ""

    # Construire le chemin destination (même convention que le vrai NAS)
    # /nas_simule/structured/<projet>/<animal>_<date>/<sequence>/
    dest_dir   = NAS_ROOT / project / build_animal_folder(animal_id, date_acq) / sanitize_animal_id(sequence)
    dest_dir.mkdir(parents=True, exist_ok=True)

    meta = {"animal_id": animal_id, "projet": project,
            "sequence": sequence, "date_acq": date_acq}

    if is_nifti:
        dest_file = dest_dir / src.name
        shutil.copy2(src, dest_file)
        file_type = "NIfTI"
        nifti_path = dest_file
    else:
        # DICOM → convertir en NIfTI
        nifti_path = dicom_to_nifti(src, dest_dir)
        file_type  = "DICOM→NIfTI"

        # Lire métadonnées DICOM si possible
        try:
            import pydicom
            ds = pydicom.dcmread(str(src), stop_before_pixels=True, force=True)
            if hasattr(ds, "PatientID") and ds.PatientID:
                meta["animal_id"] = str(ds.PatientID)
            if hasattr(ds, "StudyDate") and ds.StudyDate:
                meta["date_acq"] = str(ds.StudyDate)
            if hasattr(ds, "SeriesDescription") and ds.SeriesDescription:
                meta["sequence"] = str(ds.SeriesDescription)
        except Exception:
            pass

    # Hash MD5
    md5 = hashlib.md5(open(nifti_path, "rb").read()).hexdigest()

    return {
        "status":     "IMPORTED",
        "file_type":  file_type,
        "dest":       str(nifti_path),
        "dest_rel":   str(nifti_path.relative_to(NAS_ROOT)),
        "md5":        md5,
        "meta":       meta,
    }


@app.route("/api/pipeline/dicom-meta", methods=["POST"])
@login_required
def api_dicom_meta():
    """Lit les métadonnées DICOM du premier fichier envoyé (sans le stocker)."""
    files = request.files.getlist("files")
    if not files:
        return jsonify({}), 200
    with tempfile.TemporaryDirectory() as tmp:
        f0   = files[0]
        path = Path(tmp) / secure_filename(f0.filename)
        f0.save(str(path))
        try:
            import pydicom
            ds   = pydicom.dcmread(str(path), stop_before_pixels=True, force=True)
            meta = {}

            # Tags standard
            if getattr(ds, "PatientID",         None): meta["animal_id"] = str(ds.PatientID).strip()
            if getattr(ds, "StudyDate",          None): meta["date_acq"]  = str(ds.StudyDate).strip()
            if getattr(ds, "SeriesDescription",  None): meta["sequence"]  = str(ds.SeriesDescription).strip()
            if getattr(ds, "Modality",           None): meta["modality"]  = str(ds.Modality).strip()
            if getattr(ds, "PatientName",        None): meta["patient_name"] = str(ds.PatientName).strip()
            if getattr(ds, "ProtocolName",       None): meta["protocol"]  = str(ds.ProtocolName).strip()
            if getattr(ds, "StudyDescription",   None): meta["study_desc"] = str(ds.StudyDescription).strip()
            if getattr(ds, "InstitutionName",    None): meta["institution"] = str(ds.InstitutionName).strip()

            # Paravision exporte parfois le nom de la séquence dans SequenceName
            if not meta.get("sequence") and getattr(ds, "SequenceName", None):
                meta["sequence"] = str(ds.SequenceName).strip()
            # Ou dans SeriesDescription avec un préfixe à nettoyer
            if meta.get("sequence"):
                # Nettoyer les noms Paravision du type "* T1_FLASH" ou "FLASH_T2"
                seq = re.sub(r"^[\*\s]+", "", meta["sequence"])
                seq = sanitize_animal_id(seq)
                meta["sequence"] = seq

            # Normaliser l'animal_id selon convention FAIR
            if meta.get("animal_id"):
                meta["animal_id"] = sanitize_animal_id(meta["animal_id"])

            return jsonify(meta)
        except Exception:
            return jsonify({}), 200


@app.route("/api/pipeline/fair-preview", methods=["POST"])
@login_required
def api_fair_preview():
    """Retourne le chemin FAIR calculé pour un import donné."""
    data      = request.json or {}
    animal_id = data.get("animal_id", "").strip()
    project   = data.get("project",   "").strip()
    sequence  = data.get("sequence",  "SEQ").strip()
    date_acq  = data.get("date_acq",  "").strip()
    if not animal_id or not project:
        return jsonify({"error": "animal_id et project requis"}), 400
    folder  = build_animal_folder(animal_id, date_acq or datetime.now().strftime("%Y%m%d"))
    seq_dir = sanitize_animal_id(sequence)
    preview = f"{project}/{folder}/{seq_dir}/<fichier>.nii.gz"
    return jsonify({"preview": preview, "folder": folder, "seq": seq_dir})


@app.route("/api/nas/scan-names")
@login_required
@role_required("admin", "operateur")
def api_nas_scan_names():
    """
    Scanne le NAS pour trouver des dossiers dont le nom ne respecte pas
    la convention FAIR : AAAAMMJJ_AnimalID (sans espace ni caractère spécial).
    """
    import re as _re
    pattern = _re.compile(r"^\d{8}_[A-Za-z0-9_\-]+$")
    bad, ok_count = [], 0
    for projet_dir in sorted(NAS_ROOT.iterdir()):
        if not projet_dir.is_dir():
            continue
        for animal_dir in sorted(projet_dir.iterdir()):
            if not animal_dir.is_dir():
                continue
            name = animal_dir.name
            if pattern.match(name):
                ok_count += 1
            else:
                bad.append({
                    "projet":   projet_dir.name,
                    "nom":      name,
                    "suggere":  _re.sub(r"[* ]+", "-", name).strip("-_"),
                    "chemin":   str(animal_dir.relative_to(NAS_ROOT)),
                })
    return jsonify({"non_conformes": bad, "ok": ok_count, "total": ok_count + len(bad)})


@app.route("/api/nas/rename", methods=["POST"])
@login_required
@role_required("admin")
def api_nas_rename():
    """Renomme un dossier NAS et met à jour les chemins en base."""
    data     = request.json or {}
    projet   = data.get("projet",    "").strip()
    old_name = data.get("old_name",  "").strip()
    new_name = sanitize_animal_id(data.get("new_name", "").strip())

    if not projet or not old_name or not new_name:
        return jsonify({"error": "projet, old_name et new_name requis"}), 400

    old_path = NAS_ROOT / projet / old_name
    new_path = NAS_ROOT / projet / new_name

    if not old_path.exists():
        return jsonify({"error": "Dossier source introuvable"}), 404
    if new_path.exists():
        return jsonify({"error": "Un dossier avec ce nom existe déjà"}), 409

    old_path.rename(new_path)

    # Mettre à jour les chemins dans acquisitions
    with get_db() as db:
        acqs = db.execute(
            "SELECT id, fichier_dest FROM acquisitions WHERE projet=?", (projet,)
        ).fetchall()
        for a in acqs:
            if a["fichier_dest"] and old_name in a["fichier_dest"]:
                new_dest = a["fichier_dest"].replace(
                    str(old_path), str(new_path)
                ).replace(
                    f"/{old_name}/", f"/{new_name}/"
                )
                db.execute("UPDATE acquisitions SET fichier_dest=? WHERE id=?",
                           (new_dest, a["id"]))
        db.commit()

    return jsonify({"ok": True, "nouveau_nom": new_name})


@app.route("/api/pipeline/upload", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_upload_file():
    """Upload DICOM (un ou plusieurs fichiers / zip) ou NIfTI depuis le navigateur."""
    files     = request.files.getlist("files")
    project   = request.form.get("project",   "").strip()
    animal_id = request.form.get("animal_id", "").strip()
    sequence  = request.form.get("sequence",  "SEQ").strip()
    date_acq  = request.form.get("date_acq",  datetime.now().strftime("%Y-%m-%d")).strip()
    espece    = request.form.get("espece",    "—").strip() or "—"

    # ── Champs enrichis (poids, qualité, problème) — optionnels ─────────────
    poids_raw     = request.form.get("poids_g", "").strip()
    qualite       = request.form.get("qualite", "").strip() or None
    probleme_type = request.form.get("probleme_type", "").strip() or None
    probleme_desc = request.form.get("probleme_desc", "").strip() or None

    poids_g = None
    if poids_raw:
        try:
            poids_g = float(poids_raw)
            if poids_g <= 0 or poids_g > 5000:
                return jsonify({"error": "Poids invalide (0–5000 g)"}), 400
        except ValueError:
            return jsonify({"error": "Poids doit être un nombre"}), 400
    if qualite and qualite not in ("excellente", "bonne", "degradee", "inutilisable"):
        return jsonify({"error": "Qualité invalide"}), 400
    if probleme_type and probleme_type not in ("aucun", "positionnement", "artefact", "mouvement", "materiel", "autre"):
        return jsonify({"error": "Type de problème invalide"}), 400

    if not files or files[0].filename == "":
        return jsonify({"error": "Aucun fichier reçu"}), 400
    if not project or not animal_id:
        return jsonify({"error": "project et animal_id requis"}), 400

    # Droits d'édition sur le projet ciblé
    if not user_can_edit_projet(current_user, project):
        return jsonify({"error": "Vous n'avez pas les droits d'édition sur ce projet"}), 403

    now = datetime.now().isoformat()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir  = Path(tmp)
        saved    = []
        for f in files:
            p = tmp_dir / secure_filename(f.filename)
            f.save(str(p))
            saved.append(p)

        # Détecter le mode : zip / série DICOM / fichier unique
        is_zip    = len(saved) == 1 and saved[0].suffix.lower() == ".zip"
        is_nifti  = len(saved) == 1 and "".join(saved[0].suffixes).lower() in {".nii", ".nii.gz"}
        is_series = (not is_zip and not is_nifti and len(saved) > 1)

        dest_dir = NAS_ROOT / project / build_animal_folder(animal_id, date_acq) / sanitize_animal_id(sequence)
        dest_dir.mkdir(parents=True, exist_ok=True)

        try:
            if is_zip:
                dcm_files = extract_dicom_from_zip(saved[0], tmp_dir / "extracted")
                if not dcm_files:
                    return jsonify({"error": "Aucun fichier DICOM trouvé dans l'archive"}), 400
                nifti_path, detected = dicom_series_to_nifti(dcm_files, dest_dir, stem=sanitize_animal_id(sequence))
                file_type = f"ZIP→NIfTI ({len(dcm_files)} coupes)"

            elif is_series:
                nifti_path, detected = dicom_series_to_nifti(saved, dest_dir, stem=sanitize_animal_id(sequence))
                file_type = f"Série DICOM→NIfTI ({len(saved)} coupes)"

            elif is_nifti:
                import shutil as _sh
                nifti_path = dest_dir / saved[0].name
                _sh.copy2(saved[0], nifti_path)
                detected  = {}
                file_type = "NIfTI"

            else:
                # Fichier DICOM unique
                result = process_uploaded_file(saved[0], project, animal_id, sequence, date_acq)
                nifti_path = Path(result["dest"])
                detected   = result["meta"]
                file_type  = result["file_type"]

        except Exception as e:
            return jsonify({"error": str(e)}), 500

        md5 = hashlib.md5(open(nifti_path, "rb").read()).hexdigest()

    # Priorité aux valeurs saisies par l'utilisateur sur les métadonnées DICOM
    final_animal = animal_id or detected.get("animal_id", animal_id)
    final_date   = date_acq  or detected.get("date_acq",  date_acq)
    final_seq    = sequence  or detected.get("sequence",  sequence)

    with get_db() as db:
        db.execute(
            "INSERT INTO acquisitions "
            "(animal_id,projet,sequence,date_acq,fichier_dest,md5,statut,importé_par,importé_le,"
            " poids_g,qualite,probleme_type,probleme_desc) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (final_animal, project, final_seq, final_date,
             normalize_path_for_storage(str(nifti_path)), md5, "ok", current_user.username, now,
             poids_g, qualite, probleme_type, probleme_desc)
        )
        existing = db.execute(
            "SELECT id FROM animaux WHERE animal_id=? AND projet=?",
            (final_animal, project)
        ).fetchone()
        if existing:
            db.execute(
                "UPDATE animaux SET nb_acquisitions=nb_acquisitions+1, statut='en_cours' "
                "WHERE animal_id=? AND projet=?",
                (final_animal, project)
            )
        else:
            db.execute(
                "INSERT INTO animaux (animal_id,espece,projet,date_premiere_acq,nb_acquisitions,statut) "
                "VALUES (?,?,?,?,?,?)",
                (final_animal, espece, project, final_date, 1, "en_cours")
            )
        db.execute(
            "INSERT INTO pipeline_logs (timestamp,source,dest,animal_id,sequence,statut,md5) "
            "VALUES (?,?,?,?,?,?,?)",
            (now, f"{len(files)} fichier(s)", str(nifti_path),
             final_animal, final_seq, "IMPORTED", md5)
        )
        db.commit()

    return jsonify({
        "ok":       True,
        "message":  f"{file_type} importé avec succès",
        "dest":     str(nifti_path.relative_to(NAS_ROOT)),
        "md5":      md5,
        "nb_files": len(files),
    })


# ─────────────────────────────────────────────────
#  API — LOGS
# ─────────────────────────────────────────────────

@app.route("/planification")
@login_required
@role_required("admin", "operateur")
def page_planification():
    with get_db() as db:
        projets_raw = db.execute("SELECT * FROM projets ORDER BY nom").fetchall()
        animaux_raw = db.execute("SELECT * FROM animaux ORDER BY projet, animal_id").fetchall()
        acq_counts  = db.execute(
            "SELECT animal_id, projet, COUNT(*) as n FROM acquisitions GROUP BY animal_id, projet"
        ).fetchall()

    acq_map = {(r["animal_id"], r["projet"]): r["n"] for r in acq_counts}

    alertes = []
    projets_plan = []

    for p in projets_raw:
        seq     = p["seq_par_animal"] if p["seq_par_animal"] else 3
        animaux = [a for a in animaux_raw if a["projet"] == p["nom"]]
        enrich  = []
        nb_ok = nb_attente = nb_cours = nb_refaire = nb_manquant = 0

        for a in animaux:
            acq_faites = acq_map.get((a["animal_id"], p["nom"]), 0)
            restantes  = max(0, seq - acq_faites)
            enrich.append({
                **dict(a),
                "acq_faites": acq_faites,
                "seq_attendues": seq,
                "restantes": restantes,
                "dossier_nas": build_animal_folder(a["animal_id"], a["date_premiere_acq"] or "00000000"),
            })
            if a["statut"] == "ok":          nb_ok      += 1
            elif a["statut"] == "en_attente": nb_attente += 1
            elif a["statut"] == "en_cours":   nb_cours   += 1
            elif a["statut"] == "a_refaire":  nb_refaire += 1
            if restantes > 0:                 nb_manquant += 1

            # Alertes individuelles
            if a["statut"] == "a_refaire":
                alertes.append({
                    "type": "reprise",
                    "projet": p["nom"],
                    "animal_id": a["animal_id"],
                    "msg": f"Reprise requise pour {a['animal_id']} ({p['nom']})",
                })
            if restantes > 0 and a["statut"] not in ("ok",):
                alertes.append({
                    "type": "manquant",
                    "projet": p["nom"],
                    "animal_id": a["animal_id"],
                    "msg": f"{restantes} acquisition(s) manquante(s) — {a['animal_id']} ({p['nom']})",
                })

        prevues = p["nb_animaux_prevus"] * seq
        faites  = sum(acq_map.get((a["animal_id"], p["nom"]), 0) for a in animaux)
        pct     = round(faites / prevues * 100) if prevues else 0

        if pct < 50 and p["nb_animaux_prevus"] > 0:
            alertes.append({
                "type": "retard",
                "projet": p["nom"],
                "animal_id": None,
                "msg": f"Projet {p['nom']} : seulement {pct}% des acquisitions réalisées",
            })

        projets_plan.append({
            "nom": p["nom"], "resp": p["resp"],
            "nb_prevus": p["nb_animaux_prevus"],
            "nb_inscrits": len(animaux),
            "seq_par_animal": seq,
            "prevues": prevues, "faites": faites, "pct": pct,
            "couleur": "teal" if pct >= 75 else ("amber" if pct >= 40 else "red"),
            "nb_ok": nb_ok, "nb_attente": nb_attente,
            "nb_cours": nb_cours, "nb_refaire": nb_refaire,
            "nb_manquant": nb_manquant,
            "animaux": enrich,
        })

    # ── Conflits de créneaux IRM (acquisitions le même jour qui se chevauchent) ──
    with get_db() as db:
        rows = db.execute(
            """SELECT id, animal_id, projet, sequence, date_acq,
                      heure_debut, duree_min, importé_par, statut
               FROM acquisitions
               WHERE heure_debut IS NOT NULL AND duree_min IS NOT NULL
               ORDER BY date_acq, heure_debut"""
        ).fetchall()

    by_date: dict[str, list] = {}
    for r in rows:
        by_date.setdefault(r["date_acq"], []).append(dict(r))

    conflits = []
    for date_acq, acqs in by_date.items():
        for i in range(len(acqs)):
            a = acqs[i]; a_start = _hhmm_to_min(a["heure_debut"])
            a_end = a_start + int(a["duree_min"])
            for j in range(i + 1, len(acqs)):
                b = acqs[j]; b_start = _hhmm_to_min(b["heure_debut"])
                b_end = b_start + int(b["duree_min"])
                if a_start < b_end and b_start < a_end:
                    conflits.append({
                        "date_acq": date_acq,
                        "a_heure": a["heure_debut"], "a_fin": _min_to_hhmm(a_end),
                        "a_animal": a["animal_id"], "a_projet": a["projet"],
                        "a_seq": a["sequence"], "a_user": a["importé_par"], "a_id": a["id"],
                        "b_heure": b["heure_debut"], "b_fin": _min_to_hhmm(b_end),
                        "b_animal": b["animal_id"], "b_projet": b["projet"],
                        "b_seq": b["sequence"], "b_user": b["importé_par"], "b_id": b["id"],
                    })

    return render_template("planification.html",
        projets=projets_plan,
        alertes=alertes,
        nb_alertes=len(alertes),
        conflits=conflits,
        nb_conflits=len(conflits),
    )


@app.route("/connexions")
@login_required
@role_required("admin")
def page_connexions():
    filtre_action   = request.args.get("action", "")
    filtre_username = request.args.get("username", "").strip()

    # Pagination — 50 entrées par page
    try: page = max(1, int(request.args.get("page", 1)))
    except ValueError: page = 1
    per_page = 50
    offset   = (page - 1) * per_page

    where  = "WHERE 1=1"
    params = []
    if filtre_action:
        where += " AND action=?"; params.append(filtre_action)
    if filtre_username:
        where += " AND username LIKE ?"; params.append(f"%{filtre_username}%")

    with get_db() as db:
        nb_filtre = db.execute(
            f"SELECT COUNT(*) FROM connexions_log {where}", params
        ).fetchone()[0]
        logs = db.execute(
            f"SELECT * FROM connexions_log {where} "
            f"ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()
        nb_fail = db.execute("SELECT COUNT(*) FROM connexions_log WHERE action='login_failed'").fetchone()[0]
        total   = db.execute("SELECT COUNT(*) FROM connexions_log").fetchone()[0]

    nb_pages = max(1, (nb_filtre + per_page - 1) // per_page)
    return render_template("connexions.html",
        logs=[dict(l) for l in logs],
        nb_fail=nb_fail, total=total,
        filtre_action=filtre_action, filtre_username=filtre_username,
        smtp_configured=EMAIL_CONFIGURED,
        page=page, nb_pages=nb_pages, per_page=per_page,
        nb_filtre=nb_filtre)


@app.route("/api/connexions")
@login_required
@role_required("admin")
def api_connexions():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM connexions_log ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/export/connexions.csv")
@login_required
@role_required("admin")
def export_connexions_csv():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM connexions_log ORDER BY timestamp DESC"
        ).fetchall()
    cols = ["id", "username", "action", "ip", "pays", "timestamp"]
    buf  = io.StringIO()
    w    = csv.writer(buf, delimiter=";")
    w.writerow(cols)
    for r in rows:
        w.writerow([r[c] for c in cols])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="connexions.csv"'
    return resp


# ─────────────────────────────────────────────────
#  F6 — EXPORT CSV
# ─────────────────────────────────────────────────

def _csv_response(filename: str, headers: list, rows) -> object:
    """Génère une réponse Flask avec un fichier CSV prêt à télécharger."""
    buf = io.StringIO()
    w   = csv.writer(buf, delimiter=";")
    w.writerow(headers)
    for row in rows:
        w.writerow([row[h] if isinstance(row, dict) else row[i] for i, h in enumerate(headers)])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@app.route("/api/export/animaux.csv")
@login_required
def export_animaux_csv():
    projet = request.args.get("projet", "")
    statut = request.args.get("statut", "")
    q, params = "SELECT * FROM animaux WHERE 1=1", []
    if projet: q += " AND projet=?"; params.append(projet)
    if statut: q += " AND statut=?"; params.append(statut)
    q += " ORDER BY projet, animal_id"
    with get_db() as db:
        rows = db.execute(q, params).fetchall()
    cols    = ["id", "animal_id", "espece", "projet", "date_premiere_acq", "nb_acquisitions", "statut"]
    dossier = [build_animal_folder(r["animal_id"], r["date_premiere_acq"] or "00000000") for r in rows]
    buf = io.StringIO()
    w   = csv.writer(buf, delimiter=";")
    w.writerow(cols + ["dossier_nas"])
    for r, dos in zip(rows, dossier):
        w.writerow([r[c] for c in cols] + [dos])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="animaux.csv"'
    return resp


@app.route("/api/export/acquisitions.csv")
@login_required
def export_acquisitions_csv():
    projet = request.args.get("projet", "")
    q, params = "SELECT * FROM acquisitions WHERE 1=1", []
    if projet: q += " AND projet=?"; params.append(projet)
    q += " ORDER BY date_acq DESC"
    with get_db() as db:
        rows = db.execute(q, params).fetchall()
    cols = ["id", "animal_id", "projet", "sequence", "date_acq", "fichier_dest", "md5", "statut", "importé_par", "importé_le"]
    buf = io.StringIO()
    w   = csv.writer(buf, delimiter=";")
    w.writerow(cols)
    for r in rows:
        w.writerow([r[c] for c in cols])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="acquisitions.csv"'
    return resp


@app.route("/api/export/projet/<nom>/rapport.csv")
@login_required
def export_projet_rapport_csv(nom):
    """Rapport complet d'un projet : animaux + acquisitions fusionnés."""
    with get_db() as db:
        projet = db.execute("SELECT * FROM projets WHERE nom=?", (nom,)).fetchone()
        if not projet:
            return "Projet introuvable", 404
        rows = db.execute("""
            SELECT a.animal_id, a.espece, a.statut, a.date_premiere_acq, a.nb_acquisitions,
                   acq.sequence, acq.date_acq, acq.statut as acq_statut,
                   acq.importé_par, acq.importé_le, acq.fichier_dest
            FROM animaux a
            LEFT JOIN acquisitions acq ON a.animal_id=acq.animal_id AND a.projet=acq.projet
            WHERE a.projet=?
            ORDER BY a.animal_id, acq.date_acq
        """, (nom,)).fetchall()
    cols = ["animal_id", "espece", "statut_animal", "date_premiere_acq", "nb_acquisitions",
            "sequence", "date_acq", "statut_acquisition", "importé_par", "importé_le", "fichier_dest"]
    buf = io.StringIO()
    w   = csv.writer(buf, delimiter=";")
    w.writerow(["# Projet: " + nom])
    w.writerow(["# Exporté le: " + datetime.now().strftime("%Y-%m-%d %H:%M")])
    w.writerow([])
    w.writerow(cols)
    for r in rows:
        w.writerow([
            r["animal_id"], r["espece"], r["statut"], r["date_premiere_acq"], r["nb_acquisitions"],
            r["sequence"] or "", r["date_acq"] or "", r["acq_statut"] or "",
            r["importé_par"] or "", r["importé_le"] or "", r["fichier_dest"] or ""
        ])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="rapport_{nom}.csv"'
    return resp


# ─────────────────────────────────────────────────
#  EXPORT BIDS — Brain Imaging Data Structure
# ─────────────────────────────────────────────────
#
# Format BIDS-inspiré (extension préclinique non officielle) pour interopérabilité.
# Structure générée :
#   <projet>/
#     dataset_description.json
#     participants.tsv
#     README
#     sub-<animal>/
#       ses-<YYYYMMDD>/
#         anat/  ou  dwi/  ou  func/
#           sub-<animal>_ses-<date>_<seq>.nii.gz
#           sub-<animal>_ses-<date>_<seq>.json   (sidecar métadonnées)
# ─────────────────────────────────────────────────

def _bids_modality(sequence: str) -> str:
    """Classe une séquence dans une modalité BIDS (anat/dwi/func/misc)."""
    s = (sequence or "").upper()
    if "DTI" in s or "DWI" in s:               return "dwi"
    if "BOLD" in s or "FMRI" in s or "REST" in s: return "func"
    if any(t in s for t in ("T1", "T2", "FLAIR", "PD", "MPRAGE", "RARE", "MSME", "MGE")):
        return "anat"
    return "misc"

def _bids_safe(s: str) -> str:
    """Nettoie une chaîne pour utilisation comme label BIDS (alphanumérique uniquement)."""
    return re.sub(r"[^a-zA-Z0-9]", "", s or "")

def _bids_session(date_acq: str) -> str:
    """Convertit 2026-05-12 → 20260512 (label session BIDS)."""
    return re.sub(r"[^0-9]", "", date_acq or "")[:8] or "00000000"


@app.route("/api/export/bids/<nom>.zip")
@login_required
def export_projet_bids(nom):
    """
    Génère un dataset BIDS-like du projet sous forme de ZIP.
    Inclut les fichiers NIfTI existants + métadonnées dans des sidecars JSON.
    """
    import zipfile

    if not user_can_view_projet(current_user, nom):
        return jsonify({"error": "Accès refusé à ce projet"}), 403

    with get_db() as db:
        projet  = db.execute("SELECT * FROM projets WHERE nom=?", (nom,)).fetchone()
        if not projet:
            return jsonify({"error": "Projet introuvable"}), 404

        animaux = db.execute(
            "SELECT * FROM animaux WHERE projet=?", (nom,)
        ).fetchall()
        acqs = db.execute(
            "SELECT * FROM acquisitions WHERE projet=? ORDER BY animal_id, date_acq",
            (nom,)
        ).fetchall()

    buf = io.BytesIO()
    now_iso = datetime.utcnow().isoformat() + "Z"

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        root = nom

        # ── dataset_description.json ─────────────────────────────────────────
        dataset_desc = {
            "Name":           nom,
            "BIDSVersion":    "1.8.0",
            "DatasetType":    "raw",
            "Authors":        [projet["resp"] or "—"],
            "Acknowledgements": f"Exporté depuis IRM FAIR le {now_iso}",
            "License":        "internal",
            "EthicsApprovals": [projet["protocole_ethique"]] if projet["protocole_ethique"] else [],
        }
        zf.writestr(f"{root}/dataset_description.json",
                    json.dumps(dataset_desc, indent=2, ensure_ascii=False))

        # ── README ───────────────────────────────────────────────────────────
        readme = (
            f"# {nom}\n\n"
            f"Dataset IRM préclinique exporté depuis IRM FAIR.\n\n"
            f"- Responsable : {projet['resp'] or '—'}\n"
            f"- Animaux prévus : {projet['nb_animaux_prevus']}\n"
            f"- Séquences/animal : {projet['seq_par_animal']}\n"
            f"- Date export : {now_iso}\n\n"
            f"Convention :\n"
            f"  sub-<animal>/ses-<YYYYMMDD>/<modality>/sub-<animal>_ses-<date>_<sequence>.nii.gz\n\n"
            f"Modalités utilisées : anat (T1/T2/FLAIR/RARE/MSME), dwi (DTI/DWI), "
            f"func (BOLD/fMRI), misc (autres).\n"
        )
        zf.writestr(f"{root}/README", readme)

        # ── participants.tsv ─────────────────────────────────────────────────
        lines = ["participant_id\tspecies\tstatut\tnb_acquisitions\tdate_premiere_acq"]
        for a in animaux:
            pid = f"sub-{_bids_safe(a['animal_id'])}"
            lines.append("\t".join([
                pid,
                a["espece"] or "n/a",
                a["statut"] or "n/a",
                str(a["nb_acquisitions"]),
                a["date_premiere_acq"] or "n/a",
            ]))
        zf.writestr(f"{root}/participants.tsv", "\n".join(lines) + "\n")

        # ── participants.json (data dictionary) ──────────────────────────────
        participants_dict = {
            "participant_id": {"Description": "Identifiant unique de l'animal (préfixe sub-)"},
            "species":        {"Description": "Espèce", "Levels": {
                                "Rat": "Rat", "Souris": "Mouse", "Lapin": "Rabbit"}},
            "statut":         {"Description": "Statut de suivi animal",
                               "Levels": {"ok": "Acquisitions complètes",
                                          "en_cours": "En cours",
                                          "en_attente": "En attente",
                                          "a_refaire": "À refaire"}},
            "nb_acquisitions":     {"Description": "Nombre d'acquisitions effectuées"},
            "date_premiere_acq":   {"Description": "Date de la première acquisition (YYYYMMDD)"},
        }
        zf.writestr(f"{root}/participants.json",
                    json.dumps(participants_dict, indent=2, ensure_ascii=False))

        # ── Une entrée par acquisition : sub-X/ses-Y/<modality>/... ─────────
        nb_files = 0
        for acq in acqs:
            sub_label = _bids_safe(acq["animal_id"])
            ses_label = _bids_session(acq["date_acq"])
            modality  = _bids_modality(acq["sequence"])
            seq_label = _bids_safe(acq["sequence"]) or "seq"
            stem      = f"sub-{sub_label}_ses-{ses_label}_{seq_label}"
            target_dir = f"{root}/sub-{sub_label}/ses-{ses_label}/{modality}"

            # Sidecar JSON (toujours créé, même sans NIfTI)
            sidecar = {
                "TaskName":         acq["sequence"] or "n/a",
                "AcquisitionDate":  acq["date_acq"] or "n/a",
                "AcquisitionTime":  acq["heure_debut"] or "n/a",
                "ScanDuration":     acq["duree_min"] if acq["duree_min"] else "n/a",
                "Operator":         acq["importé_par"] or "n/a",
                "AnimalWeight_g":   acq["poids_g"] if acq["poids_g"] is not None else "n/a",
                "ImageQuality":     acq["qualite"] or "n/a",
                "Problem":          acq["probleme_type"] or "n/a",
                "ProblemDescription": acq["probleme_desc"] or "",
                "Status":           acq["statut"] or "n/a",
                "MD5":              acq["md5"] or "",
                "_source_path":     acq["fichier_dest"] or "",
                "_irm_fair_acq_id": acq["id"],
            }
            zf.writestr(f"{target_dir}/{stem}.json",
                        json.dumps(sidecar, indent=2, ensure_ascii=False))

            # Fichier NIfTI s'il existe
            if acq["fichier_dest"]:
                src = NAS_ROOT / acq["fichier_dest"]
                if src.exists() and src.is_file():
                    ext = ".nii.gz" if str(src).endswith(".nii.gz") else src.suffix
                    zf.write(src, f"{target_dir}/{stem}{ext}")
                    nb_files += 1

        # ── Manifeste d'export ───────────────────────────────────────────────
        manifest = {
            "exported_at":  now_iso,
            "exported_by":  current_user.username,
            "projet":       nom,
            "nb_animaux":   len(animaux),
            "nb_acquisitions": len(acqs),
            "nb_nifti_inclus": nb_files,
            "note": ("BIDS adapté préclinique — non strictement conforme BIDS 1.8 "
                     "car les animaux ne sont pas humains. Structure compatible "
                     "avec les outils BIDS via 'bids-validator --ignore-warnings'."),
        }
        zf.writestr(f"{root}/_export_manifest.json",
                    json.dumps(manifest, indent=2, ensure_ascii=False))

    buf.seek(0)
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "application/zip"
    resp.headers["Content-Disposition"] = f'attachment; filename="bids_{nom}.zip"'
    return resp


# ─────────────────────────────────────────────────
#  DOCUMENTATION API — OpenAPI 3.1 + Swagger UI
# ─────────────────────────────────────────────────

OPENAPI_SPEC = {
    "openapi": "3.1.0",
    "info": {
        "title":       "IRM FAIR — API",
        "version":     "1.0.0",
        "description": ("API REST de la plateforme IRM FAIR (gestion de projets "
                        "IRM précliniques). Authentification par session — il faut "
                        "appeler `POST /login` au préalable puis renvoyer le cookie."),
        "contact":     {"name": "Équipe IRM FAIR"},
    },
    "servers": [{"url": "/", "description": "Instance courante"}],
    "tags": [
        {"name": "Auth",         "description": "Connexion, 2FA, mot de passe"},
        {"name": "Projets",      "description": "CRUD projets + membres (droits par projet)"},
        {"name": "Animaux",      "description": "Animaux d'un projet"},
        {"name": "Acquisitions", "description": "Acquisitions IRM (métadonnées, statut, créneau)"},
        {"name": "Planification","description": "Conflits de créneaux, séries récurrentes"},
        {"name": "Pipeline",     "description": "Upload DICOM/NIfTI vers le NAS FAIR"},
        {"name": "Export",       "description": "Exports CSV et BIDS"},
        {"name": "Admin",        "description": "Utilisateurs, connexions, logs"},
    ],
    "components": {
        "securitySchemes": {
            "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "session"}
        },
        "schemas": {
            "Error":   {"type": "object", "properties": {"error": {"type": "string"}}},
            "Projet": {
                "type": "object",
                "properties": {
                    "nom":               {"type": "string"},
                    "resp":              {"type": "string"},
                    "nb_animaux_prevus": {"type": "integer"},
                    "seq_par_animal":    {"type": "integer"},
                    "statut":            {"type": "string", "enum": ["actif", "terminé"]},
                    "date_debut":        {"type": "string", "format": "date"},
                    "date_fin_prevue":   {"type": "string", "format": "date"},
                    "protocole_ethique": {"type": "string"},
                },
            },
            "Animal": {
                "type": "object",
                "properties": {
                    "id":                {"type": "integer"},
                    "animal_id":         {"type": "string"},
                    "espece":            {"type": "string"},
                    "projet":            {"type": "string"},
                    "statut":            {"type": "string"},
                    "nb_acquisitions":   {"type": "integer"},
                    "date_premiere_acq": {"type": "string"},
                },
            },
            "Acquisition": {
                "type": "object",
                "properties": {
                    "id":           {"type": "integer"},
                    "animal_id":    {"type": "string"},
                    "projet":       {"type": "string"},
                    "sequence":     {"type": "string"},
                    "date_acq":     {"type": "string", "format": "date"},
                    "heure_debut":  {"type": "string", "example": "09:30"},
                    "duree_min":    {"type": "integer"},
                    "fichier_dest": {"type": "string"},
                    "md5":          {"type": "string"},
                    "statut":       {"type": "string",
                                     "enum": ["ok", "en_attente", "en_cours", "a_refaire"]},
                    "poids_g":      {"type": "number", "description": "Poids animal (g)"},
                    "qualite":      {"type": "string",
                                     "enum": ["excellente", "bonne", "degradee", "inutilisable"]},
                    "probleme_type": {"type": "string",
                                      "enum": ["aucun","positionnement","artefact","mouvement",
                                               "materiel","autre"]},
                    "probleme_desc": {"type": "string"},
                    "importé_par":   {"type": "string"},
                    "importé_le":    {"type": "string", "format": "date-time"},
                },
            },
            "Membre": {
                "type": "object",
                "properties": {
                    "user_id":     {"type": "integer"},
                    "username":    {"type": "string"},
                    "role_projet": {"type": "string",
                                    "enum": ["responsable","membre","lecteur"]},
                    "added_by":    {"type": "string"},
                    "added_at":    {"type": "string", "format": "date-time"},
                },
            },
            "Conflict": {
                "type": "object",
                "properties": {
                    "animal_id":   {"type": "string"},
                    "sequence":    {"type": "string"},
                    "heure_debut": {"type": "string"},
                    "heure_fin":   {"type": "string"},
                    "importé_par": {"type": "string"},
                },
            },
        },
    },
    "security": [{"sessionCookie": []}],

    "paths": {
        # ── Auth ─────────────────────────────────────────────────────────────
        "/login": {
            "post": {
                "tags": ["Auth"], "summary": "Connexion (login + mot de passe)",
                "requestBody": {"required": True, "content": {
                    "application/x-www-form-urlencoded": {"schema": {"type": "object",
                        "required": ["username", "password"],
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"},
                            "g-recaptcha-response": {"type": "string"},
                        }}}}},
                "responses": {
                    "302": {"description": "Redirection vers / (succès) ou /login (échec)"},
                    "200": {"description": "Page login (échec)"},
                },
                "security": [],
            }
        },
        "/logout": {
            "get": {"tags": ["Auth"], "summary": "Déconnexion",
                    "responses": {"302": {"description": "Redirection vers /login"}}}
        },

        # ── Projets ──────────────────────────────────────────────────────────
        "/api/projets": {
            "post": {
                "tags": ["Projets"], "summary": "Créer un projet (admin)",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/Projet"}}}},
                "responses": {"201": {"description": "Créé"},
                              "400": {"description": "Champs manquants"},
                              "403": {"description": "Accès refusé"}},
            }
        },
        "/api/projets/{nom}": {
            "delete": {
                "tags": ["Projets"], "summary": "Supprimer un projet (admin)",
                "parameters": [{"name": "nom", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Supprimé"},
                              "409": {"description": "Acquisitions liées : suppression refusée"}},
            }
        },
        "/api/projets/{nom}/dates": {
            "patch": {
                "tags": ["Projets"], "summary": "Modifier les dates (responsable/admin)",
                "parameters": [{"name": "nom", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "properties": {
                        "date_debut":      {"type": "string", "format": "date"},
                        "date_fin_prevue": {"type": "string", "format": "date"},
                    }}}}},
                "responses": {"200": {"description": "OK"}, "403": {"description": "Droits insuffisants"}},
            }
        },
        "/api/projets/{nom}/statut":     {"patch": {"tags": ["Projets"],
            "summary": "Modifier le statut (responsable/admin)",
            "parameters": [{"name":"nom","in":"path","required":True,"schema":{"type":"string"}}],
            "responses": {"200": {"description": "OK"}}}},
        "/api/projets/{nom}/ethique":    {"patch": {"tags": ["Projets"],
            "summary": "Modifier le protocole éthique",
            "parameters": [{"name":"nom","in":"path","required":True,"schema":{"type":"string"}}],
            "responses": {"200": {"description": "OK"}}}},
        "/api/projets/{nom}/acq-prevues": {"patch": {"tags": ["Projets"],
            "summary": "Override du nb d'acquisitions prévues",
            "parameters": [{"name":"nom","in":"path","required":True,"schema":{"type":"string"}}],
            "responses": {"200": {"description": "OK"}}}},

        # ── Membres ──────────────────────────────────────────────────────────
        "/api/projets/{nom}/membres": {
            "get": {
                "tags": ["Projets"], "summary": "Liste des membres",
                "parameters": [{"name":"nom","in":"path","required":True,"schema":{"type":"string"}}],
                "responses": {"200": {"description": "OK", "content": {"application/json":
                    {"schema": {"type": "object", "properties": {
                        "projet":     {"type": "string"},
                        "restricted": {"type": "boolean"},
                        "membres": {"type": "array", "items": {"$ref": "#/components/schemas/Membre"}},
                    }}}}}},
            },
            "post": {
                "tags": ["Projets"], "summary": "Ajouter un membre (responsable/admin)",
                "parameters": [{"name":"nom","in":"path","required":True,"schema":{"type":"string"}}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["username"],
                    "properties": {
                        "username":    {"type": "string"},
                        "role_projet": {"type": "string",
                                        "enum": ["responsable","membre","lecteur"]},
                    }}}}},
                "responses": {"200": {"description": "OK"},
                              "404": {"description": "Utilisateur inconnu"},
                              "409": {"description": "Déjà membre"}},
            },
        },
        "/api/projets/{nom}/membres/{user_id}": {
            "patch": {
                "tags": ["Projets"], "summary": "Changer le rôle d'un membre",
                "parameters": [
                    {"name":"nom","in":"path","required":True,"schema":{"type":"string"}},
                    {"name":"user_id","in":"path","required":True,"schema":{"type":"integer"}}],
                "responses": {"200": {"description": "OK"}}
            },
            "delete": {
                "tags": ["Projets"], "summary": "Retirer un membre",
                "parameters": [
                    {"name":"nom","in":"path","required":True,"schema":{"type":"string"}},
                    {"name":"user_id","in":"path","required":True,"schema":{"type":"integer"}}],
                "responses": {"200": {"description": "OK"},
                              "409": {"description": "Dernier responsable"}},
            },
        },

        # ── Animaux ──────────────────────────────────────────────────────────
        "/api/animaux": {
            "get": {
                "tags": ["Animaux"], "summary": "Liste des animaux (filtre par projet/statut)",
                "parameters": [
                    {"name":"projet","in":"query","schema":{"type":"string"}},
                    {"name":"statut","in":"query","schema":{"type":"string"}}],
                "responses": {"200": {"description": "OK", "content": {"application/json":
                    {"schema": {"type": "array",
                                "items": {"$ref": "#/components/schemas/Animal"}}}}}},
            }
        },
        "/api/animaux/{animal_id}": {
            "get": {
                "tags": ["Animaux"], "summary": "Détail d'un animal + acquisitions",
                "parameters": [{"name":"animal_id","in":"path","required":True,
                                "schema":{"type":"string"}}],
                "responses": {"200": {"description": "OK"},
                              "403": {"description": "Accès refusé"},
                              "404": {"description": "Animal introuvable"}},
            }
        },
        "/api/animaux/{projet}/{animal_id}/statut": {
            "patch": {
                "tags": ["Animaux"], "summary": "Modifier le statut animal",
                "parameters": [
                    {"name":"projet","in":"path","required":True,"schema":{"type":"string"}},
                    {"name":"animal_id","in":"path","required":True,"schema":{"type":"string"}}],
                "responses": {"200": {"description": "OK"}}
            }
        },

        # ── Acquisitions ─────────────────────────────────────────────────────
        "/api/acquisitions": {
            "get":  {"tags": ["Acquisitions"], "summary": "50 dernières acquisitions",
                     "responses": {"200": {"description": "OK"}}},
            "post": {
                "tags": ["Acquisitions"], "summary": "Créer une acquisition",
                "requestBody": {"required": True, "content": {"application/json":
                    {"schema": {"$ref": "#/components/schemas/Acquisition"}}}},
                "responses": {"200": {"description": "Créé"},
                              "409": {"description": "Conflit de créneau",
                                      "content": {"application/json": {"schema": {
                                          "type": "object",
                                          "properties": {
                                              "error":     {"type": "string"},
                                              "conflicts": {"type": "array",
                                                            "items": {"$ref": "#/components/schemas/Conflict"}}}}}}}}
            },
        },
        "/api/acquisitions/{acq_id}/statut": {"patch": {"tags": ["Acquisitions"],
            "summary": "Modifier le statut d'une acquisition",
            "parameters": [{"name":"acq_id","in":"path","required":True,"schema":{"type":"integer"}}],
            "responses": {"200": {"description": "OK"}}}},
        "/api/acquisitions/{acq_id}/metadata": {"patch": {"tags": ["Acquisitions"],
            "summary": "Modifier poids/qualité/problème",
            "parameters": [{"name":"acq_id","in":"path","required":True,"schema":{"type":"integer"}}],
            "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                "properties": {
                    "poids_g":       {"type": "number"},
                    "qualite":       {"type": "string"},
                    "probleme_type": {"type": "string"},
                    "probleme_desc": {"type": "string"}}}}}},
            "responses": {"200": {"description": "OK"}}}},

        # ── Planification ────────────────────────────────────────────────────
        "/api/planification/check": {
            "post": {
                "tags": ["Planification"], "summary": "Vérifier la disponibilité d'un créneau",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object",
                    "required": ["date_acq","heure_debut","duree_min"],
                    "properties": {
                        "date_acq":    {"type": "string", "format": "date"},
                        "heure_debut": {"type": "string", "example": "10:30"},
                        "duree_min":   {"type": "integer"},
                        "exclude_id":  {"type": "integer"}}}}}},
                "responses": {"200": {"description": "OK"}}
            }
        },
        "/api/planification/conflicts": {"get": {"tags": ["Planification"],
            "summary": "Liste de tous les conflits de créneaux en base",
            "responses": {"200": {"description": "OK"}}}},
        "/api/planification/serie/preview": {"post": {"tags": ["Planification"],
            "summary": "Aperçu d'une série d'acquisitions récurrentes",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object",
                "required": ["projet","animal_id","sequence","date_debut","heure_debut",
                             "duree_min","frequence","nb_repetitions"],
                "properties": {
                    "projet":         {"type": "string"},
                    "animal_id":      {"type": "string"},
                    "sequence":       {"type": "string"},
                    "date_debut":     {"type": "string", "format": "date"},
                    "heure_debut":    {"type": "string"},
                    "duree_min":      {"type": "integer"},
                    "frequence":      {"type": "string",
                                       "enum": ["24h","48h","72h","1sem","2sem","1mois","custom"]},
                    "custom_days":    {"type": "integer"},
                    "nb_repetitions": {"type": "integer", "minimum": 1, "maximum": 50},
                }}}}},
            "responses": {"200": {"description": "OK"}}}},
        "/api/planification/serie/confirm": {"post": {"tags": ["Planification"],
            "summary": "Confirme la création d'une série planifiée",
            "responses": {"200": {"description": "Créé"}}}},

        # ── Pipeline ─────────────────────────────────────────────────────────
        "/api/pipeline/upload": {
            "post": {
                "tags": ["Pipeline"], "summary": "Upload DICOM/NIfTI vers la structure FAIR",
                "requestBody": {"required": True, "content": {"multipart/form-data":
                    {"schema": {"type": "object", "properties": {
                        "files":         {"type": "array", "items": {
                                            "type": "string", "format": "binary"}},
                        "project":       {"type": "string"},
                        "animal_id":     {"type": "string"},
                        "sequence":      {"type": "string"},
                        "date_acq":      {"type": "string", "format": "date"},
                        "espece":        {"type": "string"},
                        "poids_g":       {"type": "number"},
                        "qualite":       {"type": "string"},
                        "probleme_type": {"type": "string"},
                        "probleme_desc": {"type": "string"},
                    }}}}},
                "responses": {"200": {"description": "Upload réussi"},
                              "403": {"description": "Droits insuffisants sur le projet"}}
            }
        },

        # ── Export ───────────────────────────────────────────────────────────
        "/api/export/animaux.csv":               {"get": {"tags": ["Export"],
            "summary": "CSV de tous les animaux", "responses": {"200": {"description": "CSV"}}}},
        "/api/export/acquisitions.csv":          {"get": {"tags": ["Export"],
            "summary": "CSV de toutes les acquisitions", "responses": {"200": {"description": "CSV"}}}},
        "/api/export/projet/{nom}/rapport.csv":  {"get": {"tags": ["Export"],
            "summary": "Rapport complet d'un projet en CSV",
            "parameters": [{"name":"nom","in":"path","required":True,"schema":{"type":"string"}}],
            "responses": {"200": {"description": "CSV"}}}},
        "/api/export/bids/{nom}.zip":            {"get": {"tags": ["Export"],
            "summary": "Export BIDS-like (ZIP) d'un projet",
            "description": ("Dataset BIDS (extension préclinique non officielle) : "
                            "dataset_description.json, participants.tsv, "
                            "sub-X/ses-YYYYMMDD/<modality>/*.nii.gz + sidecars JSON."),
            "parameters": [{"name":"nom","in":"path","required":True,"schema":{"type":"string"}}],
            "responses": {"200": {"description": "Archive ZIP",
                                  "content": {"application/zip": {}}}}}},

        # ── Admin ────────────────────────────────────────────────────────────
        "/api/users":      {"get": {"tags": ["Admin"], "summary": "Liste utilisateurs (admin)",
                                    "responses": {"200": {"description": "OK"}}}},
        "/api/connexions": {"get": {"tags": ["Admin"], "summary": "Journal de connexion (admin)",
                                    "responses": {"200": {"description": "OK"}}}},
        "/api/logs":       {"get": {"tags": ["Admin"], "summary": "Logs pipeline (admin/opérateur)",
                                    "responses": {"200": {"description": "OK"}}}},
    }
}


# ─────────────────────────────────────────────────
#  MÉTRIQUES SYSTÈME — utilisation NAS (admin uniquement)
# ─────────────────────────────────────────────────
#
# Lit /proc/stat, /proc/meminfo, /proc/uptime quand disponibles (Linux/Docker).
# Sur macOS dev, ces fichiers n'existent pas → valeurs à 0 pour CPU/RAM.
# shutil.disk_usage fonctionne partout pour l'espace disque du NAS_ROOT.
# ─────────────────────────────────────────────────

# Mémoire du dernier échantillon CPU (pour calculer le delta — CPU% n'a de sens qu'entre 2 mesures)
_cpu_sample_prev: dict[str, float] = {"idle": 0.0, "total": 0.0}
_cpu_sample_lock = threading.Lock()


def _read_proc_stat_cpu() -> tuple[int, int] | None:
    """Retourne (idle_total, total) ou None si /proc/stat indisponible."""
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
        if not line.startswith("cpu "):
            return None
        cols = [int(x) for x in line.split()[1:]]
        # user nice system idle iowait irq softirq steal guest guest_nice
        idle = cols[3] + (cols[4] if len(cols) > 4 else 0)
        total = sum(cols)
        return (idle, total)
    except (FileNotFoundError, OSError, ValueError):
        return None


def _read_proc_meminfo() -> dict[str, int] | None:
    """Retourne un dict {clé: valeur en kB} depuis /proc/meminfo, ou None."""
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, _, rest = line.partition(":")
                try:
                    info[key.strip()] = int(rest.strip().split()[0])
                except (ValueError, IndexError):
                    pass
        return info
    except (FileNotFoundError, OSError):
        return None


def _read_uptime_seconds() -> float | None:
    try:
        with open("/proc/uptime", "r") as f:
            return float(f.read().split()[0])
    except (FileNotFoundError, OSError, ValueError):
        return None


def compute_system_metrics() -> dict:
    """
    Métriques système courantes. Conçu pour fonctionner sur le NAS Synology
    (Linux, container Docker) — fallback gracieux sur macOS dev.
    """
    metrics = {
        "cpu_pct":          None,
        "ram_used_mb":      None,
        "ram_total_mb":     None,
        "ram_pct":          None,
        "disk_used_gb":     None,
        "disk_free_gb":     None,
        "disk_total_gb":    None,
        "disk_pct":         None,
        "uptime_hours":     None,
        "nas_path":         str(NAS_ROOT),
        "hostname":         socket.gethostname(),
        "available":        True,
    }

    # ── CPU (Linux) ────────────────────────────────────────────────────────
    sample = _read_proc_stat_cpu()
    if sample is not None:
        idle, total = sample
        with _cpu_sample_lock:
            prev_idle  = _cpu_sample_prev["idle"]
            prev_total = _cpu_sample_prev["total"]
            _cpu_sample_prev["idle"]  = idle
            _cpu_sample_prev["total"] = total
        d_total = total - prev_total
        d_idle  = idle  - prev_idle
        if prev_total > 0 and d_total > 0:
            metrics["cpu_pct"] = round(100.0 * (1.0 - d_idle / d_total), 1)

    # ── RAM (Linux) ────────────────────────────────────────────────────────
    mem = _read_proc_meminfo()
    if mem and mem.get("MemTotal", 0) > 0:
        total_kb = mem["MemTotal"]
        avail_kb = mem.get("MemAvailable", mem.get("MemFree", 0))
        used_kb  = max(0, total_kb - avail_kb)
        metrics["ram_total_mb"] = total_kb // 1024
        metrics["ram_used_mb"]  = used_kb  // 1024
        metrics["ram_pct"]      = round(100.0 * used_kb / total_kb, 1)

    # ── Disque sur le NAS_ROOT (cross-platform) ────────────────────────────
    try:
        target = NAS_ROOT if NAS_ROOT.exists() else Path("/")
        u = shutil.disk_usage(target)
        gb = 1024 ** 3
        metrics["disk_used_gb"]  = round(u.used  / gb, 2)
        metrics["disk_free_gb"]  = round(u.free  / gb, 2)
        metrics["disk_total_gb"] = round(u.total / gb, 2)
        if u.total > 0:
            metrics["disk_pct"] = round(100.0 * u.used / u.total, 1)
    except OSError:
        pass

    # ── Uptime ─────────────────────────────────────────────────────────────
    up = _read_uptime_seconds()
    if up is not None:
        metrics["uptime_hours"] = round(up / 3600.0, 1)

    return metrics


@app.route("/api/system/metrics")
@login_required
@role_required("admin")
def api_system_metrics():
    """Métriques système live (admin uniquement)."""
    return jsonify(compute_system_metrics())


@app.route("/api/openapi.json")
@login_required
@role_required("admin")
def api_openapi():
    """Spec OpenAPI 3.1 — réservée aux admins (la spec dévoile la surface API)."""
    return jsonify(OPENAPI_SPEC)


@app.route("/api/docs")
@login_required
@role_required("admin")
def api_docs():
    """Swagger UI + page d'intro stylée — réservé aux admins."""
    return render_template("api_docs.html")


@app.route("/api/logs")
@login_required
def api_logs():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM pipeline_logs ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


# ─────────────────────────────────────────────────
#  API — UTILISATEURS (admin only)
# ─────────────────────────────────────────────────

@app.route("/api/users")
@login_required
@role_required("admin")
def api_users():
    with get_db() as db:
        rows = db.execute("SELECT id,username,role FROM users ORDER BY role,username").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users", methods=["POST"])
@login_required
@role_required("admin")
def api_add_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role     = data.get("role", "chercheur")

    if not username or not password:
        return jsonify({"error": "username et password requis"}), 400
    pw_err = validate_password(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400
    if role not in ("admin", "operateur", "chercheur"):
        return jsonify({"error": "Rôle invalide"}), 400
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (username,password,role) VALUES (?,?,?)",
                (username, hash_pw(password), role)
            )
            db.commit()
        return jsonify({"ok": True, "username": username, "role": role}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": f"L'utilisateur « {username} » existe déjà"}), 409

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
@role_required("admin")
def api_delete_user(user_id):
    if user_id == current_user.id:
        return jsonify({"error": "Impossible de supprimer son propre compte"}), 400
    with get_db() as db:
        row = db.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return jsonify({"error": "Utilisateur introuvable"}), 404
        if row["role"] == "admin" and current_user.username != "admin":
            return jsonify({"error": "Seul le compte « admin » peut supprimer un autre administrateur"}), 403
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        db.commit()
    return jsonify({"ok": True, "deleted": row["username"]})

@app.route("/api/users/<int:user_id>/role", methods=["PATCH"])
@login_required
@role_required("admin")
def api_change_role(user_id):
    data     = request.json or {}
    new_role = data.get("role", "").strip()
    if new_role not in ("admin", "operateur", "chercheur"):
        return jsonify({"error": "Rôle invalide"}), 400
    with get_db() as db:
        row = db.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return jsonify({"error": "Utilisateur introuvable"}), 404
        # Seul le compte 'admin' peut promouvoir/rétrograder un admin
        if (new_role == "admin" or row["role"] == "admin") and current_user.username != "admin":
            return jsonify({"error": "Seul le compte « admin » peut modifier le rôle d'un administrateur"}), 403
        db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
        db.commit()
    return jsonify({"ok": True, "username": row["username"], "role": new_role})


@app.route("/api/users/<int:user_id>/password", methods=["PATCH"])
@login_required
def api_change_password(user_id):
    data       = request.json or {}
    new_pw     = data.get("new_password", "").strip()

    if current_user.id == user_id:
        # Changement de son propre MDP : vérifier l'ancien
        current_pw = data.get("current_password", "").strip()
        with get_db() as db:
            row = db.execute("SELECT password FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not verify_pw(current_pw, row["password"]):
            return jsonify({"error": "Mot de passe actuel incorrect"}), 400
    else:
        # Reset du MDP d'un autre utilisateur : réservé aux admins
        if current_user.role != "admin":
            return jsonify({"error": "Accès refusé"}), 403

        # Vérifier que la cible existe et récupérer son rôle
        with get_db() as db:
            target = db.execute(
                "SELECT role FROM users WHERE id=?", (user_id,)
            ).fetchone()
        if not target:
            return jsonify({"error": "Utilisateur introuvable"}), 404

        # Seul le compte « admin » peut réinitialiser le MDP d'un autre admin
        if target["role"] == "admin" and current_user.username != "admin":
            return jsonify({"error": "Seul le compte « admin » peut réinitialiser "
                                     "le mot de passe d'un autre administrateur"}), 403

        # L'admin doit confirmer son propre mot de passe
        admin_pw = data.get("admin_password", "").strip()
        with get_db() as db:
            me = db.execute(
                "SELECT password, totp_secret, totp_enabled FROM users WHERE id=?",
                (current_user.id,)
            ).fetchone()
        if not me or not verify_pw(admin_pw, me["password"]):
            return jsonify({"error": "Votre mot de passe de confirmation est incorrect"}), 403

        # Si l'admin a le 2FA activé, il doit fournir un code valide
        if me["totp_enabled"]:
            totp_code = data.get("totp_code", "").strip().replace(" ", "")
            if not totp_code:
                return jsonify({"error": "Code 2FA requis pour confirmer cette action",
                                "require_2fa": True}), 403
            if not pyotp.TOTP(me["totp_secret"]).verify(totp_code, valid_window=1):
                return jsonify({"error": "Code 2FA invalide"}), 403

    pw_err = validate_password(new_pw)
    if pw_err:
        return jsonify({"error": pw_err}), 400

    with get_db() as db:
        updated = db.execute(
            "UPDATE users SET password=? WHERE id=?", (hash_pw(new_pw), user_id)
        ).rowcount
        db.commit()
    if not updated:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    log_connexion(current_user.username, "password_change", get_real_ip())
    return jsonify({"ok": True})


@app.route("/profil")
@login_required
def page_profil():
    with get_db() as db:
        row = db.execute(
            "SELECT inactivity_timeout, email, email_verified FROM users WHERE id=?",
            (current_user.id,)
        ).fetchone()
    timeout = int(row['inactivity_timeout']) if row and row['inactivity_timeout'] is not None else 30
    return render_template("profil.html",
        inactivity_timeout = timeout,
        user_email         = row['email'] or "",
        email_verified     = bool(row['email_verified']),
        smtp_configured    = EMAIL_CONFIGURED
    )


# ─────────────────────────────────────────────────
#  LANCEMENT
# ─────────────────────────────────────────────────



# ─────────────────────────────────────────────────
#  PAGE DÉTAIL PROJET
# ─────────────────────────────────────────────────

@app.route("/projet/<nom>")
@login_required
def page_projet_detail(nom):
    with get_db() as db:
        projet = db.execute("SELECT * FROM projets WHERE nom=?", (nom,)).fetchone()
        if not projet:
            return "Projet introuvable", 404

        if not user_can_view_projet(current_user, nom):
            return render_template("403.html"), 403

        filtre_statut = request.args.get("statut", "")
        filtre_espece = request.args.get("espece", "")
        filtre_q      = request.args.get("q", "").strip()

        q      = "SELECT * FROM animaux WHERE projet=?"
        params = [nom]
        if filtre_statut:
            q += " AND statut=?"; params.append(filtre_statut)
        if filtre_espece:
            q += " AND espece=?"; params.append(filtre_espece)
        if filtre_q:
            q += " AND animal_id LIKE ?"; params.append(f"%{filtre_q}%")
        q += " ORDER BY animal_id"

        animaux   = db.execute(q, params).fetchall()
        total_acq = db.execute("SELECT COUNT(*) FROM acquisitions WHERE projet=?", (nom,)).fetchone()[0]
        acq_ok    = db.execute("SELECT COUNT(*) FROM acquisitions WHERE projet=? AND statut='ok'", (nom,)).fetchone()[0]
        especes   = db.execute("SELECT DISTINCT espece FROM animaux WHERE projet=? AND espece IS NOT NULL", (nom,)).fetchall()
        statuts   = db.execute(
            "SELECT statut, COUNT(*) as n FROM animaux WHERE projet=? GROUP BY statut", (nom,)
        ).fetchall()
        dernieres = db.execute(
            "SELECT * FROM acquisitions WHERE projet=? ORDER BY importé_le DESC LIMIT 5", (nom,)
        ).fetchall()

    seq     = projet["seq_par_animal"] or 3
    prevues = projet["nb_animaux_prevus"] * seq
    pct     = round(total_acq / prevues * 100) if prevues else 0
    sm      = {r["statut"]: r["n"] for r in statuts}

    # Droits par projet
    membres        = [dict(m) for m in projet_membres(nom)]
    is_restricted  = projet_is_restricted(nom)
    can_manage     = user_can_manage_projet(current_user, nom)
    my_role_projet = user_projet_role(current_user, nom)

    # Liste des usernames pour l'autocomplete d'ajout membre
    with get_db() as db:
        all_users = [
            r["username"] for r in db.execute("SELECT username FROM users ORDER BY username").fetchall()
        ]

    return render_template("projet_detail.html",
        projet        = dict(projet),
        animaux       = [dict(a) for a in animaux],
        total_acq     = total_acq,
        acq_ok        = acq_ok,
        prevues       = prevues,
        pct           = pct,
        especes       = [e["espece"] for e in especes],
        sm            = sm,
        dernieres     = [dict(d) for d in dernieres],
        filtre_statut = filtre_statut,
        filtre_espece = filtre_espece,
        filtre_q      = filtre_q,
        membres        = membres,
        is_restricted  = is_restricted,
        can_manage     = can_manage,
        my_role_projet = my_role_projet,
        all_users      = all_users,
    )

# ─────────────────────────────────────────────────
#  F8 — TRAÇABILITÉ PAR ANIMAL
# ─────────────────────────────────────────────────

@app.route("/animal/<projet>/<animal_id>")
@login_required
def page_animal(projet, animal_id):
    if not user_can_view_projet(current_user, projet):
        return render_template("403.html"), 403
    with get_db() as db:
        animal  = db.execute(
            "SELECT * FROM animaux WHERE animal_id=? AND projet=?", (animal_id, projet)
        ).fetchone()
        if not animal:
            return "Animal introuvable", 404
        acqs = db.execute(
            "SELECT * FROM acquisitions WHERE animal_id=? AND projet=? ORDER BY date_acq DESC",
            (animal_id, projet)
        ).fetchall()
        commentaires = db.execute(
            "SELECT * FROM commentaires WHERE animal_id=? AND projet=? ORDER BY created_at DESC",
            (animal_id, projet)
        ).fetchall()
        logs = db.execute(
            "SELECT * FROM pipeline_logs WHERE animal_id=? ORDER BY timestamp DESC LIMIT 20",
            (animal_id,)
        ).fetchall()

    dossier_nas = build_animal_folder(animal_id, animal["date_premiere_acq"] or "00000000")

    # Dernière volumétrie par acquisition
    with get_db() as db:
        vols = db.execute(
            "SELECT * FROM volumetries WHERE animal_id=? AND projet=? ORDER BY id DESC",
            (animal_id, projet)
        ).fetchall()

    vol_by_acq = {}
    for v in vols:
        if v["acq_id"] not in vol_by_acq:
            d = dict(v)
            if d.get("resultats"):
                d["resultats"] = json.loads(d["resultats"])
            vol_by_acq[v["acq_id"]] = d

    # Dernière analyse DTI par acquisition
    with get_db() as db:
        dtis = db.execute(
            "SELECT * FROM dti_analyses WHERE animal_id=? AND projet=? ORDER BY id DESC",
            (animal_id, projet)
        ).fetchall()
    dti_by_acq = {}
    for dti in dtis:
        if dti["acq_id"] not in dti_by_acq:
            d = dict(dti)
            if d.get("resultats"):
                d["resultats"] = json.loads(d["resultats"])
            dti_by_acq[dti["acq_id"]] = d

    # Enrichir chaque acquisition avec l'URL NIfTI, la volumétrie et le flag DTI
    acqs_enriched = []
    for a in acqs:
        d = dict(a)
        d["nifti_url"]  = nas_url(d.get("fichier_dest"))
        d["volumetrie"] = vol_by_acq.get(d["id"])
        d["is_dti"]     = is_dti_sequence(d.get("sequence", ""))
        d["dti"]        = dti_by_acq.get(d["id"])
        acqs_enriched.append(d)

    # Statut pipeline : 4 étapes
    has_acqs  = len(acqs_enriched) > 0
    has_nifti = any(a.get("fichier_dest") for a in acqs_enriched)
    has_post  = any(
        a.get("volumetrie") and a["volumetrie"].get("statut") == "ok"
        for a in acqs_enriched
    )
    pipeline = [
        {"label": "IRM",        "sub": "Scan enregistré",   "ok": has_acqs,  "icon": "◎"},
        {"label": "NAS / DICOM","sub": "Fichiers transférés","ok": has_acqs,  "icon": "⬡"},
        {"label": "NIfTI",      "sub": "Conversion faite",  "ok": has_nifti, "icon": "⬢"},
        {"label": "Post-traité","sub": "Volumétrie calculée","ok": has_post,  "icon": "★"},
    ]

    return render_template("animal_detail.html",
        animal       = dict(animal),
        acqs         = acqs_enriched,
        commentaires = [dict(c) for c in commentaires],
        logs         = [dict(l) for l in logs],
        dossier_nas  = dossier_nas,
        projet       = projet,
        pipeline     = pipeline,
    )


@app.route("/api/commentaires", methods=["POST"])
@login_required
def api_add_commentaire():
    data      = request.json or {}
    animal_id = data.get("animal_id", "").strip()
    projet    = data.get("projet", "").strip()
    contenu   = data.get("contenu", "").strip()
    type_     = data.get("type", "note")

    if not animal_id or not projet or not contenu:
        return jsonify({"error": "animal_id, projet et contenu requis"}), 400
    if type_ not in ("note", "incident", "reprise"):
        type_ = "note"

    if not user_can_edit_projet(current_user, projet):
        return jsonify({"error": "Droits insuffisants sur ce projet"}), 403

    with get_db() as db:
        db.execute(
            "INSERT INTO commentaires (animal_id, projet, auteur, type, contenu, created_at) VALUES (?,?,?,?,?,?)",
            (animal_id, projet, current_user.username, type_, contenu, datetime.now().isoformat())
        )
        db.commit()
    return jsonify({"ok": True, "auteur": current_user.username}), 201


@app.route("/api/commentaires/<int:cid>", methods=["DELETE"])
@login_required
@role_required("admin")
def api_delete_commentaire(cid):
    with get_db() as db:
        db.execute("DELETE FROM commentaires WHERE id=?", (cid,))
        db.commit()
    return jsonify({"ok": True})


@app.route("/api/animaux/<projet>/<animal_id>/statut", methods=["PATCH"])
@login_required
@role_required("admin", "operateur")
def api_update_animal_statut(projet, animal_id):
    data   = request.json or {}
    statut = data.get("statut", "")
    if statut not in ("ok", "en_attente", "en_cours", "a_refaire"):
        return jsonify({"error": "Statut invalide"}), 400
    if not user_can_edit_projet(current_user, projet):
        return jsonify({"error": "Droits insuffisants sur ce projet"}), 403
    with get_db() as db:
        updated = db.execute(
            "UPDATE animaux SET statut=? WHERE animal_id=? AND projet=?",
            (statut, animal_id, projet)
        ).rowcount
        db.commit()
    if not updated:
        return jsonify({"error": "Animal introuvable"}), 404
    emit_event("statut_animal", {"animal_id": animal_id, "projet": projet,
                                  "statut": statut, "par": current_user.username})
    return jsonify({"ok": True, "statut": statut})


@app.route("/api/acquisitions/<int:acq_id>/statut", methods=["PATCH"])
@login_required
@role_required("admin", "operateur")
def api_update_statut(acq_id):
    data   = request.json or {}
    statut = data.get("statut", "")
    if statut not in ("ok", "en_attente", "en_cours", "a_refaire"):
        return jsonify({"error": "Statut invalide"}), 400
    with get_db() as db:
        acq = db.execute("SELECT projet FROM acquisitions WHERE id=?", (acq_id,)).fetchone()
        if not acq:
            return jsonify({"error": "Acquisition introuvable"}), 404
        if not user_can_edit_projet(current_user, acq["projet"]):
            return jsonify({"error": "Droits insuffisants sur ce projet"}), 403
        db.execute("UPDATE acquisitions SET statut=? WHERE id=?", (statut, acq_id))
        db.commit()
    emit_event("statut_acq", {"acq_id": acq_id, "statut": statut, "par": current_user.username})
    return jsonify({"ok": True})


@app.route("/api/acquisitions/<int:acq_id>/metadata", methods=["PATCH"])
@login_required
def api_update_acq_metadata(acq_id):
    """
    Met à jour les métadonnées enrichies (poids, qualité, problème) d'une
    acquisition. Exige le droit d'édition sur le projet correspondant.
    """
    with get_db() as db:
        acq = db.execute("SELECT projet FROM acquisitions WHERE id=?", (acq_id,)).fetchone()
    if not acq:
        return jsonify({"error": "Acquisition introuvable"}), 404
    if not user_can_edit_projet(current_user, acq["projet"]):
        return jsonify({"error": "Droits insuffisants sur ce projet"}), 403

    data = request.json or {}
    fields = {}

    if "poids_g" in data:
        v = data["poids_g"]
        if v in (None, ""):
            fields["poids_g"] = None
        else:
            try:
                v = float(v)
                if v <= 0 or v > 5000:
                    return jsonify({"error": "Poids invalide (0–5000 g)"}), 400
                fields["poids_g"] = v
            except (ValueError, TypeError):
                return jsonify({"error": "Poids doit être un nombre"}), 400

    if "qualite" in data:
        v = data["qualite"] or None
        if v not in (None, "excellente", "bonne", "degradee", "inutilisable"):
            return jsonify({"error": "Qualité invalide"}), 400
        fields["qualite"] = v

    if "probleme_type" in data:
        v = data["probleme_type"] or None
        if v not in (None, "aucun", "positionnement", "artefact", "mouvement", "materiel", "autre"):
            return jsonify({"error": "Type de problème invalide"}), 400
        fields["probleme_type"] = v

    if "probleme_desc" in data:
        v = data["probleme_desc"] or None
        if v and len(v) > 1000:
            return jsonify({"error": "Description trop longue (max 1000)"}), 400
        fields["probleme_desc"] = v

    if not fields:
        return jsonify({"error": "Aucun champ à mettre à jour"}), 400

    set_clause = ", ".join(f"{k}=?" for k in fields)
    params = list(fields.values()) + [acq_id]
    with get_db() as db:
        db.execute(f"UPDATE acquisitions SET {set_clause} WHERE id=?", params)
        db.commit()
    return jsonify({"ok": True, "updated": list(fields.keys())})


# ─────────────────────────────────────────────────
#  VOLUMÉTRIE — calcul K-means 3 classes
# ─────────────────────────────────────────────────

def is_dti_sequence(seq: str) -> bool:
    """Détecte si une séquence est de type DTI / DWI."""
    if not seq:
        return False
    return bool(re.search(r'\b(dti|dwi|diffusion|diff)\b', seq.lower()))


def normalize_path_for_storage(path: str) -> str:
    """
    Normalise un chemin Windows/UNC en chemin POSIX pour stockage en DB.
    Exemples :
      C:\\Users\\... → /Users/...
      \\\\server\\share\\IRM\\... → //server/share/IRM/...  (conservé intact)
      /Users/... → /Users/...  (inchangé)
    """
    p = str(path).replace("\\", "/")
    # Windows drive letter : C:/... → /C:/... puis on retire le préfixe
    if len(p) >= 2 and p[1] == ":":
        p = "/" + p
    return p


def _resolve_by_marker(stored_path: str) -> str | None:
    """
    Résout un chemin stocké (hôte ou Windows) vers le chemin réel via le marqueur 'structured/'.
    Gère les UNC paths (//server/share/...) et les chemins Windows (C:/...).
    Retourne None si non résolu.
    """
    s = normalize_path_for_storage(stored_path)
    marker = "structured/"
    idx = s.find(marker)
    if idx != -1:
        candidate = NAS_ROOT / s[idx + len(marker):]
        if candidate.exists():
            return str(candidate)
    return None


def resolve_nifti_path(stored_path: str) -> str:
    """Convertit un chemin NIfTI stocké en DB vers le chemin réel du container."""
    p = Path(stored_path)
    if p.exists():
        return str(p)
    result = _resolve_by_marker(stored_path)
    if result:
        return result
    raise FileNotFoundError(f"NIfTI introuvable : {stored_path}")


def compute_volumetry_bg(vol_id: int, fichier_dest: str):
    """Thread background : segmentation K-means 3 classes sur le NIfTI."""
    try:
        import nibabel as nib
        import numpy as np
        from sklearn.cluster import KMeans

        from scipy import ndimage as ndi

        now        = datetime.now().isoformat()
        real_path  = resolve_nifti_path(fichier_dest)
        img        = nib.load(real_path)
        data = np.asarray(img.dataobj, dtype=np.float32)

        zooms     = img.header.get_zooms()[:3]
        voxel_vol = float(zooms[0]) * float(zooms[1]) * float(zooms[2])
        if voxel_vol <= 0:
            voxel_vol = 1.0

        # ── Étape 1 : masque grossier (fond = voxels quasi nuls) ──────────────
        nonzero = data[data > 0]
        if nonzero.size < 10:
            raise ValueError("Volume trop petit ou données vides — vérifiez le fichier NIfTI")
        threshold_bg = float(np.percentile(nonzero, 3))
        rough_mask   = data > threshold_bg

        # ── Étape 2 : garder uniquement la plus grande composante connexe ─────
        labeled, n_components = ndi.label(rough_mask)
        if n_components == 0:
            raise ValueError("Aucune région détectée dans l'image")
        component_sizes = ndi.sum(rough_mask, labeled, range(1, n_components + 1))
        largest = int(np.argmax(component_sizes)) + 1
        brain_mask = labeled == largest

        # ── Étape 3 : boucher les trous internes (cavités ventriculaires etc.) ─
        brain_mask = ndi.binary_fill_holes(brain_mask)
        n_brain    = int(brain_mask.sum())

        brain_vals = data[brain_mask].reshape(-1, 1)

        # ── Étape 4 : K-means 4 classes ───────────────────────────────────────
        # Classe 0 → LCR / hypo-intense  (liquide céphalo-rachidien)
        # Classe 1 → Substance grise      (intensité intermédiaire basse)
        # Classe 2 → Substance blanche    (intensité intermédiaire haute)
        # Classe 3 → Vaisseaux / artefacts (hyper-intense)
        km      = KMeans(n_clusters=4, n_init=10, random_state=42)
        km.fit(brain_vals)
        labels  = km.labels_
        centers = km.cluster_centers_.flatten()
        order   = np.argsort(centers)  # du plus sombre au plus lumineux

        tissue_names = {
            order[0]: "LCR / ventricules",
            order[1]: "Substance grise",
            order[2]: "Substance blanche",
            order[3]: "Vaisseaux / hyper-intenses",
        }

        tissus = []
        for i in range(4):
            cnt = int((labels == i).sum())
            tissus.append({
                "nom":     tissue_names[i],
                "voxels":  cnt,
                "vol_mm3": round(cnt * voxel_vol, 2),
                "pct":     round(cnt / n_brain * 100, 1),
            })

        results = {
            "voxel_size_mm3": round(voxel_vol, 4),
            "brain_voxels":   n_brain,
            "brain_vol_mm3":  round(n_brain * voxel_vol, 2),
            "shape":          list(data.shape),
            "tissus":         tissus,
        }

        # CSV sauvegardé à côté du NIfTI (chemin réel dans le container)
        csv_path = Path(real_path).parent / "volumetrie.csv"
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Tissu", "Voxels", "Volume (mm³)", "% cerveau"])
            w.writerow(["Cerveau total", n_brain, results["brain_vol_mm3"], "100.0"])
            for t in tissus:
                w.writerow([t["nom"], t["voxels"], t["vol_mm3"], t["pct"]])

        with get_db() as db:
            db.execute(
                "UPDATE volumetries SET statut='ok', resultats=?, fichier_csv=?, calcule_le=? WHERE id=?",
                (json.dumps(results), str(csv_path), now, vol_id)
            )
            db.commit()

    except Exception as exc:
        with get_db() as db:
            db.execute(
                "UPDATE volumetries SET statut='erreur', erreur=? WHERE id=?",
                (str(exc), vol_id)
            )
            db.commit()


@app.route("/api/volumetrie/<int:acq_id>", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_start_volumetrie(acq_id):
    with get_db() as db:
        acq = db.execute("SELECT * FROM acquisitions WHERE id=?", (acq_id,)).fetchone()
        if not acq:
            return jsonify({"error": "Acquisition introuvable"}), 404
        if not acq["fichier_dest"]:
            return jsonify({"error": "Aucun fichier NIfTI associé à cette acquisition"}), 400

        # Éviter un double calcul simultané
        existing = db.execute(
            "SELECT id, statut FROM volumetries WHERE acq_id=? ORDER BY id DESC LIMIT 1",
            (acq_id,)
        ).fetchone()
        if existing and existing["statut"] == "en_cours":
            return jsonify({"error": "Calcul déjà en cours", "vol_id": existing["id"]}), 409

        cur = db.execute(
            "INSERT INTO volumetries (animal_id, projet, acq_id, sequence, statut, methode, calcule_par) "
            "VALUES (?,?,?,?,?,?,?)",
            (acq["animal_id"], acq["projet"], acq_id, acq["sequence"],
             "en_cours", "kmeans_3classes", current_user.username)
        )
        vol_id = cur.lastrowid
        db.commit()

    threading.Thread(target=compute_volumetry_bg, args=(vol_id, acq["fichier_dest"]), daemon=True).start()
    return jsonify({"ok": True, "vol_id": vol_id, "statut": "en_cours"})


@app.route("/api/volumetrie/status/<int:vol_id>")
@login_required
def api_volumetrie_status(vol_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM volumetries WHERE id=?", (vol_id,)).fetchone()
    if not row:
        return jsonify({"error": "Introuvable"}), 404
    d = dict(row)
    if d.get("resultats"):
        d["resultats"] = json.loads(d["resultats"])
    return jsonify(d)


@app.route("/api/volumetrie/<int:vol_id>/csv")
@login_required
def api_volumetrie_csv(vol_id):
    with get_db() as db:
        row = db.execute(
            "SELECT fichier_csv, animal_id, sequence, resultats FROM volumetries WHERE id=?", (vol_id,)
        ).fetchone()
    if not row:
        return "Volumétrie introuvable", 404

    p = Path(row["fichier_csv"]) if row["fichier_csv"] else None
    if p and p.exists():
        return send_from_directory(
            str(p.parent), p.name,
            as_attachment=True,
            download_name=f"volumetrie_{row['animal_id']}_{row['sequence']}.csv"
        )

    if not row["resultats"]:
        return "Résultats non disponibles", 404
    results = json.loads(row["resultats"])
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Tissu", "Voxels", "Volume (mm³)", "% cerveau"])
    w.writerow(["Cerveau total", results["brain_voxels"], results["brain_vol_mm3"], "100.0"])
    for t in results.get("tissus", []):
        w.writerow([t["nom"], t["voxels"], t["vol_mm3"], t["pct"]])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="volumetrie_{row["animal_id"]}_{row["sequence"]}.csv"'
    return resp


# ─────────────────────────────────────────────────
#  DTI — analyse diffusion (FSL dtifit ou commandes manuelles)
# ─────────────────────────────────────────────────

def compute_dti_bg(dti_id: int, fichier_dest: str):
    """
    Thread background : tente de lancer FSL dtifit.
    Si FSL n'est pas installé, génère les commandes à exécuter manuellement.
    Cherche automatiquement les fichiers bvec/bval compagnons.
    """
    import shutil as _shutil
    now = datetime.now().isoformat()
    try:
        real_path = resolve_nifti_path(fichier_dest)
        nii_dir   = Path(real_path).parent
        stem      = Path(real_path).stem.replace(".nii", "")

        # Chercher bvec/bval compagnons (.bvec/.bval ou .bvecs/.bvals)
        bvec_path = next((nii_dir / f for f in [f"{stem}.bvec", f"{stem}.bvecs",
                          "grad.bvec", "bvecs"] if (nii_dir / f).exists()), None)
        bval_path = next((nii_dir / f for f in [f"{stem}.bval", f"{stem}.bvals",
                          "grad.bval", "bvals"] if (nii_dir / f).exists()), None)

        out_prefix = str(nii_dir / f"dti_{stem}")
        has_fsl    = bool(_shutil.which("dtifit"))

        cmd_mask = f"bet {real_path} {nii_dir}/{stem}_brain -m -f 0.2"
        cmd_dti  = (f"dtifit --data={real_path} --out={out_prefix} "
                    f"--mask={nii_dir}/{stem}_brain_mask.nii.gz "
                    f"--bvecs={bvec_path or '<fichier.bvec>'} "
                    f"--bvals={bval_path or '<fichier.bval>'}")
        cmds = f"{cmd_mask}\n{cmd_dti}"

        resultats = {
            "fsl_disponible":  has_fsl,
            "bvec_trouve":     str(bvec_path) if bvec_path else None,
            "bval_trouve":     str(bval_path) if bval_path else None,
            "sortie_prefix":   out_prefix,
            "fichier_nifti":   real_path,
        }

        if has_fsl and bvec_path and bval_path:
            import subprocess
            # Étape 1 : masque cerveau avec bet
            mask_nii = nii_dir / f"{stem}_brain_mask.nii.gz"
            subprocess.run(["bet", real_path, str(nii_dir / f"{stem}_brain"),
                            "-m", "-f", "0.2"],
                           capture_output=True, timeout=300)
            # Étape 2 : dtifit
            ret = subprocess.run(
                ["dtifit", f"--data={real_path}", f"--out={out_prefix}",
                 f"--mask={mask_nii}", f"--bvecs={bvec_path}", f"--bvals={bval_path}"],
                capture_output=True, timeout=600
            )
            if ret.returncode == 0:
                # Lire FA moyen si disponible
                fa_file = Path(f"{out_prefix}_FA.nii.gz")
                if fa_file.exists():
                    import nibabel as nib, numpy as np
                    fa_img  = nib.load(str(fa_file))
                    fa_data = np.asarray(fa_img.dataobj, dtype=np.float32)
                    mask    = fa_data > 0
                    resultats["FA_mean"] = round(float(fa_data[mask].mean()), 4) if mask.any() else None
                resultats["fsl_execute"] = True
                statut = "ok"
            else:
                resultats["fsl_execute"] = False
                resultats["stderr"]      = ret.stderr.decode()[:500]
                statut = "ok"  # commandes générées même si dtifit a échoué
        else:
            statut = "ok"  # commandes manuelles générées

        with get_db() as db:
            db.execute(
                "UPDATE dti_analyses SET statut=?, commandes=?, resultats=?, calcule_le=? WHERE id=?",
                (statut, cmds, json.dumps(resultats), now, dti_id)
            )
            db.commit()

    except Exception as exc:
        with get_db() as db:
            db.execute(
                "UPDATE dti_analyses SET statut='erreur', erreur=? WHERE id=?",
                (str(exc), dti_id)
            )
            db.commit()


@app.route("/api/dti/<int:acq_id>", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_start_dti(acq_id):
    with get_db() as db:
        acq = db.execute("SELECT * FROM acquisitions WHERE id=?", (acq_id,)).fetchone()
        if not acq:
            return jsonify({"error": "Acquisition introuvable"}), 404
        if not acq["fichier_dest"]:
            return jsonify({"error": "Aucun fichier NIfTI associé"}), 400
        if not is_dti_sequence(acq["sequence"] or ""):
            return jsonify({"error": "Cette acquisition n'est pas identifiée comme DTI"}), 400

        existing = db.execute(
            "SELECT id, statut FROM dti_analyses WHERE acq_id=? ORDER BY id DESC LIMIT 1",
            (acq_id,)
        ).fetchone()
        if existing and existing["statut"] == "en_cours":
            return jsonify({"error": "Analyse déjà en cours", "dti_id": existing["id"]}), 409

        cur = db.execute(
            "INSERT INTO dti_analyses (animal_id, projet, acq_id, sequence, statut, calcule_par) "
            "VALUES (?,?,?,?,?,?)",
            (acq["animal_id"], acq["projet"], acq_id, acq["sequence"],
             "en_cours", current_user.username)
        )
        dti_id = cur.lastrowid
        db.commit()

    threading.Thread(target=compute_dti_bg, args=(dti_id, acq["fichier_dest"]), daemon=True).start()
    return jsonify({"ok": True, "dti_id": dti_id, "statut": "en_cours"})


@app.route("/api/dti/status/<int:dti_id>")
@login_required
def api_dti_status(dti_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM dti_analyses WHERE id=?", (dti_id,)).fetchone()
    if not row:
        return jsonify({"error": "Introuvable"}), 404
    d = dict(row)
    if d.get("resultats"):
        d["resultats"] = json.loads(d["resultats"])
    return jsonify(d)


@app.route("/nas/<path:filepath>")
@login_required
def serve_nas_file(filepath):
    """Sert les fichiers NIfTI du NAS pour NiiVue (viewer JS)."""
    safe = (NAS_ROOT / filepath).resolve()
    if not str(safe).startswith(str(NAS_ROOT.resolve())):
        return "Accès refusé", 403
    return send_from_directory(NAS_ROOT, filepath)


def nas_url(abs_path: str) -> str | None:
    """
    Convertit un chemin NIfTI (local, hôte Docker ou UNC Windows) en URL /nas/…
    Gère les chemins POSIX, Windows (C:\\...) et UNC (\\\\server\\share\\...).
    """
    if not abs_path:
        return None
    try:
        rel = Path(abs_path).resolve().relative_to(NAS_ROOT.resolve())
        return f"/nas/{rel.as_posix()}"
    except ValueError:
        p = normalize_path_for_storage(abs_path)
        marker = "structured/"
        idx = p.find(marker)
        if idx != -1:
            return f"/nas/{p[idx + len(marker):]}"
        return None


# ─────────────────────────────────────────────────
#  2FA — TOTP (Google Authenticator, Aegis, etc.)
# ─────────────────────────────────────────────────

@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    user_id = session.get("_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))

    ip = get_real_ip()

    if request.method == "POST":
        secs = get_lockout_remaining(ip)
        if secs > 0:
            return render_template("login_2fa.html",
                error=f"Trop de tentatives. Réessayez dans {(secs+59)//60} min.")

        code = request.form.get("code", "").strip().replace(" ", "")
        with get_db() as db:
            row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

        if row and row["totp_secret"]:
            import pyotp as _pyotp
            if _pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1):
                session.pop("_2fa_user_id",  None)
                session.pop("_2fa_username", None)
                login_user(User(row["id"], row["username"], row["role"]))
                session['_last_activity']      = datetime.utcnow().isoformat()
                session['_inactivity_timeout'] = int(row['inactivity_timeout']) if row['inactivity_timeout'] is not None else 30
                log_connexion(row["username"], "login", ip)
                return redirect(url_for("dashboard"))

        log_connexion(session.get("_2fa_username", "—"), "login_failed", ip)
        return render_template("login_2fa.html", error="Code incorrect ou expiré.")

    return render_template("login_2fa.html",
        username=session.get("_2fa_username", ""))


@app.route("/api/2fa/setup")
@login_required
def api_2fa_setup():
    """Génère un secret TOTP et l'URI de provisioning pour le QR code."""
    import pyotp as _pyotp
    secret = _pyotp.random_base32()
    uri    = _pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.username, issuer_name="IRM.FAIR"
    )
    session["_totp_pending"] = secret
    return jsonify({"secret": secret, "uri": uri})


@app.route("/api/2fa/enable", methods=["POST"])
@login_required
def api_2fa_enable():
    """Active le 2FA après validation d'un code TOTP."""
    import pyotp as _pyotp
    data   = request.json or {}
    code   = data.get("code", "").strip()
    secret = session.get("_totp_pending")
    if not secret:
        return jsonify({"error": "Aucune configuration en attente — rechargez la page"}), 400
    if not _pyotp.TOTP(secret).verify(code, valid_window=1):
        return jsonify({"error": "Code incorrect — vérifiez l'heure de votre appareil"}), 400
    with get_db() as db:
        db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
                   (secret, current_user.id))
        db.commit()
    session.pop("_totp_pending", None)
    log_connexion(current_user.username, "2fa_enabled", get_real_ip())
    return jsonify({"ok": True})


@app.route("/api/2fa/disable", methods=["POST"])
@login_required
def api_2fa_disable():
    """Désactive le 2FA après vérification du mot de passe courant."""
    data = request.json or {}
    pw   = data.get("password", "")
    with get_db() as db:
        row = db.execute("SELECT password FROM users WHERE id=?", (current_user.id,)).fetchone()
    if not row or not verify_pw(pw, row["password"]):
        return jsonify({"error": "Mot de passe incorrect"}), 400
    with get_db() as db:
        db.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?",
                   (current_user.id,))
        db.commit()
    log_connexion(current_user.username, "2fa_disabled", get_real_ip())
    return jsonify({"ok": True})


@app.route("/api/2fa/status")
@login_required
def api_2fa_status():
    with get_db() as db:
        row = db.execute(
            "SELECT totp_enabled FROM users WHERE id=?", (current_user.id,)
        ).fetchone()
    return jsonify({"enabled": bool(row and row["totp_enabled"])})


# ─────────────────────────────────────────────────
#  EXPLORATEUR NAS
# ─────────────────────────────────────────────────

@app.route("/nas-explorer")
@login_required
@role_required("admin", "operateur")
def page_nas_explorer():
    return render_template("nas_explorer.html")


@app.route("/api/nas/browse")
@login_required
def api_nas_browse():
    """Liste le contenu d'un répertoire du NAS (chemin relatif à NAS_ROOT)."""
    rel    = request.args.get("path", "").strip("/").replace("\\", "/")
    target = (NAS_ROOT / rel).resolve() if rel else NAS_ROOT.resolve()

    # Protection traversée de répertoire
    try:
        target.relative_to(NAS_ROOT.resolve())
    except ValueError:
        return jsonify({"error": "Accès refusé"}), 403

    if not target.exists():
        return jsonify({"error": "Répertoire introuvable"}), 404

    entries = []
    try:
        for item in sorted(target.iterdir(),
                           key=lambda x: (x.is_file(), x.name.lower())):
            try:
                st = item.stat()
                e  = {
                    "name":     item.name,
                    "type":     "file" if item.is_file() else "dir",
                    "path":     item.relative_to(NAS_ROOT).as_posix(),
                    "size":     st.st_size if item.is_file() else None,
                    "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                }
                if item.is_dir():
                    try:
                        e["n"] = sum(1 for _ in item.iterdir())
                    except OSError:
                        e["n"] = 0
                entries.append(e)
            except OSError:
                pass
    except PermissionError:
        return jsonify({"error": "Permission refusée"}), 403

    parent = str(Path(rel).parent.as_posix()) if rel else None
    if parent in (".", ""):
        parent = None

    return jsonify({"path": rel, "entries": entries, "parent": parent})


# ─────────────────────────────────────────────────
#  ALIAS UTILISATEUR (arborescence personnalisée)
# ─────────────────────────────────────────────────

@app.route("/api/aliases")
@login_required
def api_get_aliases():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM user_aliases WHERE user_id=? ORDER BY real_path",
            (current_user.id,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/aliases", methods=["POST"])
@login_required
def api_set_alias():
    data       = request.json or {}
    real_path  = data.get("real_path",  "").strip()
    alias_name = data.get("alias_name", "").strip()
    if not real_path or not alias_name:
        return jsonify({"error": "real_path et alias_name requis"}), 400
    now = datetime.now().isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO user_aliases (user_id, real_path, alias_name, created_at) "
            "VALUES (?,?,?,?) ON CONFLICT(user_id,real_path) DO UPDATE SET alias_name=excluded.alias_name",
            (current_user.id, real_path, alias_name, now)
        )
        db.commit()
    return jsonify({"ok": True, "real_path": real_path, "alias_name": alias_name})


@app.route("/api/aliases/<int:alias_id>", methods=["DELETE"])
@login_required
def api_delete_alias(alias_id):
    with get_db() as db:
        db.execute("DELETE FROM user_aliases WHERE id=? AND user_id=?",
                   (alias_id, current_user.id))
        db.commit()
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────
#  MOT DE PASSE OUBLIÉ
# ─────────────────────────────────────────────────

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("forgot_password.html")

    ip       = get_real_ip()
    username = request.form.get("username", "").strip()
    if not username:
        return render_template("forgot_password.html", error="Identifiant requis.")

    # Anti-brute-force sur le formulaire de reset aussi
    secs = get_lockout_remaining(ip)
    if secs > 0:
        return render_template("forgot_password.html",
            error=f"Trop de tentatives. Réessayez dans {(secs+59)//60} min.")

    with get_db() as db:
        user = db.execute(
            "SELECT id, username FROM users WHERE username=?", (username,)
        ).fetchone()

    # Toujours afficher le même message (éviter l'énumération d'utilisateurs)
    success_msg = ("Si ce compte existe, un lien de réinitialisation a été envoyé "
                   "à l'administrateur ou par email.")

    if not user:
        # Logger la tentative échouée
        log_connexion(username, "reset_failed", ip)
        return render_template("forgot_password.html", success=success_msg)

    # Invalider les anciens tokens
    with get_db() as db:
        db.execute("UPDATE password_resets SET used=1 WHERE user_id=? AND used=0", (user["id"],))
        db.commit()

    token      = secrets.token_urlsafe(32)
    now        = datetime.now()
    expires_at = (now + timedelta(hours=1)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO password_resets (user_id, username, token, created_at, expires_at) "
            "VALUES (?,?,?,?,?)",
            (user["id"], user["username"], token, now.isoformat(), expires_at)
        )
        db.commit()

    log_connexion(username, "reset_requested", ip)

    # Envoyer par email uniquement — le lien n'est JAMAIS affiché dans la page
    with get_db() as db:
        u = db.execute(
            "SELECT email, email_verified FROM users WHERE id=?", (user["id"],)
        ).fetchone()
    email_addr = (u["email"] or "") if u else ""
    email_verified = bool(u["email_verified"]) if u else False

    if EMAIL_CONFIGURED and email_addr and email_verified:
        send_reset_email(email_addr, user["username"], token)

    return render_template("forgot_password.html", success=success_msg)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    now = datetime.now().isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM password_resets WHERE token=? AND used=0 AND expires_at>?",
            (token, now)
        ).fetchone()

    if not row:
        return render_template("reset_password.html",
            error="Lien invalide ou expiré. Faites une nouvelle demande.")

    if request.method == "GET":
        return render_template("reset_password.html", token=token, username=row["username"])

    ip     = get_real_ip()
    new_pw = request.form.get("password", "").strip()
    conf   = request.form.get("confirm",  "").strip()

    if new_pw != conf:
        return render_template("reset_password.html", token=token, username=row["username"],
            error="Les mots de passe ne correspondent pas.")

    pw_err = validate_password(new_pw)
    if pw_err:
        return render_template("reset_password.html", token=token, username=row["username"],
            error=pw_err)

    with get_db() as db:
        db.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(new_pw), row["user_id"]))
        db.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
        db.commit()

    log_connexion(row["username"], "password_reset", ip)
    return render_template("reset_password.html", done=True)


# ─────────────────────────────────────────────────
#  CALENDRIER IRM (#6)
# ─────────────────────────────────────────────────

@app.route("/calendrier")
@login_required
@role_required("admin", "operateur")
def page_calendrier():
    now    = datetime.now()
    year   = int(request.args.get("year",  now.year))
    month  = int(request.args.get("month", now.month))
    projet = request.args.get("projet", "")

    # Borner year/month
    year  = max(2020, min(2050, year))
    month = max(1,    min(12,   month))

    # Navigation prev/next
    prev_dt = datetime(year, month, 1) - timedelta(days=1)
    next_dt = datetime(year, month, 28) + timedelta(days=4)
    next_dt = next_dt.replace(day=1)

    month_str = f"{year}-{month:02d}"
    q, params = "SELECT * FROM acquisitions WHERE date_acq LIKE ?", [f"{month_str}%"]
    if projet:
        q += " AND projet=?"; params.append(projet)
    q += " ORDER BY date_acq"

    with get_db() as db:
        acqs_raw = db.execute(q, params).fetchall()
        projets  = db.execute("SELECT DISTINCT nom FROM projets ORDER BY nom").fetchall()
        # Totaux par jour pour le mois
        all_acqs = db.execute(
            "SELECT date_acq, projet, animal_id, sequence, statut FROM acquisitions "
            "WHERE date_acq LIKE ? ORDER BY date_acq",
            (f"{month_str}%",)
        ).fetchall()

    # Grouper par jour
    from collections import defaultdict
    acqs_by_day: dict[int, list] = defaultdict(list)
    for a in all_acqs:
        d = a["date_acq"]
        if d and len(d) >= 10:
            try:
                day = int(d[8:10])
                acqs_by_day[day].append(dict(a))
            except ValueError:
                pass

    # Grille calendrier (liste de semaines, chaque semaine = 7 jours, 0 = hors mois)
    cal_weeks = _cal.monthcalendar(year, month)

    # Couleurs par projet (rotation)
    proj_colors = ["teal", "blue", "amber", "red"]
    proj_list   = [p["nom"] for p in projets]
    color_map   = {p: proj_colors[i % len(proj_colors)] for i, p in enumerate(proj_list)}

    month_names_fr = [
        "", "Janvier", "Février", "Mars", "Avril", "Mai", "Juin",
        "Juillet", "Août", "Septembre", "Octobre", "Novembre", "Décembre"
    ]

    with get_db() as db2:
        dernieres_acq = db2.execute(
            "SELECT * FROM acquisitions ORDER BY date_acq DESC LIMIT 20"
        ).fetchall()

    return render_template("calendrier.html",
        year=year, month=month,
        month_name=month_names_fr[month],
        cal_weeks=cal_weeks,
        acqs_by_day=dict(acqs_by_day),
        color_map=color_map,
        projets=proj_list,
        projet=projet,
        prev_year=prev_dt.year, prev_month=prev_dt.month,
        next_year=next_dt.year, next_month=next_dt.month,
        today_day=now.day if (now.year == year and now.month == month) else -1,
        dernieres_acq=[dict(r) for r in dernieres_acq],
    )


# ─────────────────────────────────────────────────
#  GESTIONNAIRES D'ERREURS
# ─────────────────────────────────────────────────

@app.errorhandler(404)
def error_404(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Ressource introuvable"}), 404
    return render_template("404.html"), 404

@app.errorhandler(403)
def error_403(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Accès refusé"}), 403
    return render_template("403.html"), 403

@app.errorhandler(500)
def error_500(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Erreur interne du serveur"}), 500
    return render_template("500.html"), 500


# ─────────────────────────────────────────────────
#  VÉRIFICATIONS SÉCURITÉ AU DÉMARRAGE
# ─────────────────────────────────────────────────
_DEFAULT_SECRET = "dev_secret_change_in_prod"
if app.secret_key == _DEFAULT_SECRET:
    print("\n" + "!"*60, flush=True)
    print("  ⚠  AVERTISSEMENT SÉCURITÉ CRITIQUE", flush=True)
    print("  SECRET_KEY = valeur par défaut de développement.", flush=True)
    print("  Les sessions peuvent être forgées par n'importe qui.", flush=True)
    print("  → Définissez SECRET_KEY dans les variables d'environnement.", flush=True)
    print("!"*60 + "\n", flush=True)

if not RECAPTCHA_SITE_KEY or not RECAPTCHA_SECRET_KEY:
    print("[IRM FAIR] reCAPTCHA désactivé — définissez RECAPTCHA_SITE_KEY "
          "et RECAPTCHA_SECRET_KEY pour l'activer.", flush=True)

# Appelé au démarrage quel que soit le mode (gunicorn ou python3 app.py)
init_db()
_ensure_scheduler()   # boucle de rappels J-1 (envoi 8h chaque jour)

if __name__ == "__main__":
    try:
        _ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        _ip = "127.0.0.1"
    print("=" * 50)
    print("  IRM FAIR — Backend Flask")
    print(f"  DB    : {DB_PATH.resolve()}")
    print(f"  NAS   : {NAS_ROOT.resolve()}")
    print(f"  Running on http://{_ip}:5000")
    print(f"  (host) http://localhost:5001")
    print("  Comptes démo : admin/admin123  nicolas/nico123")
    print("=" * 50)
    app.run(host="0.0.0.0", debug=True, port=5000)
