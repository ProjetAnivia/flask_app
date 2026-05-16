"""
app.py — Backend Flask IRM Préclinique
Équipe 3 : Interface Web & Backend API

Lancer :
  pip install flask flask-login
  python3 app.py

Accéder : http://localhost:5000
Comptes démo : admin/admin123  |  operateur/op123  |  chercheur/ch123
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, make_response, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from pathlib import Path
import json, sqlite3, hashlib, os, re, csv, io, socket, threading
from datetime import datetime

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
        """)

        # Migration douce — ajoute les colonnes si absentes (SQLite ne supporte pas IF NOT EXISTS sur ALTER)
        for col_sql in [
            "ALTER TABLE projets ADD COLUMN seq_par_animal INTEGER DEFAULT 3",
        ]:
            try:
                db.execute(col_sql)
            except sqlite3.OperationalError:
                pass

        # Utilisateurs démo (toujours insérés si absents)
        users_demo = [
            ("admin",      hash_pw("admin123"),   "admin"),
            ("nicolas",    hash_pw("nico123"),     "admin"),
            ("clemence",   hash_pw("clem123"),     "admin"),
            ("florent",    hash_pw("flo123"),      "operateur"),
            ("chercheur",  hash_pw("ch123"),       "chercheur"),
        ]
        for u in users_demo:
            db.execute("INSERT OR IGNORE INTO users (username,password,role) VALUES (?,?,?)", u)

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

        db.commit()

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def validate_password(pw: str) -> str | None:
    """Retourne un message d'erreur ou None si le mot de passe est valide."""
    if len(pw) < 8:
        return "Mot de passe trop court (8 caractères minimum)"
    if not re.search(r"[A-Z]", pw):
        return "Le mot de passe doit contenir au moins une majuscule"
    if not re.search(r"[0-9]", pw):
        return "Le mot de passe doit contenir au moins un chiffre"
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
#  ROUTES AUTH
# ─────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, hash_pw(password))
            ).fetchone()
        if row:
            login_user(User(row["id"], row["username"], row["role"]))
            with get_db() as db2:
                db2.execute(
                    "INSERT INTO connexions_log (username, action, ip, timestamp) VALUES (?,?,?,?)",
                    (row["username"], "login", request.remote_addr, datetime.now().isoformat())
                )
                db2.commit()
            return redirect(url_for("dashboard"))
        # Log de l'échec (username fourni peut ne pas exister)
        with get_db() as db2:
            db2.execute(
                "INSERT INTO connexions_log (username, action, ip, timestamp) VALUES (?,?,?,?)",
                (username or "—", "login_failed", request.remote_addr, datetime.now().isoformat())
            )
            db2.commit()
        return render_template("login.html", error="Identifiants incorrects")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    with get_db() as db:
        db.execute(
            "INSERT INTO connexions_log (username, action, ip, timestamp) VALUES (?,?,?,?)",
            (current_user.username, "logout", request.remote_addr, datetime.now().isoformat())
        )
        db.commit()
    logout_user()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────
#  ROUTES INTERFACE — dynamiques
# ─────────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    # Filtres F4
    f_projet    = request.args.get("projet", "")
    f_statut    = request.args.get("statut", "")
    f_date_from = request.args.get("date_from", "")
    f_date_to   = request.args.get("date_to", "")
    f_user      = request.args.get("user", "")

    with get_db() as db:
        nb_animaux  = db.execute("SELECT COUNT(*) FROM animaux").fetchone()[0]
        nb_acq      = db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0]
        nb_doublons = db.execute("SELECT COUNT(*) FROM pipeline_logs WHERE statut='DUPLICATE_SKIPPED'").fetchone()[0]
        projets_raw    = db.execute("SELECT * FROM projets ORDER BY nom").fetchall()
        acq_par_projet = db.execute("SELECT projet, COUNT(*) as n FROM acquisitions GROUP BY projet").fetchall()
        statuts_raw    = db.execute(
            "SELECT projet, statut, COUNT(*) as n FROM animaux GROUP BY projet, statut"
        ).fetchall()

        # Acquisitions filtrées pour le tableau du bas
        q, params = "SELECT * FROM acquisitions WHERE 1=1", []
        if f_projet:
            q += " AND projet=?"; params.append(f_projet)
        if f_statut:
            q += " AND statut=?"; params.append(f_statut)
        if f_date_from:
            q += " AND date_acq >= ?"; params.append(f_date_from)
        if f_date_to:
            q += " AND date_acq <= ?"; params.append(f_date_to)
        if f_user:
            q += " AND \"importé_par\"=?"; params.append(f_user)
        q += " ORDER BY date_acq DESC LIMIT 20"
        dernieres_acq = db.execute(q, params).fetchall()

        utilisateurs = db.execute(
            "SELECT DISTINCT \"importé_par\" FROM acquisitions WHERE \"importé_par\" IS NOT NULL ORDER BY 1"
        ).fetchall()

    acq_map    = {r["projet"]: r["n"] for r in acq_par_projet}
    statut_map = {}
    for s in statuts_raw:
        statut_map.setdefault(s["projet"], {})[s["statut"]] = s["n"]

    projets = []
    for p in projets_raw:
        if f_projet and p["nom"] != f_projet:
            continue
        seq   = p["seq_par_animal"] if p["seq_par_animal"] else 3
        prevues = p["nb_animaux_prevus"] * seq
        faites  = acq_map.get(p["nom"], 0)
        pct     = round(faites / prevues * 100) if prevues else 0
        sm      = statut_map.get(p["nom"], {})
        projets.append({
            "nom": p["nom"], "resp": p["resp"],
            "prevues": prevues, "faites": faites, "pct": pct,
            "couleur": "teal" if pct >= 75 else ("amber" if pct >= 40 else "red"),
            "nb_ok":      sm.get("ok", 0),
            "nb_attente": sm.get("en_attente", 0),
            "nb_cours":   sm.get("en_cours", 0),
            "nb_refaire": sm.get("a_refaire", 0),
        })

    return render_template("dashboard.html",
        nb_animaux=nb_animaux, nb_acq=nb_acq, nb_doublons=nb_doublons,
        nas_to=11.2, nas_max=16, projets=projets,
        dernieres_acq=[dict(r) for r in dernieres_acq],
        utilisateurs=[u["importé_par"] for u in utilisateurs],
        projets_all=[p["nom"] for p in projets_raw],
        f_projet=f_projet, f_statut=f_statut,
        f_date_from=f_date_from, f_date_to=f_date_to, f_user=f_user,
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
    return render_template("animaux.html",
        animaux=[dict(a) for a in animaux], projets=[p["nom"] for p in projets],
        total=total, filtre_projet=filtre_projet, filtre_statut=filtre_statut)

@app.route("/projets")
@login_required
def page_projets():
    with get_db() as db:
        projets_raw    = db.execute("SELECT * FROM projets ORDER BY nom").fetchall()
        acq_par_projet = db.execute("SELECT projet, COUNT(*) as n FROM acquisitions GROUP BY projet").fetchall()
        statuts        = db.execute("SELECT projet, statut, COUNT(*) as n FROM animaux GROUP BY projet, statut").fetchall()
    acq_map   = {r["projet"]: r["n"] for r in acq_par_projet}
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
                        "couleur": "teal" if pct >= 75 else ("amber" if pct >= 40 else "red"),
                        "nb_ok": sm.get("ok", 0), "nb_attente": sm.get("en_attente", 0),
                        "nb_cours": sm.get("en_cours", 0), "nb_refaire": sm.get("a_refaire", 0)})
    return render_template("projets.html", projets=projets)

@app.route("/import")
@login_required
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
def page_logs():
    with get_db() as db:
        logs       = db.execute("SELECT * FROM pipeline_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
        nb_erreurs = db.execute("SELECT COUNT(*) FROM pipeline_logs WHERE statut='ERROR'").fetchone()[0]
        last_ts    = db.execute("SELECT timestamp FROM pipeline_logs ORDER BY timestamp DESC LIMIT 1").fetchone()
    return render_template("logs.html",
        logs=[dict(l) for l in logs], nb_erreurs=nb_erreurs,
        last_ts=last_ts["timestamp"][:16] if last_ts else "—")

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
        db.commit()
    return jsonify({"ok": True, "deleted": nom})


# ─────────────────────────────────────────────────
#  API — ANIMAUX
# ─────────────────────────────────────────────────

@app.route("/api/animaux")
@login_required
def api_animaux():
    projet = request.args.get("projet")
    statut = request.args.get("statut")
    q = "SELECT * FROM animaux WHERE 1=1"
    params = []
    if projet:
        q += " AND projet=?"; params.append(projet)
    if statut:
        q += " AND statut=?"; params.append(statut)
    with get_db() as db:
        rows = db.execute(q, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/animaux/<animal_id>")
@login_required
def api_animal_detail(animal_id):
    with get_db() as db:
        animal = db.execute("SELECT * FROM animaux WHERE animal_id=?", (animal_id,)).fetchone()
        acqs   = db.execute("SELECT * FROM acquisitions WHERE animal_id=?", (animal_id,)).fetchall()
    if not animal:
        return jsonify({"error": "Animal introuvable"}), 404
    return jsonify({"animal": dict(animal), "acquisitions": [dict(a) for a in acqs]})


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
    return jsonify([dict(r) for r in rows])

@app.route("/api/acquisitions", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_add_acquisition():
    data = request.json
    required = ["animal_id", "projet", "sequence", "date_acq"]
    if not all(k in data for k in required):
        return jsonify({"error": "Champs manquants"}), 400
    with get_db() as db:
        db.execute(
            "INSERT INTO acquisitions (animal_id,projet,sequence,date_acq,statut,importé_par,importé_le) VALUES (?,?,?,?,?,?,?)",
            (data["animal_id"], data["projet"], data["sequence"],
             data["date_acq"], data.get("statut","ok"),
             current_user.username, datetime.now().isoformat())
        )
        db.execute(
            "UPDATE animaux SET nb_acquisitions=nb_acquisitions+1 WHERE animal_id=?",
            (data["animal_id"],)
        )
        db.commit()
    return jsonify({"ok": True}), 201


# ─────────────────────────────────────────────────
#  IMPORT DICOM → NIfTI (upload fichier local)
# ─────────────────────────────────────────────────

import shutil, tempfile
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {".dcm", ".ima", ".nii", ".nii.gz", ""}

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


@app.route("/api/pipeline/upload", methods=["POST"])
@login_required
@role_required("admin", "operateur")
def api_upload_file():
    """Upload d'un fichier DICOM ou NIfTI depuis le navigateur."""
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier reçu"}), 400

    f         = request.files["file"]
    project   = request.form.get("project", "").strip()
    animal_id = request.form.get("animal_id", "").strip()
    sequence  = request.form.get("sequence", "SEQ").strip()
    date_acq  = request.form.get("date_acq", datetime.now().strftime("%Y-%m-%d")).strip()

    if not project or not animal_id:
        return jsonify({"error": "project et animal_id requis"}), 400
    if f.filename == "":
        return jsonify({"error": "Nom de fichier vide"}), 400

    filename = secure_filename(f.filename)

    # Sauvegarder temporairement
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / filename
        f.save(str(tmp_path))

        try:
            result = process_uploaded_file(
                tmp_path, project, animal_id, sequence, date_acq
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Enregistrer en base
    with get_db() as db:
        db.execute(
            """INSERT INTO acquisitions
               (animal_id, projet, sequence, date_acq, fichier_dest, md5, statut, importé_par, importé_le)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (result["meta"]["animal_id"], project, result["meta"]["sequence"],
             result["meta"]["date_acq"], result["dest"], result["md5"],
             "ok", current_user.username, datetime.now().isoformat())
        )
        # Mettre à jour ou créer l'animal
        existing = db.execute(
            "SELECT id FROM animaux WHERE animal_id=? AND projet=?",
            (result["meta"]["animal_id"], project)
        ).fetchone()
        if existing:
            db.execute(
                "UPDATE animaux SET nb_acquisitions=nb_acquisitions+1, statut='en_cours' WHERE animal_id=? AND projet=?",
                (result["meta"]["animal_id"], project)
            )
        else:
            db.execute(
                """INSERT INTO animaux (animal_id, espece, projet, date_premiere_acq, nb_acquisitions, statut)
                   VALUES (?,?,?,?,?,?)""",
                (result["meta"]["animal_id"], "—", project,
                 result["meta"]["date_acq"], 1, "en_cours")
            )
        # Log pipeline
        db.execute(
            """INSERT INTO pipeline_logs (timestamp, source, dest, animal_id, sequence, statut, md5, erreur)
               VALUES (?,?,?,?,?,?,?,?)""",
            (datetime.now().isoformat(), filename, result["dest"],
             result["meta"]["animal_id"], result["meta"]["sequence"],
             "IMPORTED", result["md5"], None)
        )
        db.commit()

    return jsonify({
        "ok":      True,
        "message": f"Fichier importé ({result['file_type']})",
        "dest":    result["dest_rel"],
        "md5":     result["md5"],
    })


# ─────────────────────────────────────────────────
#  API — LOGS
# ─────────────────────────────────────────────────

@app.route("/planification")
@login_required
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

    return render_template("planification.html",
        projets=projets_plan,
        alertes=alertes,
        nb_alertes=len(alertes),
    )


@app.route("/connexions")
@login_required
@role_required("admin")
def page_connexions():
    filtre_action   = request.args.get("action", "")
    filtre_username = request.args.get("username", "").strip()
    q      = "SELECT * FROM connexions_log WHERE 1=1"
    params = []
    if filtre_action:
        q += " AND action=?"; params.append(filtre_action)
    if filtre_username:
        q += " AND username LIKE ?"; params.append(f"%{filtre_username}%")
    q += " ORDER BY timestamp DESC LIMIT 200"
    with get_db() as db:
        logs    = db.execute(q, params).fetchall()
        nb_fail = db.execute("SELECT COUNT(*) FROM connexions_log WHERE action='login_failed'").fetchone()[0]
        total   = db.execute("SELECT COUNT(*) FROM connexions_log").fetchone()[0]
    return render_template("connexions.html",
        logs=[dict(l) for l in logs],
        nb_fail=nb_fail, total=total,
        filtre_action=filtre_action, filtre_username=filtre_username)


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
    cols = ["id", "username", "action", "ip", "timestamp"]
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
    # Un utilisateur peut changer uniquement son propre mot de passe,
    # un admin peut changer celui de n'importe qui.
    if current_user.role != "admin" and current_user.id != user_id:
        return jsonify({"error": "Accès refusé"}), 403

    data        = request.json or {}
    new_pw      = data.get("new_password", "").strip()
    current_pw  = data.get("current_password", "").strip()

    # Si l'utilisateur change son propre MDP, vérifier l'ancien
    if current_user.id == user_id:
        with get_db() as db:
            row = db.execute("SELECT password FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or row["password"] != hash_pw(current_pw):
            return jsonify({"error": "Mot de passe actuel incorrect"}), 400

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

    with get_db() as db:
        db.execute(
            "INSERT INTO connexions_log (username, action, ip, timestamp) VALUES (?,?,?,?)",
            (current_user.username, "password_change", request.remote_addr, datetime.now().isoformat())
        )
        db.commit()
    return jsonify({"ok": True})


@app.route("/profil")
@login_required
def page_profil():
    return render_template("profil.html")


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
    )

# ─────────────────────────────────────────────────
#  F8 — TRAÇABILITÉ PAR ANIMAL
# ─────────────────────────────────────────────────

@app.route("/animal/<projet>/<animal_id>")
@login_required
def page_animal(projet, animal_id):
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

    # Enrichir chaque acquisition avec l'URL NIfTI et la volumétrie
    acqs_enriched = []
    for a in acqs:
        d = dict(a)
        d["nifti_url"]  = nas_url(d.get("fichier_dest"))
        d["volumetrie"] = vol_by_acq.get(d["id"])
        acqs_enriched.append(d)

    return render_template("animal_detail.html",
        animal       = dict(animal),
        acqs         = acqs_enriched,
        commentaires = [dict(c) for c in commentaires],
        logs         = [dict(l) for l in logs],
        dossier_nas  = dossier_nas,
        projet       = projet,
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
    with get_db() as db:
        updated = db.execute(
            "UPDATE animaux SET statut=? WHERE animal_id=? AND projet=?",
            (statut, animal_id, projet)
        ).rowcount
        db.commit()
    if not updated:
        return jsonify({"error": "Animal introuvable"}), 404
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
        db.execute("UPDATE acquisitions SET statut=? WHERE id=?", (statut, acq_id))
        db.commit()
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────
#  VOLUMÉTRIE — calcul K-means 3 classes
# ─────────────────────────────────────────────────

def compute_volumetry_bg(vol_id: int, fichier_dest: str):
    """Thread background : segmentation K-means 3 classes sur le NIfTI."""
    try:
        import nibabel as nib
        import numpy as np
        from sklearn.cluster import KMeans

        now  = datetime.now().isoformat()
        img  = nib.load(fichier_dest)
        data = np.asarray(img.dataobj, dtype=np.float32)

        zooms     = img.header.get_zooms()[:3]
        voxel_vol = float(zooms[0]) * float(zooms[1]) * float(zooms[2])
        if voxel_vol <= 0:
            voxel_vol = 1.0

        # Masque cerveau : exclure le fond (intensité quasi nulle)
        nonzero = data[data > 0]
        if nonzero.size < 10:
            raise ValueError("Volume trop petit ou données vides — vérifiez le fichier NIfTI")
        threshold   = float(np.percentile(nonzero, 5))
        brain_mask  = data > threshold
        n_brain     = int(brain_mask.sum())

        brain_vals = data[brain_mask].reshape(-1, 1)

        # K-means 3 classes : LCR, substance grise, substance blanche
        km      = KMeans(n_clusters=3, n_init=10, random_state=42)
        km.fit(brain_vals)
        labels  = km.labels_
        centers = km.cluster_centers_.flatten()
        order   = np.argsort(centers)  # 0=hypointense → 2=hyperintense

        tissue_names = {order[0]: "LCR / fond", order[1]: "Substance grise", order[2]: "Substance blanche"}

        tissus = []
        for i in range(3):
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

        # CSV sauvegardé à côté du NIfTI
        csv_path = Path(fichier_dest).parent / "volumetrie.csv"
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
            "SELECT fichier_csv, animal_id, sequence FROM volumetries WHERE id=?", (vol_id,)
        ).fetchone()
    if not row or not row["fichier_csv"]:
        return "Fichier non disponible", 404
    p = Path(row["fichier_csv"])
    if not p.exists():
        return "Fichier introuvable sur le serveur", 404
    return send_from_directory(
        str(p.parent), p.name,
        as_attachment=True,
        download_name=f"volumetrie_{row['animal_id']}_{row['sequence']}.csv"
    )


@app.route("/nas/<path:filepath>")
@login_required
def serve_nas_file(filepath):
    """Sert les fichiers NIfTI du NAS pour NiiVue (viewer JS)."""
    safe = (NAS_ROOT / filepath).resolve()
    if not str(safe).startswith(str(NAS_ROOT.resolve())):
        return "Accès refusé", 403
    return send_from_directory(NAS_ROOT, filepath)


def nas_url(abs_path: str) -> str | None:
    """Convertit un chemin absolu NIfTI en URL /nas/…"""
    if not abs_path:
        return None
    try:
        rel = Path(abs_path).resolve().relative_to(NAS_ROOT.resolve())
        return f"/nas/{rel}"
    except ValueError:
        # Fallback Docker : le fichier_dest stocke un chemin hôte absolu
        # (ex: /Users/nolan/.../nas_simule/structured/proj/…) mais NAS_ROOT
        # vaut /nas/structured dans le conteneur. On cherche le marqueur "structured/".
        p = str(abs_path).replace("\\", "/")
        marker = "structured/"
        idx = p.find(marker)
        if idx != -1:
            return f"/nas/{p[idx + len(marker):]}"
        return None


if __name__ == "__main__":
    init_db()
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
