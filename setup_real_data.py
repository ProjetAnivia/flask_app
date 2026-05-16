"""
setup_real_data.py — Import réel DICOM → NIfTI + création des projets en base.
Lancer DEPUIS le dossier flask_app : python3 setup_real_data.py
"""
import sqlite3, hashlib, shutil, sys
from pathlib import Path
from datetime import datetime

import pydicom
import nibabel as nib
import numpy as np

# ── Chemins ────────────────────────────────────────────────────────────────────
DB_PATH   = Path("./db/irm_fair.db")
NAS_ROOT  = Path("./nas_simule/structured")
DICOM_SRC = Path("/Users/nolan/Downloads/Echantillon Dicom")

if not DB_PATH.exists():
    sys.exit(f"Base introuvable : {DB_PATH}. Lance d'abord 'python3 app.py' une fois.")
if not DICOM_SRC.exists():
    sys.exit(f"Dossier DICOM introuvable : {DICOM_SRC}")

NAS_ROOT.mkdir(parents=True, exist_ok=True)

# ── Plan des 3 projets ─────────────────────────────────────────────────────────
# Chaque fichier DICOM → 1 acquisition pour l'animal indiqué.
# La date est fictive mais réaliste.
PLAN = [
    {
        "nom": "irm_preclinique",
        "resp": "Nicolas",
        "nb_animaux_prevus": 3,
        "seq_par_animal": 2,
        "animals": [
            {   # emri_small : 10 frames → volume 3D parfait pour NiiVue
                "animal_id": "Rat-1", "espece": "Rat", "date": "20260301",
                "acquisitions": [
                    {"dcm": "emri_small.dcm",                      "seq": "T0_FLASH"},
                    {"dcm": "MR_small.dcm",                        "seq": "T1_SE"},
                ]
            },
            {
                "animal_id": "Rat-2", "espece": "Rat", "date": "20260302",
                "acquisitions": [
                    {"dcm": "MR-SIEMENS-DICOM-WithOverlays.dcm",   "seq": "T0_GRE"},
                    {"dcm": "MR_small_RLE.dcm",                    "seq": "T1_GRE"},
                ]
            },
            {
                "animal_id": "Rat-3", "espece": "Rat", "date": "20260303",
                "acquisitions": [
                    {"dcm": "MR2_UNCI.dcm",                        "seq": "T0_HIRES"},
                ]
            },
        ]
    },
    {
        "nom": "scanner_ct",
        "resp": "Clémence",
        "nb_animaux_prevus": 3,
        "seq_par_animal": 2,
        "animals": [
            {
                "animal_id": "B1", "espece": "Rat", "date": "20260310",
                "acquisitions": [
                    {"dcm": "693_UNCI.dcm",                        "seq": "T0_CT_5mm"},
                    {"dcm": "693_UNCR.dcm",                        "seq": "T1_CT_5mm"},
                ]
            },
            {
                "animal_id": "B2", "espece": "Rat", "date": "20260311",
                "acquisitions": [
                    {"dcm": "CT_small.dcm",                        "seq": "T0_CT"},
                    {"dcm": "eCT_Supplemental.dcm",                "seq": "T1_CT_Suppl"},
                ]
            },
            {
                "animal_id": "B3", "espece": "Souris", "date": "20260312",
                "acquisitions": [
                    {"dcm": "explicit_VR-UN.dcm",                  "seq": "T0_Pancreas"},
                ]
            },
        ]
    },
    {
        "nom": "echographie",
        "resp": "Florent",
        "nb_animaux_prevus": 2,
        "seq_par_animal": 2,
        "animals": [
            {
                "animal_id": "S1", "espece": "Rat", "date": "20260320",
                "acquisitions": [
                    {"dcm": "US1_UNCI.dcm",                        "seq": "T0_Echo"},
                    {"dcm": "US1_UNCR.dcm",                        "seq": "T1_Echo"},
                ]
            },
            {
                "animal_id": "S2", "espece": "Souris", "date": "20260321",
                "acquisitions": [
                    {"dcm": "OBXXXX1A.dcm",                        "seq": "T0_US_Abdo"},
                ]
            },
        ]
    },
]

# ── Conversion DICOM → NIfTI ───────────────────────────────────────────────────
def dcm_to_nifti(dcm_path: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / (dcm_path.stem + ".nii.gz")

    pixels = None
    ds     = None

    # Tentative 1 : lecture normale
    try:
        ds     = pydicom.dcmread(str(dcm_path), force=True)
        pixels = ds.pixel_array.astype(np.float32)
    except Exception as e:
        print(f"  [warn] pixel_array échoué ({e}), tentative gdcm…")

    # Tentative 2 : gdcm si dispo
    if pixels is None:
        try:
            import gdcm  # noqa
            pydicom.config.pixel_data_handlers = ["gdcm"]
            ds     = pydicom.dcmread(str(dcm_path), force=True)
            pixels = ds.pixel_array.astype(np.float32)
        except Exception as e:
            print(f"  [warn] gdcm échoué ({e}), fallback zéros…")

    # Fallback : tableau de zéros
    if pixels is None:
        try:
            ds   = pydicom.dcmread(str(dcm_path), stop_before_pixels=True, force=True)
            rows = int(getattr(ds, "Rows", 64))
            cols = int(getattr(ds, "Columns", 64))
        except Exception:
            rows, cols = 64, 64
        pixels = np.zeros((rows, cols), dtype=np.float32)

    # Mise en forme : (rows, cols) → (rows, cols, 1) | (frames, rows, cols) → (rows, cols, frames)
    if pixels.ndim == 2:
        data = pixels[:, :, np.newaxis]
    elif pixels.ndim == 3:
        data = np.transpose(pixels, (1, 2, 0))   # (frames,r,c) → (r,c,frames)
    elif pixels.ndim == 4:
        # (frames, r, c, channels) → prendre canal 0
        data = np.transpose(pixels[:, :, :, 0], (1, 2, 0))
    else:
        data = pixels.reshape(64, 64, 1)

    # Normalisation 0-255 pour une meilleure visualisation NiiVue
    mn, mx = data.min(), data.max()
    if mx > mn:
        data = (data - mn) / (mx - mn) * 1000.0

    # Affine depuis métadonnées
    affine = np.eye(4)
    if ds is not None:
        try:
            ps = ds.PixelSpacing
            st = float(getattr(ds, "SliceThickness", 1.0))
            affine = np.diag([float(ps[0]), float(ps[1]), st, 1.0])
        except Exception:
            pass

    img = nib.Nifti1Image(data, affine)
    nib.save(img, str(out_path))
    return out_path

# ── Fonctions DB ───────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def folder_name(animal_id, date):
    """AAAAMMJJ_AnimalID"""
    import re
    animal_clean = re.sub(r"[* ]+", "-", str(animal_id).strip())
    animal_clean = re.sub(r"[^a-zA-Z0-9_\-]", "", animal_clean).strip("-_")
    return f"{date}_{animal_clean}"

# ── Main ───────────────────────────────────────────────────────────────────────
DEMO_PROJETS = ("tumorigenese", "inflammation", "neuro_dev")

print("=" * 60)
print("  IRM FAIR — Import réel DICOM")
print("=" * 60)

with get_db() as db:
    # 0. S'assurer que toutes les tables existent (init partielle si besoin)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS projets (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE NOT NULL, resp TEXT, nb_animaux_prevus INTEGER DEFAULT 0, seq_par_animal INTEGER DEFAULT 3);
        CREATE TABLE IF NOT EXISTS animaux (id INTEGER PRIMARY KEY AUTOINCREMENT, animal_id TEXT NOT NULL, espece TEXT, projet TEXT, date_premiere_acq TEXT, nb_acquisitions INTEGER DEFAULT 0, statut TEXT DEFAULT 'en_attente');
        CREATE TABLE IF NOT EXISTS acquisitions (id INTEGER PRIMARY KEY AUTOINCREMENT, animal_id TEXT NOT NULL, projet TEXT NOT NULL, sequence TEXT, date_acq TEXT, fichier_dest TEXT, md5 TEXT, statut TEXT DEFAULT 'ok', "importé_par" TEXT, "importé_le" TEXT);
        CREATE TABLE IF NOT EXISTS pipeline_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source TEXT, dest TEXT, animal_id TEXT, sequence TEXT, statut TEXT, md5 TEXT, erreur TEXT);
        CREATE TABLE IF NOT EXISTS commentaires (id INTEGER PRIMARY KEY AUTOINCREMENT, animal_id TEXT NOT NULL, projet TEXT NOT NULL, auteur TEXT NOT NULL, type TEXT DEFAULT 'note', contenu TEXT NOT NULL, created_at TEXT NOT NULL);
    """)
    # Migration douce : ajouter seq_par_animal si absent
    try:
        db.execute("ALTER TABLE projets ADD COLUMN seq_par_animal INTEGER DEFAULT 3")
    except Exception:
        pass
    db.commit()

    # 1. Supprimer les projets fictifs et toutes leurs données
    print("\n[1/3] Suppression des projets fictifs…")
    for nom in DEMO_PROJETS:
        anim = db.execute("SELECT animal_id FROM animaux WHERE projet=?", (nom,)).fetchall()
        for a in anim:
            db.execute("DELETE FROM commentaires WHERE animal_id=? AND projet=?", (a["animal_id"], nom))
            db.execute("DELETE FROM acquisitions WHERE animal_id=? AND projet=?",  (a["animal_id"], nom))
            db.execute("DELETE FROM pipeline_logs WHERE animal_id=?", (a["animal_id"],))
        db.execute("DELETE FROM animaux WHERE projet=?",  (nom,))
        db.execute("DELETE FROM projets WHERE nom=?",      (nom,))
        print(f"  ✓ Projet «{nom}» supprimé ({len(anim)} animaux)")
    db.commit()

    # Supprimer les dossiers NAS fictifs
    for nom in DEMO_PROJETS:
        p = NAS_ROOT / nom
        if p.exists():
            shutil.rmtree(p)
            print(f"  ✓ Dossier NAS {p} supprimé")

    # 2. Créer les nouveaux projets
    print("\n[2/3] Création des projets réels…")
    for proj in PLAN:
        try:
            db.execute(
                "INSERT INTO projets (nom, resp, nb_animaux_prevus, seq_par_animal) VALUES (?,?,?,?)",
                (proj["nom"], proj["resp"], proj["nb_animaux_prevus"], proj["seq_par_animal"])
            )
            print(f"  ✓ Projet «{proj['nom']}» créé")
        except sqlite3.IntegrityError:
            print(f"  ~ Projet «{proj['nom']}» existe déjà")
        (NAS_ROOT / proj["nom"]).mkdir(parents=True, exist_ok=True)
    db.commit()

    # 3. Importer les animaux et DICOM
    print("\n[3/3] Import DICOM → NIfTI…")
    now = datetime.now().isoformat()
    errors = []

    for proj in PLAN:
        for ani in proj["animals"]:
            animal_id  = ani["animal_id"]
            espece     = ani["espece"]
            date_acq   = ani["date"]
            dossier    = folder_name(animal_id, date_acq)

            # Créer/màj animal en base
            existing = db.execute(
                "SELECT id FROM animaux WHERE animal_id=? AND projet=?",
                (animal_id, proj["nom"])
            ).fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO animaux (animal_id,espece,projet,date_premiere_acq,nb_acquisitions,statut) VALUES (?,?,?,?,?,?)",
                    (animal_id, espece, proj["nom"], date_acq, 0, "en_cours")
                )

            print(f"\n  Animal {animal_id} / {proj['nom']}")

            for acq_def in ani["acquisitions"]:
                dcm_file = DICOM_SRC / acq_def["dcm"]
                seq      = acq_def["seq"]

                if not dcm_file.exists():
                    print(f"    [SKIP] {acq_def['dcm']} introuvable")
                    errors.append(f"{acq_def['dcm']} introuvable")
                    continue

                # Dossier destination
                dest_dir = NAS_ROOT / proj["nom"] / dossier / seq
                dest_dir.mkdir(parents=True, exist_ok=True)

                print(f"    {acq_def['dcm']} → {seq}…", end=" ", flush=True)
                try:
                    nifti_path = dcm_to_nifti(dcm_file, dest_dir)
                    import hashlib as hlib
                    md5 = hlib.md5(open(nifti_path, "rb").read()).hexdigest()
                    size_kb = nifti_path.stat().st_size // 1024

                    # Enregistrer acquisition
                    db.execute(
                        """INSERT INTO acquisitions
                           (animal_id,projet,sequence,date_acq,fichier_dest,md5,statut,importé_par,importé_le)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (animal_id, proj["nom"], seq, date_acq,
                         str(nifti_path.resolve()), md5, "ok", "nicolas", now)
                    )
                    db.execute(
                        "UPDATE animaux SET nb_acquisitions=nb_acquisitions+1, statut='en_cours' WHERE animal_id=? AND projet=?",
                        (animal_id, proj["nom"])
                    )
                    db.execute(
                        """INSERT INTO pipeline_logs (timestamp,source,dest,animal_id,sequence,statut,md5)
                           VALUES (?,?,?,?,?,?,?)""",
                        (now, str(dcm_file), str(nifti_path.resolve()),
                         animal_id, seq, "IMPORTED", md5)
                    )
                    print(f"OK ({size_kb} Ko, shape {nib.load(str(nifti_path)).shape})")
                except Exception as e:
                    print(f"ERREUR — {e}")
                    errors.append(f"{acq_def['dcm']}: {e}")

            # Mettre le statut OK si toutes les acquisitions sont là
            nb = db.execute(
                "SELECT COUNT(*) FROM acquisitions WHERE animal_id=? AND projet=? AND statut='ok'",
                (animal_id, proj["nom"])
            ).fetchone()[0]
            if nb >= proj["seq_par_animal"]:
                db.execute(
                    "UPDATE animaux SET statut='ok' WHERE animal_id=? AND projet=?",
                    (animal_id, proj["nom"])
                )

    db.commit()

print("\n" + "=" * 60)
print("  Import terminé.")
if errors:
    print(f"  {len(errors)} avertissement(s) :")
    for e in errors:
        print(f"    - {e}")
print("  Relance l'appli Flask pour voir les données.")
print("=" * 60)
