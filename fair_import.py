#!/usr/bin/env python3
"""
fair_import.py — Pipeline d'import FAIR pour données IRM précliniques
Équipe 1 : Acquisition, Import & Structuration FAIR

Fonctionnalités :
  - Lecture automatique des métadonnées DICOM / NIfTI
  - Renommage standardisé (convention Linux-safe)
  - Arborescence : projet/animal_date/séquence
  - Détection des doublons (via hash MD5)
  - Journalisation complète (logs JSON + CSV)
  - Rapport de conformité FAIR

Usage :
  python3 fair_import.py --source /chemin/raw --dest /mnt/nas/projets --project NOM_PROJET
"""

import os
import sys
import json
import shutil
import hashlib
import logging
import argparse
import csv
import re
from pathlib import Path
from datetime import datetime

# --- Dépendances optionnelles (graceful import) ---
try:
    import pydicom
    HAS_DICOM = True
except ImportError:
    HAS_DICOM = False
    print("[WARN] pydicom non installé — lecture DICOM désactivée. `pip install pydicom`")

try:
    import nibabel as nib
    HAS_NIBABEL = True
except ImportError:
    HAS_NIBABEL = False
    print("[WARN] nibabel non installé — lecture NIfTI désactivée. `pip install nibabel`")


# ─────────────────────────────────────────────────
#  CONFIGURATION (peut être surchargée via JSON)
# ─────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "naming": {
        "date_format": "%Y%m%d",
        "separator": "_",
        "allowed_chars": r"[^a-zA-Z0-9_\-]",   # tout le reste sera remplacé
        "replacement_char": "-"
    },
    "structure": {
        # projet / animal_dateAcq / séquence_index
        "levels": ["project", "animal_date", "sequence"]
    },
    "extensions": {
        "dicom": [".dcm", ".ima", ""],          # DICOM sans extension = courant
        "nifti": [".nii", ".nii.gz"]
    },
    "log": {
        "dir": "logs",
        "json_log": "pipeline_log.json",
        "csv_log":  "pipeline_log.csv",
        "level": "INFO"
    },
    "duplicate_policy": "skip"   # "skip" | "overwrite" | "rename"
}


# ─────────────────────────────────────────────────
#  UTILITAIRES
# ─────────────────────────────────────────────────

def sanitize_name(name: str, config: dict) -> str:
    """Rend un nom de fichier/dossier compatible Linux (pas d'étoile, d'espace, etc.)."""
    n = config["naming"]
    cleaned = re.sub(n["allowed_chars"], n["replacement_char"], str(name))
    cleaned = cleaned.strip(n["replacement_char"])
    return cleaned if cleaned else "UNKNOWN"


def md5_file(path: Path, chunk_size: int = 8192) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def setup_logging(log_dir: Path, level: str = "INFO") -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("fair_pipeline")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # Console
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Fichier texte
    fh = logging.FileHandler(log_dir / "pipeline.log", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────────
#  LECTURE MÉTADONNÉES
# ─────────────────────────────────────────────────

def read_dicom_metadata(path: Path) -> dict:
    """Extrait les métadonnées clés d'un fichier DICOM."""
    if not HAS_DICOM:
        return {}
    try:
        ds = pydicom.dcmread(str(path), stop_before_pixels=True, force=True)
        return {
            "animal_id":         getattr(ds, "PatientID",          "UNKNOWN"),
            "study_date":        getattr(ds, "StudyDate",           "00000000"),
            "series_description": sanitize_name(
                                  getattr(ds, "SeriesDescription",  "SEQ"), {}
                                  ),
            "series_number":     str(getattr(ds, "SeriesNumber",    "0")),
            "modality":          getattr(ds, "Modality",            "MR"),
            "study_uid":         getattr(ds, "StudyInstanceUID",    ""),
            "series_uid":        getattr(ds, "SeriesInstanceUID",   ""),
            "institution":       getattr(ds, "InstitutionName",     ""),
            "file_type":         "DICOM"
        }
    except Exception as e:
        return {"error": str(e), "file_type": "DICOM"}


def read_nifti_metadata(path: Path) -> dict:
    """Extrait les métadonnées d'un fichier NIfTI (header)."""
    if not HAS_NIBABEL:
        return {}
    try:
        img = nib.load(str(path))
        hdr = img.header
        # NIfTI n'a pas d'ID animal natif → on parse le nom de fichier
        stem = path.stem.replace(".nii", "")
        parts = stem.split("_")
        return {
            "animal_id":          parts[0] if parts else "UNKNOWN",
            "study_date":         "00000000",   # à compléter depuis le contexte
            "series_description": stem,
            "series_number":      "0",
            "modality":           "MR",
            "dims":               list(map(int, hdr.get_data_shape())),
            "voxel_size_mm":      [round(float(v), 4) for v in hdr.get_zooms()[:3]],
            "file_type":          "NIfTI"
        }
    except Exception as e:
        return {"error": str(e), "file_type": "NIfTI"}


def detect_and_read(path: Path, config: dict) -> dict:
    """Détecte le type de fichier et lit les métadonnées."""
    ext = "".join(path.suffixes).lower()
    dicom_exts = config["extensions"]["dicom"]
    nifti_exts  = config["extensions"]["nifti"]

    if ext in nifti_exts or path.suffix.lower() in [".nii"]:
        return read_nifti_metadata(path)
    elif ext in dicom_exts or path.suffix.lower() in [".dcm", ".ima"]:
        return read_dicom_metadata(path)
    else:
        # Tentative DICOM sans extension (fréquent en Paravision)
        if HAS_DICOM:
            meta = read_dicom_metadata(path)
            if "error" not in meta:
                return meta
        return {"file_type": "UNKNOWN", "animal_id": "UNKNOWN",
                "study_date": "00000000", "series_description": path.stem,
                "series_number": "0"}


# ─────────────────────────────────────────────────
#  CONSTRUCTION DE L'ARBORESCENCE
# ─────────────────────────────────────────────────

def sanitize_animal_id(raw: str) -> str:
    """
    Normalise un ID animal selon les conventions du labo :
      - Rat-1, Rat-2, Rat*, animal_VRAI, animal_bis, date_nomanimal
      - Supprime espaces, étoiles, caractères spéciaux Linux-incompatibles
      - Conserve tirets, underscores, alphanumériques
    Exemples :
      "Rat*1"      → "Rat-1"
      "Rat 2"      → "Rat-2"
      "animal_bis" → "animal_bis"   (déjà valide)
      "B 3"        → "B-3"
    """
    # Remplacer étoiles et espaces par tiret
    s = re.sub(r"[* ]+", "-", raw.strip())
    # Supprimer tout caractère non autorisé (garde lettres, chiffres, - et _)
    s = re.sub(r"[^a-zA-Z0-9_\-]", "", s)
    # Nettoyer les tirets multiples
    s = re.sub(r"-{2,}", "-", s).strip("-_")
    return s if s else "UNKNOWN"


def build_dest_path(dest_root: Path, project: str, meta: dict, config: dict) -> Path:
    """
    Construit le chemin destination selon la convention FAIR client :

      <dest_root>/<projet>/<AAAAMMJJ_AnimalID>/<sequence>/

    Exemples :
      structured/tumorigenese/20250312_Rat-1/DTI/
      structured/inflammation/20250401_B3/Anatomique/

    Convention nommage animal (F2) :
      - Rat-1, Rat-2       (numérotation tiret)
      - animal_bis         (suffixe underscore)
      - date_nomanimal     (date + nom)
      Caractères interdits : espaces, étoiles, /, \, :, ?, ", <, >
    """
    project_clean = sanitize_name(project, config)
    animal_clean  = sanitize_animal_id(meta.get("animal_id", "UNKNOWN"))
    date_raw      = meta.get("study_date", "00000000")

    # Normaliser la date en AAAAMMJJ
    date_clean = re.sub(r"[^0-9]", "", date_raw)[:8].ljust(8, "0")

    seq_clean  = sanitize_name(meta.get("series_description", "SEQ"), config)

    # Format : AAAAMMJJ_AnimalID
    animal_date_dir = f"{date_clean}_{animal_clean}"

    return dest_root / project_clean / animal_date_dir / seq_clean


# ─────────────────────────────────────────────────
#  IMPORT D'UN FICHIER
# ─────────────────────────────────────────────────

def import_file(
    src: Path,
    dest_root: Path,
    project: str,
    config: dict,
    known_hashes: dict,
    logger: logging.Logger
) -> dict:
    """
    Importe un fichier :
      1. Lit les métadonnées
      2. Vérifie les doublons (MD5)
      3. Construit le chemin de destination
      4. Copie le fichier
      5. Retourne un enregistrement de log
    """
    record = {
        "timestamp":   datetime.now().isoformat(),
        "source":      str(src),
        "status":      None,
        "dest":        None,
        "file_type":   None,
        "animal_id":   None,
        "study_date":  None,
        "sequence":    None,
        "md5":         None,
        "error":       None
    }

    # 1. Métadonnées
    try:
        meta = detect_and_read(src, config)
    except Exception as e:
        meta = {"file_type": "UNKNOWN", "animal_id": "UNKNOWN",
                "study_date": "00000000", "series_description": src.stem,
                "series_number": "0"}
        record["error"] = f"metadata_read: {e}"

    record.update({
        "file_type":  meta.get("file_type"),
        "animal_id":  meta.get("animal_id"),
        "study_date": meta.get("study_date"),
        "sequence":   meta.get("series_description"),
    })

    # 2. Hash MD5 (détection doublon)
    try:
        file_hash = md5_file(src)
        record["md5"] = file_hash
    except Exception as e:
        record["error"] = f"hash: {e}"
        record["status"] = "ERROR"
        logger.error(f"Impossible de hasher {src}: {e}")
        return record

    policy = config.get("duplicate_policy", "skip")
    if file_hash in known_hashes:
        original = known_hashes[file_hash]
        if policy == "skip":
            record["status"] = "DUPLICATE_SKIPPED"
            logger.warning(f"DOUBLON ignoré : {src.name} == {original}")
            return record
        elif policy == "overwrite":
            logger.warning(f"DOUBLON écrasé : {src.name}")
        # "rename" géré ci-dessous

    # 3. Chemin destination
    dest_dir = build_dest_path(dest_root, project, meta, config)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Gestion rename si doublon
    dest_file = dest_dir / src.name
    if dest_file.exists() and policy == "rename":
        stem = src.stem
        suffix = "".join(src.suffixes)
        dest_file = dest_dir / f"{stem}_dup{datetime.now().strftime('%H%M%S')}{suffix}"

    record["dest"] = str(dest_file)

    # 4. Copie
    try:
        shutil.copy2(src, dest_file)
        known_hashes[file_hash] = str(dest_file)
        record["status"] = "IMPORTED"
        logger.info(f"OK  {src.name} → {dest_file.relative_to(dest_root)}")
    except Exception as e:
        record["status"] = "ERROR"
        record["error"] = f"copy: {e}"
        logger.error(f"Erreur copie {src} → {dest_file}: {e}")

    return record


# ─────────────────────────────────────────────────
#  SCAN DU RÉPERTOIRE SOURCE
# ─────────────────────────────────────────────────

def collect_files(source_dir: Path, config: dict) -> list[Path]:
    """Collecte tous les fichiers DICOM/NIfTI dans le répertoire source (récursif)."""
    all_exts = set(config["extensions"]["dicom"] + config["extensions"]["nifti"])
    files = []
    for p in source_dir.rglob("*"):
        if not p.is_file():
            continue
        ext = "".join(p.suffixes).lower()
        # Inclure si extension connue OU si sans extension (DICOM Paravision)
        if ext in all_exts or p.suffix == "":
            files.append(p)
    return sorted(files)


# ─────────────────────────────────────────────────
#  JOURNALISATION FINALE
# ─────────────────────────────────────────────────

def write_logs(records: list[dict], log_dir: Path, config: dict):
    log_cfg = config["log"]

    # JSON
    json_path = log_dir / log_cfg["json_log"]
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    # CSV
    csv_path = log_dir / log_cfg["csv_log"]
    if records:
        fields = list(records[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(records)

    return json_path, csv_path


def print_summary(records: list[dict], logger: logging.Logger):
    total    = len(records)
    imported = sum(1 for r in records if r["status"] == "IMPORTED")
    skipped  = sum(1 for r in records if r["status"] == "DUPLICATE_SKIPPED")
    errors   = sum(1 for r in records if r["status"] == "ERROR")

    logger.info("=" * 50)
    logger.info(f"  RÉSUMÉ PIPELINE")
    logger.info(f"  Total fichiers traités : {total}")
    logger.info(f"  ✓ Importés             : {imported}")
    logger.info(f"  ~ Doublons ignorés     : {skipped}")
    logger.info(f"  ✗ Erreurs              : {errors}")
    logger.info("=" * 50)


# ─────────────────────────────────────────────────
#  RAPPORT FAIR
# ─────────────────────────────────────────────────

def generate_fair_report(dest_root: Path, records: list[dict], project: str) -> Path:
    """Génère un rapport de conformité FAIR minimaliste en Markdown."""
    imported = [r for r in records if r["status"] == "IMPORTED"]
    animals  = set(r["animal_id"] for r in imported)
    seqs     = set(r["sequence"]  for r in imported)

    report_path = dest_root / project / "FAIR_REPORT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Rapport FAIR — Projet : {project}\n\n")
        f.write(f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Findable (Trouvable)\n")
        f.write(f"- {len(imported)} fichiers importés\n")
        f.write(f"- {len(animals)} animaux uniques : {', '.join(sorted(animals))}\n")
        f.write(f"- {len(seqs)} types de séquences : {', '.join(sorted(seqs))}\n\n")
        f.write("## Accessible\n")
        f.write(f"- Arborescence standardisée sous `{dest_root / project}`\n")
        f.write("- Logs JSON et CSV disponibles dans `logs/`\n\n")
        f.write("## Interoperable\n")
        f.write("- Formats : DICOM, NIfTI (.nii / .nii.gz)\n")
        f.write("- Nommage : snake_case Linux-safe, date ISO 8601\n\n")
        f.write("## Reusable\n")
        f.write("- Traçabilité complète via MD5 + logs horodatés\n")
        f.write("- Métadonnées préservées dans les fichiers originaux\n\n")
        f.write("## Doublons détectés\n")
        dups = [r for r in records if r["status"] == "DUPLICATE_SKIPPED"]
        if dups:
            for d in dups:
                f.write(f"- `{Path(d['source']).name}` (MD5: {d['md5']})\n")
        else:
            f.write("- Aucun doublon détecté.\n")

    return report_path


# ─────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Pipeline FAIR IRM préclinique")
    parser.add_argument("--source",  required=True,  help="Répertoire source (raw data)")
    parser.add_argument("--dest",    required=True,  help="Répertoire destination (NAS)")
    parser.add_argument("--project", required=True,  help="Nom du projet")
    parser.add_argument("--config",  default=None,   help="Fichier config JSON (optionnel)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simule sans copier les fichiers")
    args = parser.parse_args()

    # Config
    config = DEFAULT_CONFIG.copy()
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            user_cfg = json.load(f)
            config.update(user_cfg)

    source_dir = Path(args.source)
    dest_root  = Path(args.dest)
    project    = sanitize_name(args.project, config)

    if not source_dir.exists():
        print(f"[ERREUR] Source introuvable : {source_dir}")
        sys.exit(1)

    # Logs
    log_dir = dest_root / project / config["log"]["dir"]
    logger  = setup_logging(log_dir, config["log"]["level"])
    logger.info(f"Démarrage pipeline FAIR — Projet : {project}")
    logger.info(f"Source : {source_dir}  →  Dest : {dest_root / project}")
    if args.dry_run:
        logger.info("[DRY-RUN] Aucune copie ne sera effectuée.")

    # Collecte
    files = collect_files(source_dir, config)
    logger.info(f"{len(files)} fichier(s) détecté(s)")

    if not files:
        logger.warning("Aucun fichier DICOM/NIfTI trouvé. Vérifiez le répertoire source.")
        sys.exit(0)

    # Import
    records      = []
    known_hashes = {}   # md5 → chemin dest (pour détection doublons cross-session idéalement persisté)

    for src in files:
        if args.dry_run:
            meta = detect_and_read(src, config)
            dest_dir = build_dest_path(dest_root, project, meta, config)
            logger.info(f"[DRY-RUN] {src.name} → {dest_dir.relative_to(dest_root)}/")
            records.append({
                "timestamp": datetime.now().isoformat(),
                "source": str(src), "status": "DRY_RUN",
                "dest": str(dest_dir / src.name),
                "file_type": meta.get("file_type"),
                "animal_id": meta.get("animal_id"),
                "study_date": meta.get("study_date"),
                "sequence": meta.get("series_description"),
                "md5": None, "error": None
            })
        else:
            record = import_file(src, dest_root, project, config, known_hashes, logger)
            records.append(record)

    # Logs finaux
    if not args.dry_run:
        json_p, csv_p = write_logs(records, log_dir, config)
        logger.info(f"Log JSON : {json_p}")
        logger.info(f"Log CSV  : {csv_p}")

        # Rapport FAIR
        report_p = generate_fair_report(dest_root, records, project)
        logger.info(f"Rapport FAIR : {report_p}")

    print_summary(records, logger)


if __name__ == "__main__":
    main()
