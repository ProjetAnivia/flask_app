#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  backup.sh — Sauvegarde de la base SQLite IRM FAIR
#
#  Usage manuel :
#    bash backup.sh
#
#  Automatiser avec le Planificateur de tâches DSM (ou cron) :
#    0 3 * * *  bash /volume1/IRM_preclinique/app/backup.sh
# ─────────────────────────────────────────────────────────────────────────────

DB_PATH="${DB_DIR:-/volume1/IRM_preclinique/db}/irm_fair.db"
BACKUP_DIR="/volume1/IRM_preclinique/db/backups"
KEEP_DAYS=30   # nombre de jours de rétention

if [ ! -f "$DB_PATH" ]; then
  echo "❌  Base introuvable : $DB_PATH"
  exit 1
fi

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DEST="$BACKUP_DIR/irm_fair_${TIMESTAMP}.db"

# Copie atomique via sqlite3 .backup (cohérente même en production)
if command -v sqlite3 &>/dev/null; then
  sqlite3 "$DB_PATH" ".backup '$DEST'"
else
  cp "$DB_PATH" "$DEST"
fi

echo "✔  Sauvegarde créée : $DEST  ($(du -sh "$DEST" | cut -f1))"

# ── Nettoyage des sauvegardes trop anciennes ──────────────────────────────────
DELETED=$(find "$BACKUP_DIR" -name "irm_fair_*.db" -mtime +"$KEEP_DAYS" -print -delete | wc -l)
if [ "$DELETED" -gt 0 ]; then
  echo "→  $DELETED sauvegarde(s) expirée(s) supprimée(s) (>${KEEP_DAYS}j)."
fi

# ── Résumé des sauvegardes disponibles ───────────────────────────────────────
COUNT=$(find "$BACKUP_DIR" -name "irm_fair_*.db" | wc -l)
echo "→  $COUNT sauvegarde(s) conservée(s) dans $BACKUP_DIR"
