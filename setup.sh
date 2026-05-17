#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  setup.sh — Premier déploiement IRM FAIR sur NAS Synology
#  Lancer avec : bash setup.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

COMPOSE_FILE="docker-compose.nas.yml"
DATA_ROOT="/volume1/IRM_preclinique"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║         IRM FAIR — Setup initial             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Vérification de Docker ─────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "❌  Docker n'est pas installé ou pas dans le PATH."
  echo "    Installez Container Manager depuis le Package Center DSM."
  exit 1
fi
echo "✔  Docker détecté : $(docker --version)"

# ── 2. Création de l'arborescence NAS ────────────────────────────────────────
echo ""
echo "→ Création des dossiers sous $DATA_ROOT …"
mkdir -p "$DATA_ROOT"/{structured,raw,db,logs}
echo "✔  Dossiers créés."

# ── 3. Génération de la clé secrète ──────────────────────────────────────────
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
  || openssl rand -hex 32)
echo ""
echo "→ Clé secrète générée."

# ── 4. Mise à jour du docker-compose.nas.yml ─────────────────────────────────
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "❌  $COMPOSE_FILE introuvable. Lancez ce script depuis le dossier de l'app."
  exit 1
fi

# Remplace le placeholder par la vraie clé
sed -i "s|CHANGE_THIS_SECRET_KEY_IN_PRODUCTION|$SECRET_KEY|g" "$COMPOSE_FILE"
echo "✔  SECRET_KEY injectée dans $COMPOSE_FILE."

# ── 5. Variables optionnelles ─────────────────────────────────────────────────
echo ""
read -rp "Activer HTTPS (reverse proxy TLS Synology) ? [o/N] " HTTPS_ANSWER
if [[ "$HTTPS_ANSWER" =~ ^[oOyY]$ ]]; then
  sed -i "s|HTTPS_ENABLED=false|HTTPS_ENABLED=true|g" "$COMPOSE_FILE"
  echo "✔  HTTPS_ENABLED=true"
fi

read -rp "Renseigner l'URL publique de l'app (ex: http://192.168.1.10:5001) : " APP_URL_VAL
if [ -n "$APP_URL_VAL" ]; then
  sed -i "s|APP_URL=http://IP-DU-NAS:5001|APP_URL=$APP_URL_VAL|g" "$COMPOSE_FILE"
  echo "✔  APP_URL=$APP_URL_VAL"
fi

# ── 6. Construction et démarrage ──────────────────────────────────────────────
echo ""
echo "→ Construction de l'image Docker (peut prendre 2-3 minutes)…"
docker compose -f "$COMPOSE_FILE" up -d --build

echo ""
echo "✔  IRM FAIR démarré."
echo ""
echo "    Accès : http://$(hostname -I | awk '{print $1}'):5001"
echo "    Logs  : docker compose -f $COMPOSE_FILE logs -f"
echo ""
echo "  Comptes démo :"
echo "    admin / admin123  (sudo — à changer immédiatement)"
echo "    nicolas / nico123"
echo ""
echo "⚠  Changez le mot de passe admin dès la première connexion."
echo ""
