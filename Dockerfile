FROM python:3.11-slim

LABEL description="Plateforme FAIR IRM préclinique"

# Dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl \
    python3-gdcm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY fair_import.py* ./

# Embarquer les données réelles dans l'image (DB + NIfTI — 3.6 Mo)
# Permet un déploiement cloud sans volume persistant (demo/test)
COPY db/irm_fair.db    /app/db/irm_fair.db
COPY nas_simule/       /app/nas_simule/

EXPOSE 5000

ENV FLASK_ENV=production
ENV DB_DIR=/app/db
ENV NAS_ROOT=/app/nas_simule/structured

# Gunicorn en production (2 workers, timeout 120s pour le viewer NIfTI)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
