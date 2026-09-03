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
COPY google_calendar.py .
COPY i18n.py .
COPY templates/ templates/
COPY static/ static/
COPY fair_import.py* ./

# Embarquer les données réelles dans l'image (DB + NIfTI — 3.6 Mo)
# Permet un déploiement cloud sans volume persistant (demo/test)
COPY db/irm_fair.db    /app/db/irm_fair.db
COPY nas_simule/       /app/nas_simule/

EXPOSE 5000

ENV FLASK_ENV=production
ENV DB_DIR=/app/db
ENV NAS_ROOT=/app/nas_simule/structured

# Gunicorn gthread : 2 workers × 4 threads = 8 requêtes simultanées
# gthread permet les connexions SSE longues sans bloquer les autres workers
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "gthread", "--workers", "2", "--threads", "4", "--timeout", "300", "app:app"]
