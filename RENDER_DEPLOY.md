# Déploiement sur Render — IRM FAIR

Alternative gratuite à Railway pour exposer le dashboard sur une URL publique.
Pour le déploiement sur le NAS Synology, voir `DEPLOY.md` (inchangé).

---

## Pourquoi Render

| | Railway | Render (plan Free) |
|---|---|---|
| Coût | plan Free limité à 1 $ de crédit/mois, insuffisant pour un conteneur allumé ; Hobby à 5 $/mois | 0 € |
| RAM | selon conso | 512 Mo |
| Build Docker | oui | oui |
| Mise en veille | non | oui, après 15 min sans trafic |
| Disque persistant | oui | non sur le plan Free |

Le `Dockerfile` embarque déjà la base SQLite et les NIfTI dans l'image
(environ 3,9 Mo), donc aucun volume persistant n'est nécessaire pour faire
tourner la démo.

---

## ⚠️ Limite à connaître avant de démarrer

**Le plan Free n'a pas de disque persistant.** Tout ce qui est écrit dans
`/app/db/irm_fair.db` pendant l'utilisation (nouveaux comptes, planification,
imports, logs d'audit) **est perdu** à chaque mise en veille ou redéploiement.
L'app repart systématiquement de l'instantané embarqué dans l'image.

C'est acceptable pour une démo consultable, mais pas pour une plateforme où
les encadrants saisiraient réellement des données. Trois façons de traiter ça,
selon l'usage réel :

1. **Assumer le reset** : l'URL Render sert de vitrine, les vraies données
   restent sur le NAS. Rien à changer.
2. **Instance payante + disque** : environ 7 $/mois pour l'instance
   `0.5c-512mb` plus 0,25 $/Go/mois de disque. Il suffit d'ajouter un bloc
   `disk:` dans `render.yaml` et de remettre `DB_DIR` dessus.
3. **Migrer vers Postgres** : le Postgres gratuit de Render devient
   inaccessible au bout de 30 jours, donc ça n'a d'intérêt qu'en version
   payante, et ça demande de sortir de SQLite. À garder pour plus tard.

---

## Procédure

### 1. Pousser le repo

```bash
git add Dockerfile render.yaml RENDER_DEPLOY.md
git commit -m "Add Render deployment blueprint"
git push
```

### 2. Créer le service

1. Aller sur https://dashboard.render.com → **New** → **Blueprint**
2. Connecter le compte GitHub et sélectionner `Nolan-lpr/CHR-Dashboard`
3. Render lit `render.yaml` et propose le service `irm-fair`
4. Valider. Le premier build prend environ 5 à 10 min (image Python + gdcm)

### 3. Renseigner les variables secrètes

Dans **Settings → Environment** du service, remplir les variables marquées
`sync: false` dans `render.yaml` :

| Variable | Valeur | Obligatoire |
|---|---|---|
| `APP_URL` | l'URL Render, ex. `https://irm-fair.onrender.com` | oui, pour les liens de reset password |
| `RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET_KEY` | clés reCAPTCHA v3, avec le domaine `onrender.com` ajouté dans la console Google | non, l'app tourne sans |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | serveur d'envoi pour le reset password | non |
| `GOOGLE_CALENDAR_ID` | ID du calendrier partagé | seulement si sync agenda |
| `GOOGLE_CALENDAR_CREDENTIALS_JSON` | contenu complet du JSON du service account, collé tel quel | seulement si sync agenda |

`SECRET_KEY` est générée automatiquement par Render à la création du service
et reste stable ensuite. Ne pas la remplacer, sinon toutes les sessions
ouvertes sont invalidées.

Pour activer la synchronisation Google Calendar, passer aussi
`GOOGLE_CALENDAR_ENABLED` à `true`. Elle est à `false` par défaut car le
fichier `secrets/google_calendar_sa.json` n'est pas dans le repo (et ne doit
pas y être).

### 4. Vérifier

- `https://<nom>.onrender.com/login` doit répondre
- Le health check Render interroge `/login`, un service `live` signifie que
  gunicorn a démarré et que `init_db()` est passé
- Comptes de démo : voir la fin de `app.py`

---

## Garder le service éveillé

Le plan Free coupe l'instance après 15 min sans trafic, avec un redémarrage
d'environ une minute à la requête suivante.

Le quota est de **750 heures d'instance par mois et par workspace**. Un mois
plein fait 720 h (30 jours) ou 744 h (31 jours), donc **un seul** service
gratuit peut rester éveillé en permanence sans dépasser le quota. Si un
deuxième service gratuit tourne dans le même workspace, les deux se font
suspendre en fin de mois.

Deux approches :

- **Ping automatique** : un cron externe (par exemple cron-job.org) qui
  appelle `https://<nom>.onrender.com/login` toutes les 10 min. Le service
  reste chaud en continu.
- **Réveil manuel** : ouvrir l'URL 2 minutes avant une démo ou un audit.
  Suffisant si personne ne consulte entre deux.

---

## Ce qui a changé dans le repo

- `Dockerfile` : gunicorn écoute maintenant sur `$PORT` (imposé par Render) et
  le nombre de workers est piloté par `$WEB_CONCURRENCY`. La forme shell de
  `CMD` est nécessaire pour que ces variables soient substituées. Valeurs par
  défaut : `PORT=5000`, `WEB_CONCURRENCY=2`, donc `docker-compose up` en local
  et le déploiement NAS se comportent exactement comme avant.
- `render.yaml` : blueprint du service.

`render.yaml` force `WEB_CONCURRENCY=1` sur Render. Sur 512 Mo, deux workers
qui chargent numpy, scipy et scikit-learn (route de segmentation) font tomber
l'instance en OOM. Un worker avec 4 threads gthread encaisse largement une
démo, et les connexions SSE continuent de fonctionner.

Une sauvegarde `Dockerfile.bak` a été laissée à côté, à supprimer une fois le
déploiement validé.
