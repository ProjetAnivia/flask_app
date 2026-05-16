# Déploiement sur NAS Synology — IRM FAIR

## Prérequis sur le NAS

1. **DSM 7.x** minimum
2. **Container Manager** installé (Package Center → Container Manager)
3. **SSH activé** (Panneau de configuration → Terminal et SNMP → activer SSH)

---

## Structure des dossiers à créer sur le NAS

Avant de lancer, créer cette arborescence via File Station ou SSH :

```
/volume1/IRM_preclinique/
├── structured/       ← données DICOM/NIfTI structurées
├── raw/              ← données brutes Paravision
├── db/               ← base SQLite (irm_fair.db)
└── logs/             ← logs de transfert rsync
```

En SSH :
```bash
mkdir -p /volume1/IRM_preclinique/{structured,raw,db,logs}
```

---

## Déploiement

### 1. Copier les fichiers sur le NAS

Depuis ton Mac, via la commande `scp` :
```bash
scp -r ~/Downloads/flask_app admin@IP-DU-NAS:/volume1/IRM_preclinique/app
```
Ou via File Station : glisser-déposer le dossier `flask_app`.

### 2. Modifier la clé secrète

Dans `docker-compose.yml`, remplacer :
```yaml
- SECRET_KEY=CHANGE_THIS_SECRET_KEY_IN_PRODUCTION
```
Par une vraie clé aléatoire, par exemple :
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Construire et lancer

En SSH sur le NAS :
```bash
cd /volume1/IRM_preclinique/app
docker compose up -d --build
```

Vérifier que ça tourne :
```bash
docker compose ps
docker compose logs -f
```

Accéder à l'interface : `http://IP-DU-NAS:5001`

---

## Configurer le Reverse Proxy DSM (recommandé)

Le reverse proxy permet d'accéder à l'app via `https://irm.labo.local`
au lieu de `http://IP:5001`, avec HTTPS automatique.

1. DSM → **Panneau de configuration** → **Portail de connexion** → **Avancé** → **Reverse Proxy**
2. Cliquer **Créer**
3. Remplir :

| Champ | Valeur |
|-------|--------|
| Nom | IRM FAIR |
| Protocole source | HTTPS |
| Nom d'hôte source | `irm.labo.local` (ou l'IP du NAS) |
| Port source | 443 |
| Protocole destination | HTTP |
| Nom d'hôte destination | `localhost` |
| Port destination | 5001 |

4. Ajouter `irm.labo.local` dans le fichier `/etc/hosts` des machines du labo :
```
192.168.X.X    irm.labo.local
```

---

## Mettre à jour l'application

Après modification du code :
```bash
cd /volume1/IRM_preclinique/app
docker compose down
docker compose up -d --build
```

La base de données SQLite est dans `/volume1/IRM_preclinique/db/` —
elle est **persistée** et ne sera pas effacée lors des mises à jour.

---

## Commandes utiles

```bash
# Voir les logs en temps réel
docker compose logs -f irm-app

# Redémarrer sans rebuild
docker compose restart irm-app

# Ouvrir un shell dans le container (debug)
docker exec -it irm_fair_app bash

# Vérifier l'espace disque NAS
df -h /volume1
```

---

## Test sur le site de démo Synology

Sur `demo.synology.com` tu peux tester **Container Manager** visuellement :
1. Aller dans Container Manager → **Projet**
2. Cliquer **Créer** → uploader le `docker-compose.yml`
3. Le site de démo ne monte pas de vrais volumes mais permet de
   vérifier que la configuration Docker est correctement reconnue.

Note : le site de démo ne persistera pas les données et ne sera
pas accessible depuis l'extérieur — c'est uniquement pour valider
la configuration avant de déployer sur le vrai NAS.
