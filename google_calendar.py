"""
Synchronisation des acquisitions IRM avec Google Calendar.

Approche : Push one-way (Dashboard → Google).
Le Dashboard reste la source de vérité. À chaque création/modification/
suppression de créneau côté Flask, on appelle l'API Google Calendar pour
mettre à jour un événement correspondant.

Configuration (variables d'environnement) :
  GOOGLE_CALENDAR_CREDENTIALS_PATH : chemin vers le JSON du service account
  GOOGLE_CALENDAR_ID               : ID du Google Calendar partagé
  GOOGLE_CALENDAR_ENABLED          : "true" / "false" pour activer/désactiver
  GOOGLE_CALENDAR_TZ               : fuseau horaire (défaut Europe/Paris)

Comportement :
  - Si désactivé ou mal configuré : les fonctions sont des no-ops silencieux.
    Le Dashboard fonctionne normalement, simplement sans sync.
  - Toutes les erreurs API sont catchées et loggées — jamais relevées vers
    l'utilisateur, pour ne pas bloquer la création d'acquisitions.
"""

from __future__ import annotations

import os
import logging
from datetime import datetime, timedelta
from typing import Optional

log = logging.getLogger("google_calendar")

# ─── Configuration ───────────────────────────────────────────────────────
_CRED_PATH   = os.environ.get("GOOGLE_CALENDAR_CREDENTIALS_PATH", "")
_CALENDAR_ID = os.environ.get("GOOGLE_CALENDAR_ID", "")
_ENABLED     = os.environ.get("GOOGLE_CALENDAR_ENABLED", "true").lower() == "true"
_TZ          = os.environ.get("GOOGLE_CALENDAR_TZ", "Europe/Paris")
_SCOPES      = ["https://www.googleapis.com/auth/calendar"]

# ─── Service singleton (lazy + cache) ────────────────────────────────────
_service_cache = None
_service_failed = False  # ne pas réessayer en boucle si auth a déjà échoué


def _get_service():
    """Initialise et cache le client Google Calendar. Retourne None si KO."""
    global _service_cache, _service_failed
    if _service_failed:
        return None
    if _service_cache is not None:
        return _service_cache
    if not _ENABLED or not _CRED_PATH or not _CALENDAR_ID:
        _service_failed = True
        log.info("Google Calendar désactivé (config manquante).")
        return None
    if not os.path.isfile(_CRED_PATH):
        _service_failed = True
        log.warning("Google Calendar : credentials introuvables : %s", _CRED_PATH)
        return None
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        creds = service_account.Credentials.from_service_account_file(
            _CRED_PATH, scopes=_SCOPES
        )
        _service_cache = build("calendar", "v3", credentials=creds,
                               cache_discovery=False)
        log.info("Google Calendar : authentification OK (calendrier %s).", _CALENDAR_ID)
        return _service_cache
    except Exception as e:
        _service_failed = True
        log.error("Google Calendar : échec d'authentification : %s", e)
        return None


def is_enabled() -> bool:
    """True si la synchro est active et configurée."""
    return _get_service() is not None


# ─── Construction de l'événement ─────────────────────────────────────────

_COLOR_BY_SCANNER = {
    # IDs colorIds Google Calendar (1..11). On mappe les couleurs scanner
    # internes vers les couleurs Google les plus proches.
    "#ea7c1c": "6",   # orange   → tangerine  (IRM 1 par défaut)
    "#1d4ed8": "9",   # blue     → blueberry  (IRM 2 par défaut)
    "#b45309": "5",   # amber    → banana
    "#dc2626": "11",  # red      → tomato
    "#16a34a": "10",  # green    → basil      (IRM 3 par défaut)
    "#7c3aed": "3",   # purple   → grape
    "#0891b2": "7",   # teal     → peacock
    "#db2777": "4",   # pink     → flamingo
}

# Fallback : si la couleur du scanner ne matche pas exactement, on prend
# le colorId associé à l'index du scanner (modulo 9 couleurs distinctes).
# Garantit que IRM 1 / IRM 2 / IRM 3 ont 3 couleurs Google différentes
# même si leurs couleurs internes sont mal mappées.
_COLOR_FALLBACK_BY_INDEX = ["6", "9", "10", "11", "7", "4", "3", "5", "1"]

_STATUT_LABEL = {
    "en_attente": "🕐 en attente",
    "en_cours":   "▶ en cours",
    "ok":         "✓ ok",
    "a_refaire":  "⟲ à refaire",
}

_PERIODE_LABEL = {
    "matin":      "🌅 Matin",
    "apres_midi": "🌇 Après-midi",
    "journee":    "🌞 Journée",
}


def _build_event_body(acq: dict, app_url: str = "") -> dict:
    """Construit le payload d'un événement à partir d'une ligne acquisition."""
    date_acq    = acq.get("date_acq") or ""
    heure_debut = acq.get("heure_debut") or "09:00"
    duree_min   = int(acq.get("duree_min") or 30)

    # ISO 8601 local (Google interprète avec timeZone)
    start_dt = f"{date_acq}T{heure_debut}:00"
    try:
        dt = datetime.strptime(f"{date_acq} {heure_debut}", "%Y-%m-%d %H:%M")
        end_dt = (dt + timedelta(minutes=duree_min)).strftime("%Y-%m-%dT%H:%M:00")
    except ValueError:
        end_dt = f"{date_acq}T{heure_debut}:00"

    animal = acq.get("animal_id") or "?"
    seq    = acq.get("sequence") or "?"
    projet = acq.get("projet") or ""
    scanner_nom = acq.get("scanner_nom") or ""

    periode = acq.get("periode")
    periode_label = _PERIODE_LABEL.get(periode)

    summary = f"{animal} · {seq}"
    if periode_label:
        summary = f"{periode_label.split(' ', 1)[1]} · {summary}"  # ex: "Matin · B3 · T2"
    if scanner_nom:
        summary += f" [{scanner_nom}]"

    # Description riche
    projet_nom_long = acq.get("projet_nom_long") or ""
    projet_resp     = acq.get("projet_resp") or ""
    projet_label    = f"{projet}"
    if projet_nom_long:
        projet_label += f" — {projet_nom_long}"
    lines = [f"Projet : {projet_label}"]
    if projet_resp:
        lines.append(f"Chercheur : {projet_resp}")
    if periode_label:
        lines.append(f"Période : {periode_label}")
    if scanner_nom:
        lines.append(f"Scanner : {scanner_nom}")
    statut = acq.get("statut")
    if statut:
        lines.append(f"Statut : {_STATUT_LABEL.get(statut, statut)}")
    poids = acq.get("poids_g")
    if poids:
        lines.append(f"Poids : {poids} g")
    importe_par = acq.get("importé_par") or acq.get("importe_par")
    if importe_par:
        lines.append(f"Planifié par : {importe_par}")
    if app_url and acq.get("id"):
        lines.append("")
        lines.append(f"Fiche animal : {app_url}/animal/{projet}/{animal}")
    description = "\n".join(lines)

    body = {
        "summary":     summary,
        "description": description,
        "start":       {"dateTime": start_dt, "timeZone": _TZ},
        "end":         {"dateTime": end_dt,   "timeZone": _TZ},
        "source":      {"title": "IRM Dashboard",
                        "url": app_url or "https://localhost"},
        # ID interne stocké en propriété étendue (debug/recherche)
        "extendedProperties": {
            "private": {
                "acq_id":  str(acq.get("id") or ""),
                "projet":  projet,
                "animal":  animal,
            }
        },
    }

    # CR : on garantit 3 couleurs distinctes pour les 3 IRM.
    # 1. Match exact par couleur hex du scanner
    # 2. Fallback : scanner_id modulo nb couleurs disponibles
    color_id = _COLOR_BY_SCANNER.get((acq.get("scanner_couleur") or "").lower())
    if not color_id and acq.get("scanner_id"):
        try:
            idx = (int(acq["scanner_id"]) - 1) % len(_COLOR_FALLBACK_BY_INDEX)
            color_id = _COLOR_FALLBACK_BY_INDEX[idx]
        except (ValueError, TypeError):
            pass
    if color_id:
        body["colorId"] = color_id

    return body


# ─── Opérations CRUD ─────────────────────────────────────────────────────

def push_event(acq: dict, app_url: str = "") -> Optional[str]:
    """
    Crée l'événement sur Google Calendar. Retourne l'event_id ou None.
    `acq` doit contenir au minimum : id, animal_id, projet, sequence,
    date_acq, heure_debut, duree_min.
    """
    svc = _get_service()
    if svc is None or not acq.get("date_acq") or not acq.get("heure_debut"):
        return None
    try:
        body  = _build_event_body(acq, app_url=app_url)
        event = svc.events().insert(calendarId=_CALENDAR_ID, body=body).execute()
        return event.get("id")
    except Exception as e:
        log.warning("Google Calendar push KO (acq %s) : %s", acq.get("id"), e)
        return None


def update_event(event_id: str, acq: dict, app_url: str = "") -> bool:
    """Met à jour un événement existant. Si event_id est absent, ne fait rien."""
    svc = _get_service()
    if svc is None or not event_id:
        return False
    try:
        body = _build_event_body(acq, app_url=app_url)
        svc.events().update(calendarId=_CALENDAR_ID, eventId=event_id,
                            body=body).execute()
        return True
    except Exception as e:
        # 404 → l'événement a été supprimé côté Google, on tente une recréation
        if "404" in str(e) or "Not Found" in str(e):
            log.info("Google Calendar : event %s introuvable, recréation.", event_id)
            return False
        log.warning("Google Calendar update KO (event %s) : %s", event_id, e)
        return False


def delete_event(event_id: str) -> bool:
    """Supprime un événement. Tolère le 404 (déjà supprimé)."""
    svc = _get_service()
    if svc is None or not event_id:
        return False
    try:
        svc.events().delete(calendarId=_CALENDAR_ID, eventId=event_id).execute()
        return True
    except Exception as e:
        if "404" in str(e) or "410" in str(e) or "Not Found" in str(e):
            return True  # déjà supprimé, on considère que c'est OK
        log.warning("Google Calendar delete KO (event %s) : %s", event_id, e)
        return False


def upsert_event(acq: dict, app_url: str = "") -> Optional[str]:
    """
    Helper : si acq a un google_event_id valide → update.
    Sinon (ou si update fail en 404) → push (create).
    Retourne l'event_id à stocker, ou None.
    """
    event_id = acq.get("google_event_id")
    if event_id:
        if update_event(event_id, acq, app_url=app_url):
            return event_id
    # Pas d'event existant, ou update a échoué → on crée
    return push_event(acq, app_url=app_url)


def list_changes(sync_token: Optional[str] = None) -> dict:
    """
    Synchronisation incrémentale (polling).

    - Premier appel : sync_token=None → on récupère tout (limité aux 90 derniers
      jours pour éviter de tirer un historique gigantesque) ET on récupère un
      nouveau sync_token pour les appels suivants.
    - Appels suivants : on passe le sync_token précédent → Google ne renvoie
      que les événements qui ont changé depuis. C'est gratuit côté quota et
      très rapide.

    Retourne {events: [...], next_sync_token: str, full_resync_needed: bool}.
    Si full_resync_needed=True (token expiré, jamais arrivé jusqu'ici), il
    faut rappeler la fonction avec sync_token=None.
    """
    svc = _get_service()
    if svc is None:
        return {"events": [], "next_sync_token": sync_token, "full_resync_needed": False}

    events: list = []
    page_token = None
    next_sync_token = None
    full_resync_needed = False

    # Premier sync : on limite à 90 jours en arrière, pas de syncToken
    base_kwargs = {
        "calendarId": _CALENDAR_ID,
        "singleEvents": True,
        "showDeleted": True,   # essentiel pour détecter les suppressions
    }
    if sync_token:
        base_kwargs["syncToken"] = sync_token
    else:
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        time_min = (_dt.now(_tz.utc) - _td(days=90)).isoformat()
        base_kwargs["timeMin"] = time_min

    try:
        while True:
            kwargs = dict(base_kwargs)
            if page_token:
                kwargs["pageToken"] = page_token
            resp = svc.events().list(**kwargs).execute()
            events.extend(resp.get("items", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                next_sync_token = resp.get("nextSyncToken")
                break
    except Exception as e:
        if "410" in str(e) or "Gone" in str(e):
            # syncToken expiré (Google les invalide après ~7j d'inactivité)
            log.info("Google Calendar : syncToken expiré, full resync nécessaire.")
            return {"events": [], "next_sync_token": None, "full_resync_needed": True}
        log.warning("Google Calendar list_changes KO : %s", e)
        return {"events": [], "next_sync_token": sync_token, "full_resync_needed": False}

    return {
        "events": events,
        "next_sync_token": next_sync_token,
        "full_resync_needed": full_resync_needed,
    }


def parse_event_to_acq_fields(event: dict) -> dict:
    """
    Extrait de l'événement Google les champs qui peuvent avoir changé côté Google
    et qu'on veut répliquer côté DB.
    Retourne {date_acq, heure_debut, duree_min, status, acq_id (depuis extProp)}.
    `status` est 'cancelled' (événement supprimé) ou 'confirmed'.
    """
    out = {
        "google_event_id": event.get("id"),
        "status":          event.get("status"),
        "acq_id":          None,
        "date_acq":        None,
        "heure_debut":     None,
        "duree_min":       None,
    }
    ext = (event.get("extendedProperties") or {}).get("private") or {}
    if ext.get("acq_id"):
        try:
            out["acq_id"] = int(ext["acq_id"])
        except (ValueError, TypeError):
            pass

    start = (event.get("start") or {}).get("dateTime")
    end   = (event.get("end")   or {}).get("dateTime")
    if start and len(start) >= 16:
        # Format Google : 2026-06-10T14:00:00+02:00 → on prend les 16 premiers chars
        out["date_acq"]    = start[:10]
        out["heure_debut"] = start[11:16]
        if end and len(end) >= 16:
            try:
                s_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                e_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                out["duree_min"] = max(1, int((e_dt - s_dt).total_seconds() // 60))
            except Exception:
                pass
    return out


def test_connection() -> dict:
    """Diagnostic. Retourne {ok, message, calendar_summary}."""
    svc = _get_service()
    if svc is None:
        return {"ok": False, "message": "Service non initialisé (config manquante ou auth KO)."}
    try:
        cal = svc.calendars().get(calendarId=_CALENDAR_ID).execute()
        return {
            "ok": True,
            "message": "OK",
            "calendar_summary": cal.get("summary"),
            "calendar_id": cal.get("id"),
            "time_zone": cal.get("timeZone"),
        }
    except Exception as e:
        return {"ok": False, "message": f"Erreur API : {e}"}
