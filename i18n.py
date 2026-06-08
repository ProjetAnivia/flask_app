"""
CR #21 — Internationalisation minimale FR / EN.

Approche pragmatique : un dictionnaire `TRANSLATIONS[lang][key] = string`,
exposé en Jinja via le filtre `t()`. Les chaînes en français restent les
clés (lisibles en code et fallback automatique si pas de traduction).

Usage côté template :
    {{ "Nouveau projet" | t }}           # traduit si lang=en, sinon inchangé
    {{ "Acquisitions" | t(lang) }}       # passe explicitement le lang

Côté Python :
    from i18n import translate
    translate("Nouveau projet", "en")    # → "New project"

Pour ajouter une langue : créer une nouvelle entrée dans TRANSLATIONS.
Pour ajouter une chaîne : juste l'ajouter dans en/, le fr/ est implicite.
"""

# Dictionnaire EN seulement — les chaînes FR sont les clés (pas de duplication)
TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        # Navigation
        "Dashboard":           "Dashboard",
        "Tableau de bord":     "Dashboard",
        "Opérationnel":        "Workflow",
        "Données":             "Data",
        "Système":             "System",
        "Projets":             "Projects",
        "Animaux":             "Animals",
        "Planning acquisitions": "Acquisition planning",
        "Planning":            "Planning",
        "Planification":       "Planning",
        "Calendrier":          "Calendar",
        "Explorateur NAS":     "NAS Explorer",
        "Utilisateurs":        "Users",
        "Connexions":          "Sessions",
        "Audit":               "Audit log",
        "Archive":             "Archive",
        "Notifications":       "Notifications",
        "Aide":                "Help",
        "Préférences":         "Preferences",
        "Se déconnecter":      "Sign out",
        "Sécurité":            "Security",
        "Vue générale":        "Overview",
        # Common labels
        "Nom":                 "Name",
        "Nom du projet":       "Project name",
        "Acronyme":            "Acronym",
        "Acronyme du projet":  "Project acronym",
        "Nom complet":         "Full name",
        "Nom complet du projet (facultatif)": "Full project name (optional)",
        "Responsable":         "Lead researcher",
        "Chercheur":           "Researcher",
        "Espèce":              "Species",
        "Date":                "Date",
        "Heure":               "Time",
        "Durée":               "Duration",
        "Statut":              "Status",
        "Action":              "Action",
        "Actions":             "Actions",
        "Détail":              "Details",
        "Notes":               "Notes",
        "Description":         "Description",
        "Projet":              "Project",
        "Session":             "Session",
        "Animal":              "Animal",
        "Séquence":            "Sequence",
        "Acquisition":         "Acquisition",
        "Acquisitions":        "Acquisitions",
        # Statuts
        "en attente":          "pending",
        "en cours":            "in progress",
        "terminé":             "completed",
        "à refaire":           "to redo",
        "complet":             "complete",
        # Buttons
        "Créer":               "Create",
        "Créer →":             "Create →",
        "Enregistrer":         "Save",
        "Annuler":             "Cancel",
        "Supprimer":           "Delete",
        "Modifier":            "Edit",
        "Confirmer":           "Confirm",
        "Réserver":            "Reserve",
        "Réserver un créneau": "Reserve a slot",
        "Aperçu":              "Preview",
        "Vérifier le créneau": "Check slot",
        "Lancer le calcul":    "Run calculation",
        "Calculer":            "Compute",
        # Periodes
        "Matin":               "Morning",
        "Après-midi":          "Afternoon",
        "Journée":             "Full day",
        "Personnalisé":        "Custom",
        "Période":             "Period",
        # Form labels
        "Poids":               "Weight",
        "Poids (g)":           "Weight (g)",
        "Qualité":             "Quality",
        "Excellente":          "Excellent",
        "Bonne":               "Good",
        "Dégradée":            "Degraded",
        "Inutilisable":        "Unusable",
        "Problème":            "Issue",
        # Messages
        "Aucun résultat":      "No results",
        "Aucun projet actif ce mois": "No active project this month",
        "Mise à jour":         "Updated",
        "Aujourd'hui":         "Today",
        "Demain":              "Tomorrow",
        "Hier":                "Yesterday",
        # Date / period
        "format dates":        "date format",
        # Misc
        "Évolution du poids":  "Weight evolution",
        "Cahier de manips":    "Lab notebook",
        "Identité":            "Identity",
        "Planning":            "Schedule",
        "Acquisitions TEP":    "PET acquisitions",
        "Dose injectée (MBq)": "Injected dose (MBq)",
        "Produit radioactif":  "Radioactive tracer",
        "Cohérence NAS":       "NAS naming check",
    },
    # "fr" : pas nécessaire, les clés SONT les valeurs FR
}


def translate(key: str, lang: str = "fr") -> str:
    """Traduit une chaîne. Fallback sur la clé si pas de traduction."""
    if not key:
        return key
    lang = (lang or "fr").lower()
    if lang == "fr":
        return key
    return TRANSLATIONS.get(lang, {}).get(key, key)


def get_supported_languages() -> list[dict]:
    """Liste des langues supportées pour le switcher."""
    return [
        {"code": "fr", "label": "Français", "flag": "🇫🇷"},
        {"code": "en", "label": "English",  "flag": "🇬🇧"},
    ]
