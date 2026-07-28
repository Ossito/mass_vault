import os
from pathlib import Path

# --- Configuration de l'Application ---
APP_NAME = "MASSS VAULT"
DEFAULT_THEME = os.getenv("APP_THEME", "flatly")
DEFAULT_LANG = os.getenv("APP_LANG", "fr")

# --- Gestion des Chemins ---
BASE_DIR = Path(__file__).resolve().parent.parent
SETTINGS_FILE = BASE_DIR / "settings.json"

def load_settings():
    """Charge les paramètres depuis le fichier JSON."""
    if SETTINGS_FILE.exists():
        try:
            import json
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_settings(settings_dict):
    """Sauvegarde les paramètres dans le fichier JSON."""
    try:
        import json
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings_dict, f, indent=4, ensure_ascii=False)
        return True
    except Exception:
        return False

# Charger les paramètres au démarrage
app_settings = load_settings()

# Priorité : settings.json > Variable d'environnement > Défaut (base_dir/vault_data)
default_storage = os.getenv("STORAGE_PATH", str(BASE_DIR / "vault_data"))
saved_path = app_settings.get("storage_path", default_storage)

# Gestion intelligente des chemins : si c'est relatif, on le résout par rapport à BASE_DIR
# Pour éviter que Docker et Local ne se mélangent les pinceaux
if saved_path.startswith("./") or not os.path.isabs(saved_path):
    STORAGE_PATH = (BASE_DIR / saved_path.lstrip("./")).resolve()
else:
    STORAGE_PATH = Path(saved_path).resolve()

# --- Configuration des Dossiers du Coffre-Fort ---
VAULT_STRUCTURE = {
    'encrypted_files': "encrypted_files",
    'keys_generated': "keys_generated",
    'logs': "logs",
    'metadata': "metadata",
    'performance_outputs': "performance_outputs",
    'performance_resources': "performance_resources",
    'signed_files': "signed_files",
    'temp': "temp",
    'decryption_outputs': "decryption_outputs",
    'decrypted_files': "decrypted_files",
}

def ensure_vault_directories():
    """Crée la structure de base si elle n'existe pas."""
    STORAGE_PATH.mkdir(parents=True, exist_ok=True)
    for folder in VAULT_STRUCTURE.values():
        (STORAGE_PATH / folder).mkdir(parents=True, exist_ok=True)
