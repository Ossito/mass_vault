#!/bin/bash
cd "$(dirname "$0")" || exit

PYTHON=python3.12

# --- Vérifier / Créer l'environnement virtuel ---
if [ -d ".venv" ]; then
    # Vérifier la version de Python dans l'environnement
    VENV_PYTHON=$(.venv/bin/python3 --version 2>/dev/null || echo "none")
    if [[ "$VENV_PYTHON" != *"3.12"* ]]; then
        echo "⚠️  L'environnement virtuel existe mais n'utilise pas Python 3.12. Recréation..."
        rm -rf .venv
    fi
fi

if [ ! -d ".venv" ]; then
    echo "🔧 Création de l'environnement virtuel avec $PYTHON..."
    $PYTHON -m venv .venv
    echo "✅ Environnement créé"
fi

# Activer l'environnement
source .venv/bin/activate

# --- Installer les dépendances (seulement les manquantes) ---
echo "📦 Vérification des dépendances..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet 2>/dev/null || \
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --quiet

echo "✅ Dépendances à jour – Lancement de MASSS VAULT"
cd app || exit
python main.py