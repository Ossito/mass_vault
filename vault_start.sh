#!/bin/bash
cd "$(dirname "$0")" || exit
PYTHON=python3.12

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------- Environnement virtuel ----------
if [ -d ".venv" ]; then
    VENV_PYTHON=$(.venv/bin/python3 --version 2>/dev/null || echo "none")
    if [[ "$VENV_PYTHON" != *"3.12"* ]]; then
        echo -e "${CYAN}⚠️  L'environnement virtuel n'utilise pas Python 3.12. Recréation...${NC}"
        rm -rf .venv
    fi
fi

if [ ! -d ".venv" ]; then
    echo -e "${CYAN}🔧 Création de l'environnement virtuel avec $PYTHON...${NC}"
    $PYTHON -m venv .venv
fi

source .venv/bin/activate

# ---------- Dépendances ----------
echo -e "${CYAN}📦 Vérification des dépendances...${NC}"
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet 2>/dev/null || \
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --quiet

# ---------- Suppression du conflit fpdf ----------
pip uninstall pypdf PyFPDF fpdf -y --quiet 2>/dev/null
pip install --force-reinstall --no-deps fpdf2 --quiet 2>/dev/null

# ---------- Lancement ----------
echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     ✅ MASSS VAULT est lancé !      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""

cd app || exit
python main.py

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       👋 Application fermée         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"