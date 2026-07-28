#!/bin/bash

# COULEURS POUR LES MESSAGES
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}--- MASSS VAULT STARTUP SCRIPT ---${NC}"

# 1. VÉRIFIER SI XQUARTZ EST INSTALLÉ ET LANCÉ
if ! command -v xhost &> /dev/null; then
    echo -e "${RED}Erreur: XQuartz n'est pas installé ou n'est pas dans votre PATH.${NC}"
    echo -e "${YELLOW}Veuillez installer XQuartz sur https://www.xquartz.org/ et redémarrer votre session.${NC}"
    echo -e "${YELLOW}IMPORTANT: Dans XQuartz > Réglages > Sécurité, cochez 'Autoriser les connexions des clients réseau'.${NC}"
    exit 1
fi

# Démarrer XQuartz s'il n'est pas en cours d'exécution
if ! pgrep -x "XQuartz" > /dev/null; then
    echo -e "${YELLOW}Lancement de XQuartz...${NC}"
    open -a XQuartz
    sleep 3
fi

# 2. ATTENDRE QUE LE SERVEUR X11 SOIT PRÊT
echo -e "${BLUE}Attente du serveur X11...${NC}"

# Sur Mac, DISPLAY est souvent un socket dynamique dans /tmp
[ -z "$DISPLAY" ] && export DISPLAY=:0

MAX_WAIT=5
COUNT=0
while [ $COUNT -lt $MAX_WAIT ]; do
    if xhost > /dev/null 2>&1; then
        break
    fi
    sleep 1
    COUNT=$((COUNT + 1))
done

# 3. AUTORISER LES CONNEXIONS LOCALES AU SERVEUR X
echo -e "${BLUE}Autorisation des connexions X11 via TCP (xhost +)...${NC}"
DISPLAY=localhost:0 xhost + > /dev/null 2>&1

if [ $? -ne 0 ]; then
    # Fallback si localhost:0 échoue
    xhost + > /dev/null 2>&1
fi

# 4. LANCER LE CONTENEUR VIA DOCKER COMPOSE
echo -e "${GREEN}Lancement de MASSS VAULT dans Docker...${NC}"
docker-compose up --build

# À l'arrêt du conteneur
echo -e "${BLUE}Application arrêtée.${NC}"
xhost -localhost > /dev/null 2>&1
