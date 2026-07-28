# Image de base Python légère
FROM python:3.12-slim

# Éviter la génération de fichiers .pyc et activer le mode non-interactif
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive

# Installation des dépendances système pour GUI (X11, Tkinter)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-tk \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxinerama1 \
    libxi6 \
    fonts-noto-color-emoji \
    fonts-liberation \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Création du répertoire de travail
WORKDIR /app

# Copie des dépendances et installation
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source et réglage des permissions
COPY . .
RUN chmod -R 755 /app

# Définition du point d'entrée
CMD ["python", "app/main.py"]
