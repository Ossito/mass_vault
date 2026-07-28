🔐 **MASSS** **VAULT**

**MASSS** **VAULT** est une application de chiffrement, de signature et de vérification de fichiers, construite avec Python, Tkinter et la bibliothèque cryptography. Elle permet d’évaluer et de comparer les performances de différents algorithmes asymétriques (**RSA**, **ECC**, ElGamal) en combinaison avec **AES**‑**256**‑**CTR**.

L’application offre une interface graphique moderne (thème Bootstrap), un explorateur de résultats, un système de métriques automatique, un assistant de décision basé sur les données expérimentales, et des rapports **PDF** comparatifs.

### Fonctionnalités principales

- Chiffrement & Signature – Chiffrement **AES**‑**CTR** d’un dossier complet, protection de la clé **AES** par une clé publique (**RSA**, **ECC**, ElGamal), signature avec la clé privée.
- Déchiffrement – Restauration des fichiers originaux à partir des fichiers chiffrés et des métadonnées.
- Vérification de Signature – Vérifie l’intégrité et l’authenticité de chaque fichier chiffré.
- Métriques automatiques – Chaque opération génère un fichier **JSON** contenant les temps, l’utilisation **CPU**/**RAM**, l’overhead, et un échantillon de calibration pour des prédictions futures.
- Explorateur avancé – Interface de navigation avec arbre de dossiers, visualisation des graphiques, visionneuse d’images et de **JSON**.
- Assistant de décision – Saisie des contraintes (volume, **RAM**, **CPU**, stockage…), prédiction des performances, recommandation de l’algorithme le plus adapté, génération d’un rapport **PDF**.
- Comparaison des performances – Regroupe tous les **JSON** de metrics_graphs/, calcule moyennes et écarts‑types, génère 8 graphiques comparatifs et un rapport **PDF**.
- Internationalisation – Interface disponible en français et en anglais.
- Stockage configurable – L’utilisateur choisit le dossier racine où toutes les données sont sauvegardées.

### Stack technique

- Python 3.12
- Interface graphique : tkinter + ttkbootstrap (thèmes modernes)
- Cryptographie : cryptography (hazmat)
- Visualisation : matplotlib, Pillow
- Rapports **PDF** : **FPDF**
- Gestion des fichiers : pathlib, shutil
- Parallélisme : concurrent.futures
- Analyse de données : numpy

### Arborescence du projet

```
mass-vault/
├── app/
│   ├── main.py                         # Point d’entrée de l’interface graphique
│   ├── interfaces/
│   │   ├── home_window.py              # Page d’accueil
│   │   ├── encrypt_sign_window.py      # Chiffrement & Signature
│   │   ├── decrypt_window.py           # Déchiffrement
│   │   ├── verify_window.py            # Vérification de Signature
│   │   └── decision_window.py          # Assistant de décision
│   ├── handlers/
│   │   ├── encrypt_sign.py             # Logique de chiffrement/signature
│   │   ├── decrypt.py                  # Logique de déchiffrement
│   │   ├── verify.py                   # Logique de vérification
│   │   ├── keys.py                     # Génération des clés asymétriques
│   │   ├── folders.py                  # Gestion des dossiers
│   │   ├── perf.py                     # Tracking des performances (CPU, RAM)
│   │   ├── comparison.py               # Comparaison des métriques
│   │   └── decision_assistant.py       # Assistant de décision
│   ├── utils/
│   │   ├── storage.py                  # Gestionnaire de stockage (StorageManager)
│   │   ├── explorer_manager.py         # Explorateur de fichiers avancé
│   │   ├── hash_utils.py               # Utilitaires de hachage
│   │   ├── window_utils.py             # Centrage des fenêtres
│   │   └── lang.py                     # Dictionnaire de langue (FR/EN)
│   └── fonts/                          # Polices Unicode pour les PDF
├── vault_data/                         # Dossier de stockage par défaut (configurable)
│   ├── encrypted_files/                # Fichiers chiffrés
│   │   └── {algo_keysize}/            # ex: RSA_2048, ECC_P-384
│   ├── signed_files/                   # Fichiers de signature (.sig)
│   │   └── {algo_keysize}/
│   ├── metadata/                       # Métadonnées (.meta)
│   │   └── {algo_keysize}/
│   ├── metrics_graphs/                 # JSON de métriques par opération
│   │   └── {algo_keysize}/
│   ├── performance_outputs/            # Graphiques de performance
│   │   └── graphs/{algo_keysize}/
│   ├── performance_resources/          # Métriques système (CPU/RAM)
│   │   └── {algo_keysize}/system_metrics/
│   ├── comparison_graphs/              # Rapports de comparaison
│   └── decision_reports/               # Rapports de l’assistant de décision
├── requirements.txt                    # Dépendances Python
└── README.md
```

### Installation

#### Cloner le dépôt

    git clone [https://github.com/VOTRE_COMPTE/mass-vault.git](https://github.com/VOTRE_COMPTE/mass-vault.git)
    cd mass-vault

#### Créer un environnement virtuel (recommandé)

    python3 -m venv .venv
    source .venv/bin/activate      # macOS/Linux
    # .venv\Scripts\activate       # Windows

#### Installer les dépendances

    pip install -r requirements.txt
    (Si le fichier requirements.txt n’existe pas encore, vous pouvez le générer avec pip freeze > requirements.txt après avoir installé les bibliothèques nécessaires.)

#### Lancer l’application

    cd app
    python main.py

### Utilisation rapide

1- Chiffrement & Signature : sélectionnez un dossier, choisissez l’algorithme, la taille de clé, l’algorithme de hachage, puis cliquez sur Chiffrer et Signer.

2- Déchiffrement : choisissez l’algorithme et la taille de clé correspondante, puis Déchiffrer.

3- Vérification : sélectionnez l’algorithme et la taille de clé, puis Vérifier les signatures.

4- Explorer les résultats : cliquez sur le bouton Explorer (en haut à droite) pour ouvrir l’explorateur avancé.

5- Comparer les performances : depuis la page d’accueil, cliquez sur 📊 Comparer les performances.

6- Assistant de décision : accessible depuis la barre supérieure de l’accueil, il vous guide pour choisir le meilleur algorithme selon vos contraintes.

### Métriques collectées

Chaque opération réussie enregistre un fichier **JSON** dans vault_data/metrics_graphs/{algo_keysize}/. Les métriques incluent :

- Temps de génération de clé, encapsulation, signature, vérification, décapsulation.
- Utilisation **CPU** (moyenne et écart‑type), **RAM** (max et moyenne).
- Overhead de stockage.
- Nombre de fichiers traités.
- Échantillon de calibration (taille de fichier → temps **AES**‑**CTR**) pour les prédictions de l’assistant.

### Assistant de décision

L’assistant de décision (handlers/decision_assistant.py) charge les métriques, extrapole les temps de chiffrement **AES**‑**CTR** pour un volume donné, estime les opérations asymétriques (indépendantes de la taille), puis applique des règles de recommandation (**RAM** limitée, conservation longue, accès fréquent…). Un rapport **PDF** personnalisé est généré.

### 📝 Licence

Ce logiciel est protégé par une licence personnalisée.  
Il est interdit de le redistribuer ou de l’utiliser à des fins commerciales.
Vous pouvez le modifier pour votre usage personnel, éducatif ou de recherche.
Consultez le fichier [LICENSE](LICENSE) pour plus de détails.

### Auteur

Développé par Germain H. (@ossitogermain)
