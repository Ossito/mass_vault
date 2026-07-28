import datetime
import glob
import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import shutil
import sys
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import json
import io
import matplotlib
import numpy as np
matplotlib.use('Agg')  
from matplotlib import pyplot as plt
from handlers.perf import perf_tracker, measure_performance
from concurrent.futures import ProcessPoolExecutor, as_completed
from utils.hash_utils import get_hash_algorithm

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def _get_overhead_data(files):
    valid = []
    for f in files:
        if f.get('success') and f.get('original_path') and f.get('encrypted_path'):
            orig_path = f['original_path']
            enc_path = f['encrypted_path']
            if os.path.exists(orig_path) and os.path.exists(enc_path):
                orig = os.path.getsize(orig_path)
                enc = os.path.getsize(enc_path)
                overhead = (enc - orig) / orig * 100 if orig > 0 else 0.0
                valid.append({
                    'name': f['filename'][:15] + '...' if len(f['filename']) > 15 else f['filename'],
                    'orig_bytes': orig,
                    'enc_bytes': enc,
                    'overhead': overhead
                })
    return valid

# ----------------------------------------------------------------------------------
# 1. Configuration des logs
# ----------------------------------------------------------------------------------
def setup_logging(algorithm="AES-256-CTR", storage_manager=None):
    """Configure le logging avec StorageManager"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    # Utiliser le StorageManager pour le dossier logs
    logs_dir = storage_manager.get_directory("logs")
    
    # Nettoyage des anciens logs
    if logs_dir.exists():
        try:
            shutil.rmtree(logs_dir)
        except Exception as e:
            print(f"⚠️ Erreur nettoyage logs: {e}")
    
    logs_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    log_filename = logs_dir / f"crypto_session_{timestamp}.log"

    # Format pour l'en-tête technique
    
    header_format = """
        ╔══════════════════════════════════════════════════╗
        ║ %(asctime)s - %(levelname)-8s                    ║
        ╠══════════════════════════════════════════════════╣
        ║ %(message)s
        ╚══════════════════════════════════════════════════╝
        """

    # Détection des paramètres de l'algorithme
    algo_parts = algorithm.split('-')
    algo_name = algo_parts[0]
    algo_key_size = int(algo_parts[1]) if len(algo_parts) > 1 else 256
    algo_mode = algo_parts[2] if len(algo_parts) > 2 else "CTR"

    # Configuration technique détaillée (version enrichie)
    tech_info = f"""
        === CONFIGURATION CRYPTOGRAPHIE ===
        [Algorithmes]
        • Chiffrement      : {algorithm}
        - Taille clé     : {algo_key_size} bits ({algo_key_size//8} octets)
        - Mode           : {algo_mode}
        • Intégrité        : HMAC-SHA-256
        - Taille clé     : 256 bits (32 octets)

        [Environnement]
        • Bibliothèque     : cryptography (hazmat)
        • Système          : {sys.platform}
        • Version Python   : {sys.version.split()[0]}
        • PID              : {os.getpid()}
        • Répertoire       : {os.getcwd()}
        • Horodatage       : {timestamp}
        • Stockage         : {storage_manager.base_dir}
        """

    # Configuration du logger
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    file_handler = logging.FileHandler(log_filename, mode='w', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(header_format, datefmt="%Y-%m-%d %H:%M:%S"))
    
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    # Écriture de l'en-tête technique
    logging.info(f"🔐 DÉBUT SESSION \n{tech_info}")

    return str(log_filename)


# ----------------------------------------------------------------------------------
# 2. Génération de clés (AES, Nonce, HMAC)
# ----------------------------------------------------------------------------------
def generate_aes_key():
    """Génère une clé AES-256 aléatoire et sécurisée."""
    key = secrets.token_bytes(32) 
    # print(f"🔑 Clé AES générée : {key.hex()}")
    return key

def generate_nonce():
    """Génère un nonce de 16 octets aléatoire."""
    nonce = secrets.token_bytes(16)
    print(f"🎲 Nonce généré : {nonce.hex()}")
    logging.info(f"Nonce généré : {nonce.hex()}")
    return nonce

def generate_hmac_key():
    """Génère une clé HMAC de 32 octets."""
    hmac_key = secrets.token_bytes(32)
    print(f"🔐 Clé HMAC générée : {hmac_key.hex()}")
    logging.info(f"Clé HMAC générée : {hmac_key.hex()}")
    return hmac_key

# Nettoyage sécurisé à la fin du traitement
def clean_sensitive_data(key_material):
    """Nettoie les données sensibles en écrasant la mémoire"""
    if isinstance(key_material, bytes):
        # Conversion en bytearray (mutable)
        mutable_data = bytearray(key_material)
        # Écrasement avec des zéros
        for i in range(len(mutable_data)):
            mutable_data[i] = 0
        # Reconversion en bytes
        return bytes(mutable_data)
    return key_material

# ----------------------------------------------------------------------------------
# 3. Fonction de chiffrement 
# ----------------------------------------------------------------------------------
@measure_performance
def encrypt_file(file_path, key, nonce):
    """Chiffre un fichier avec AES-CTR et retourne le chemin du fichier temporaire."""
    temp_path = None
    
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        temp_path = file_path + ".tmp"
        
        with open(file_path, "rb") as f_in, open(temp_path, "wb") as f_out:
            while True:
                chunk = f_in.read(1024 * 1024)  # 1 Mo par morceau
                if not chunk:
                    break
                f_out.write(encryptor.update(chunk))
            f_out.write(encryptor.finalize())
            
        # print(f"🔒 Fichier chiffré temporaire : {temp_path}")
        # logging.info(f"Fichier {file_path} chiffré dans {temp_path}")
        temp_path = file_path + ".tmp"
        return temp_path

    except Exception as e:
        if temp_path and os.path.exists(temp_path): 
            os.remove(temp_path)
        logging.error(f"Échec du chiffrement de {file_path} : {e}")
        raise


# ----------------------------------------------------------------------------------
# 4. Fonction de validation
# ----------------------------------------------------------------------------------
def validate_file(temp_path, hash_name):
    """Génère l'empreinte (hachage) du fichier chiffré pour en assurer l'intégrité."""
    from utils.hash_utils import get_hash_algorithm
    try:
        # Vérifier la taille
        if os.path.getsize(temp_path) == 0:
            raise ValueError("Fichier temporaire vide")

        # Calculer le hachage avec l'algorithme choisi
        hash_algo = get_hash_algorithm(hash_name)
        digest = hashes.Hash(hash_algo, backend=default_backend())
        with open(temp_path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        hash_value = digest.finalize()
        print(f"🔎 Empreinte calculée ({hash_name}) : {hash_value.hex()[:32]}...")
        return hash_value

    except Exception as e:
        logging.error(f"Erreur de hachage pour {temp_path} : {e}")
        return None


# ----------------------------------------------------------------------------------
# 5. Configurations des algorithmes supportés
# ----------------------------------------------------------------------------------
SUPPORTED_ALGORITHMS = {
    "RSA": {"1024": 1024, "2048": 2048, "3072": 3072, "4096": 4096},
    "ECC": {"192": 192, "224": 224, "256": 256, "384": 384, "521": 521},  
    "ElGamal": {"1024": 1024, "2048": 2048, "3072": 3072, "4096": 4096}
}

# ----------------------------------------------------------------------------------
# 6. Fonction pour vérifier les paramètres
# ----------------------------------------------------------------------------------
def validate_algorithm_choice(algorithm, key_size):
    """Validation compatible ECC"""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithme non supporté: {algorithm}")
    
    # Normalisation pour ECC
    if algorithm == "ECC":
        if isinstance(key_size, str) and key_size.startswith("P-"):
            key_size = int(key_size[2:])  
        elif isinstance(key_size, str):
            key_size = int(key_size)  
        
        valid_sizes = list(SUPPORTED_ALGORITHMS["ECC"].values())
    else:
        valid_sizes = list(SUPPORTED_ALGORITHMS[algorithm].values())
    
    if key_size not in valid_sizes:
        raise ValueError(f"Taille {key_size} invalide pour {algorithm}")
    

# ----------------------------------------------------------------------------------
# 7. Fonction pour charger la clé publique
# ----------------------------------------------------------------------------------

_key_cache = {}

def load_public_key(algorithm, key_size, storage_manager=None):
    if storage_manager is None:
        from utils.storage import storage_manager
    
    # Déterminer le nom du dossier et fichier
    if algorithm == "RSA":
        subfolder = f"RSA_{key_size}"
        filename = f"rsa_public_{key_size}.pem"
    elif algorithm == "ECC":
        if isinstance(key_size, str) and key_size.startswith("P-"):
            curve_id = key_size.replace("-", "_")  
        else:
            curve_id = f"P_{key_size}"             
        subfolder = f"ECC_{curve_id}"
        filename = f"ecc_public_{curve_id}.pem"
    elif algorithm == "ElGamal":
        subfolder = f"ElGamal_{key_size}"
        filename = f"elgamal_public_{key_size}.pem"
    else:
        raise ValueError(f"Algorithme non supporté: {algorithm}")
    
    # Chercher le fichier spécifique
    key_file = storage_manager.get_file_path(filename, "keys_generated", subfolder)
    
    # Fallback: chercher any public key file
    if not key_file.exists():
        key_dir = storage_manager.get_directory("keys_generated") / subfolder
        if key_dir.exists():
            public_files = list(key_dir.glob("*public*.pem"))
            if public_files:
                key_file = public_files[0]
    
    if not key_file.exists():
        raise FileNotFoundError(f"❌ Aucune clé publique trouvée dans {key_file.parent}")

    with open(key_file, "rb") as f:
        pem_data = f.read()
        
        if algorithm == "RSA":
            return serialization.load_pem_public_key(pem_data)
        elif algorithm == "ECC":
            key = serialization.load_pem_public_key(pem_data)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError("❌ La clé chargée n'est pas une clé ECC valide")
            return key
        elif algorithm == "ElGamal":
            return serialization.load_pem_public_key(pem_data)

def load_public_key_cached(algorithm, key_size, storage_manager=None):
    cache_key = f"{algorithm}_{key_size}"
    if cache_key not in _key_cache:
        _key_cache[cache_key] = load_public_key(algorithm, key_size, storage_manager)
    return _key_cache[cache_key]

# ----------------------------------------------------------------------------------
# 8. Fonction pour chiffrer la clé AES
# ----------------------------------------------------------------------------------
def encrypt_aes_key(aes_key, algorithm, key_size):
    """Chiffre la clé AES avec la clé publique appropriée"""
    try:
        public_key = load_public_key(algorithm, key_size)
        
        print(f"🔏 Chiffrement clé AES avec {algorithm}_{key_size}...")
        
        if algorithm == "RSA":
            encrypted = public_key.encrypt(  # type: ignore
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted
        
        elif algorithm == "ECC":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise TypeError("Type de clé ECC invalide")
            
            curve = public_key.curve
            private_key_ephem = ec.generate_private_key(curve)
            public_key_ephem = private_key_ephem.public_key()
            
            # Format uncompressed pour compatibilité
            pubkey_bytes = public_key_ephem.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Échange de clé ECDH
            shared_key = private_key_ephem.exchange(ec.ECDH(), public_key)
            
            # Dérivation de clé
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecc_key_wrap',
            ).derive(shared_key)
            
            # Chiffrement XOR
            encrypted_key = bytes(a ^ b for a, b in zip(aes_key, derived_key))
            
            # On retourne TOUTE la donnée nécessaire
            return pubkey_bytes + encrypted_key 
        
        elif algorithm == "ElGamal":
            # Padding OAEP est plus sécurisé que PKCS1v15
            encrypted = public_key.encrypt(  # type: ignore
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Taille clé chiffrée ElGamal : {len(encrypted)} bytes")  # Doit être 128 pour 1024 bits
            return encrypted
        
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")
        
    except Exception as e:
        print(f"❌ Erreur chiffrement: {str(e)}")
        raise


def write_metadata_header(ciphertext_path, metadata, output_path):
    """
    Crée l'en-tête contenant les métadonnées et l'ajoute au début du ciphertext.
    Format : [4 octets de taille] + [JSON des métadonnées] + [Ciphertext]
    """
    import json
    meta_json = json.dumps(metadata).encode('utf-8')
    header_size = len(meta_json).to_bytes(4, byteorder='big')
    
    with open(output_path, 'wb') as f_out:
        f_out.write(header_size)
        f_out.write(meta_json)
        with open(ciphertext_path, 'rb') as f_in:
            while True:
                chunk = f_in.read(1024 * 1024)
                if not chunk:
                    break
                f_out.write(chunk)
                
    return output_path


# ----------------------------------------------------------------------------------
# 9. Fonction pour sauvegarder les métadonnées
# ----------------------------------------------------------------------------------
def save_metadata(filename, file_type, aes_key, nonce, hmac_value, algorithm, key_size, hash_name, storage_manager=None):
    """Sauvegarde les métadonnées via StorageManager"""
    if not hash_name:
        raise ValueError("Hash algorithm must be specified")
    if storage_manager is None:
        from utils.storage import storage_manager
    
    try:
        # Structure des métadonnées
        metadata = {
            'filename': filename,
            'file_type': file_type,
            'algorithm': f"{algorithm}_{key_size}",
            'hash_algorithm': hash_name,
            'encrypted_key': aes_key.hex(),
            'nonce': nonce.hex(),
            'hmac': hmac_value.hex(),
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Sauvegarde via StorageManager
        meta_file = storage_manager.save_metadata(
            metadata,
            f"{filename}.meta",
            f"{algorithm}_{key_size}"  # sous-dossier
        )
        
        # Définit les permissions en lecture seule
        meta_file.chmod(0o444)  # r--r--r--
        
        print(f"✓ Métadonnées sauvegardées: {meta_file}")
        return meta_file, metadata
    except PermissionError as pe:
        print(f"❌ Erreur de permission: {str(pe)}")
        raise
    except Exception as e:
        print(f"❌ Erreur inattendue: {str(e)}")
        raise


# ----------------------------------------------------------------------------------
# 10. Fonction pour charger la clé privée
# ----------------------------------------------------------------------------------
def load_private_key(algorithm, key_size, storage_manager=None):
    if storage_manager is None:
        from utils.storage import storage_manager
    
    # Même logique de nommage que load_public_key
    if algorithm == "RSA":
        subfolder = f"RSA_{key_size}"
        filename = f"rsa_private_{key_size}.pem"
    elif algorithm == "ECC":
        if isinstance(key_size, str) and key_size.startswith("P-"):
            curve_id = key_size.replace("-", "_")
        else:
            curve_id = f"P_{key_size}"
        subfolder = f"ECC_{curve_id}"
        filename = f"ecc_private_{curve_id}.pem"
    elif algorithm == "ElGamal":
        subfolder = f"ElGamal_{key_size}"
        filename = f"elgamal_private_{key_size}.pem"
    else:
        raise ValueError(f"Algorithme non supporté: {algorithm}")
    
    key_file = storage_manager.get_file_path(filename, "keys_generated", subfolder)
    
    # Fallback pour private key
    if not key_file.exists():
        key_dir = storage_manager.get_directory("keys_generated") / subfolder
        if key_dir.exists():
            private_files = list(key_dir.glob("*private*.pem"))
            if private_files:
                key_file = private_files[0]
    
    if not key_file.exists():
        raise FileNotFoundError(f"❌ Aucune clé privée trouvée dans {key_file.parent}")

    with open(key_file, "rb") as f:
        pem_data = f.read()
        
        if algorithm == "RSA":
            return serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )
        elif algorithm == "ECC":
            key = serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise ValueError("❌ La clé chargée n'est pas une clé privée ECC valide")
            return key
        elif algorithm == "ElGamal":
            return serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )


# ----------------------------------------------------------------------------------
@measure_performance
def sign_file(file_path, algorithm, key_size, hash_name, storage_manager=None):
    """Signe un fichier avec l'algorithme spécifié via StorageManager"""
    if not hash_name:
        raise ValueError("Hash algorithm must be specified")
    if not algorithm or not key_size:
        raise ValueError("Algorithm and key size must be specified")
    if storage_manager is None:
        from utils.storage import storage_manager
    
    try:
        # Charger la clé privée
        private_key = load_private_key(algorithm, key_size, storage_manager)
        
        # Lire le contenu du fichier
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Signer selon l'algorithme
        hash_algo = get_hash_algorithm(hash_name)
        if algorithm == "RSA":
            signature = private_key.sign( # type: ignore
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hash_algo),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ), # type: ignore
                hash_algo
            )
        elif algorithm == "ECC":
            digest = hashes.Hash(hash_algo, backend=default_backend())
            digest.update(data)
            hashed_data = digest.finalize()
            signature = private_key.sign(  # type: ignore[arg-type]
                hashed_data,
                ec.ECDSA(utils.Prehashed(hash_algo)))
        elif algorithm == "ElGamal":
            digest = hashes.Hash(hash_algo, backend=default_backend())
            digest.update(data)
            hashed_data = digest.finalize()
            signature = private_key.sign(  # type: ignore[call-arg]
                hashed_data,
                padding.PKCS1v15())
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")
        # Sauvegarder la signature via StorageManager
        signature_path = storage_manager.save_file(
            signature,
            f"{os.path.basename(file_path)}.sig",
            "signed_files",
            f"{algorithm}_{key_size}"  # sous-dossier
        )
        
        print(f"🔏 Fichier signé: {signature_path}")
        return signature_path
        
    except Exception as e:
        print(f"❌ Erreur de signature: {str(e)}")
        raise


# ----------------------------------------------------------------------------------
# 12. Checker la permission des dossiers
# ----------------------------------------------------------------------------------
def check_folder_permissions(folder_path):
    """Vérifie les permissions de lecture/écriture sur un dossier"""
    if not os.path.isdir(folder_path):
        raise ValueError(f"Le chemin {folder_path} n'est pas un dossier valide")
    
    if not os.access(folder_path, os.R_OK | os.X_OK):
        raise PermissionError(f"Permission insuffisante pour lire le dossier {folder_path}")
    
    return True


# ----------------------------------------------------------------------------------
# 13. Clean les fichiers temporaires (notamment les ".DS_Store" hidden files)
# ----------------------------------------------------------------------------------
def cleanup_temp_files(folder_path):
    """Nettoie tous les fichiers .tmp et .DS_Store.tmp dans le dossier spécifié"""
    folder = Path(folder_path)
    for file_path in folder.glob("**/*.tmp"):
        try:
            if file_path.is_file():
                file_path.unlink()
                print(f"🗑️ Fichier temporaire supprimé: {file_path.name}")
        except Exception as e:
            print(f"⚠️ Erreur suppression {file_path.name}: {e}")

    # Suppression des fichiers .DS_Store.tmp
    for file_path in folder.glob("**/.DS_Store.tmp"):
        try:
            if file_path.is_file():
                file_path.unlink()
                print(f"🗑️ Fichier temporaire supprimé: {file_path.name}")
        except Exception as e:
            print(f"⚠️ Erreur suppression {file_path.name}: {e}")


# ----------------------------------------------------------------------------------
# 13. Clean les fichiers metadata (notamment les ".DS_Store" hidden files)
# ----------------------------------------------------------------------------------
def cleanup_metadata_files(storage_manager=None):
    """Nettoie les fichiers .DS_Store.meta dans les métadonnées"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    metadata_dir = storage_manager.get_directory("metadata")
    for file_path in metadata_dir.glob("**/.DS_Store.meta"):
        try:
            if file_path.is_file():
                file_path.unlink()
                print(f"🗑️ Métadonnée supprimée: {file_path.name}")
        except Exception as e:
            print(f"⚠️ Erreur suppression {file_path.name}: {e}")


# ----------------------------------------------------------------------------------
# 14. Clean les fichiers signés (notamment les ".DS_Store" hidden files)
# ----------------------------------------------------------------------------------
def cleanup_signature_files(storage_manager=None):
    """Nettoie les fichiers .DS_Store.sig dans les signatures"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    signed_dir = storage_manager.get_directory("signed_files")
    for file_path in signed_dir.glob("**/.DS_Store.sig"):
        try:
            if file_path.is_file():
                file_path.unlink()
                print(f"🗑️ Signature supprimée: {file_path.name}")
        except Exception as e:
            print(f"⚠️ Erreur suppression {file_path.name}: {e}")


def generate_encryption_graph(files, output_path):
    """Génère un graphique clair pour le chiffrement avec les spécifications demandées"""
    plt.figure(figsize=(12, 6))
    
    # Configuration du style
    plt.style.use('default')  # Style minimal sans grille de fond colorée
    plt.rcParams.update({
        'font.size': 8,       # Police plus petite
        'axes.titlesize': 10,
        'axes.labelsize': 9,
        'xtick.labelsize': 8,
        'ytick.labelsize': 8
    })
    
    # Préparation des données
    filenames = [f['filename'][:15]+'...' if len(f['filename']) > 15 else f['filename'] for f in files]
    encrypt_times = [f['steps'].get('encryption', 0) for f in files]
    file_sizes = [f.get('file_size_kb', 0)/1024 for f in files]  # Conversion en Mo
    
    # Création du graphique
    bars = plt.bar(filenames, encrypt_times, color='#1f77b4', alpha=0.7)
    plt.ylabel('Temps de chiffrement (s)', fontsize=9)
    plt.xlabel('Fichiers', fontsize=9)
    plt.title('Temps de chiffrement par fichier', fontsize=10, pad=12)
    plt.xticks(rotation=45, ha='right')
    
    # Ajout des valeurs et tailles (2 chiffres après la virgule)
    for bar, size in zip(bars, file_sizes):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height + 0.01,
                f'{height:.2f}s\n{size:.2f}Mo',
                ha='center', va='bottom', fontsize=7)
    
    # Suppression de la grille de fond colorée
    plt.grid(False)
    plt.gca().set_facecolor('white')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()



def generate_signing_graph(files, output_path):
    """Génère un graphique clair pour la signature avec les spécifications demandées"""
    plt.figure(figsize=(12, 6))
    
    # Configuration du style
    plt.style.use('default')
    plt.rcParams.update({
        'font.size': 8,
        'axes.titlesize': 10,
        'axes.labelsize': 9,
        'xtick.labelsize': 8,
        'ytick.labelsize': 8
    })
    
    # Préparation des données
    filenames = [f['filename'][:15]+'...' if len(f['filename']) > 15 else f['filename'] for f in files]
    sign_times = [f['steps'].get('signing', 0) for f in files]
    file_sizes = [f.get('file_size_kb', 0)/1024 for f in files]  # Conversion en Mo
    
    # Création du graphique
    bars = plt.bar(filenames, sign_times, color='#2ca02c', alpha=0.7)
    plt.ylabel('Temps de signature (s)', fontsize=9)
    plt.xlabel('Fichiers', fontsize=9)
    plt.title('Temps de signature par fichier', fontsize=10, pad=12)
    plt.xticks(rotation=45, ha='right')
    
    # Ajout des valeurs (2 chiffres après la virgule)
    for bar, size in zip(bars, file_sizes):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height + 0.01,
                f'{height:.2f}s\n{size:.2f}Mo',
                ha='center', va='bottom', fontsize=7)
    
    # Suppression de la grille de fond colorée
    plt.grid(False)
    plt.gca().set_facecolor('white')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()


def generate_asymmetric_keygen_graph(asymmetric_gen_time, output_path):
    """Graphique simple pour le temps de génération de la clé asymétrique"""
    plt.figure(figsize=(4, 6))
    plt.bar(['Clé asymétrique'], [asymmetric_gen_time], color='#9467bd')
    plt.ylabel('Temps (s)')
    plt.title('Temps de génération de la clé asymétrique')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def generate_phases_graph(files, output_path):
    plt.figure(figsize=(14, 7))
    plt.style.use('default')
    plt.rcParams.update({
        'font.size': 8,
        'axes.titlesize': 10,
        'axes.labelsize': 9,
        'xtick.labelsize': 8,
        'ytick.labelsize': 8,
        'legend.fontsize': 8
    })

    filenames = [f['filename'][:15]+'...' if len(f['filename']) > 15 else f['filename'] for f in files]
    phases = ['aes_key_gen', 'key_wrapping', 'encryption', 'validation', 'signing']
    phase_labels = ['Génération AES', 'Chiffrement clé AES', 'Chiffrement fichier', 'Hachage', 'Signature']
    colors = ['#ff7f0e', '#17becf', '#1f77b4', '#d62728', '#2ca02c']

    bar_width = 0.15
    indices = np.arange(len(filenames))

    for i, (phase, label) in enumerate(zip(phases, phase_labels)):
        times = [f['steps'].get(phase, 0) for f in files]
        plt.bar(indices + i*bar_width, times, bar_width, label=label, color=colors[i], alpha=0.8)

    plt.ylabel('Temps (s)')
    plt.xlabel('Fichiers')
    plt.title('Détail des temps par phase')
    plt.xticks(indices + bar_width*2, filenames, rotation=45, ha='right')
    plt.legend(fontsize=8, bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(False)
    plt.gca().set_facecolor('white')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()   


def generate_overhead_percent_graph(files, output_path):
    data = _get_overhead_data(files)
    if not data:
        return

    names = [d['name'] for d in data]
    overheads = [d['overhead'] for d in data]
    orig_bytes = [d['orig_bytes'] for d in data]

    def fmt_size(octets):
        if octets < 1024:        return f"{octets} o"
        elif octets < 1024**2:   return f"{octets/1024:.1f} Ko"
        elif octets < 1024**3:   return f"{octets/1024**2:.1f} Mo"
        else:                    return f"{octets/1024**3:.1f} Go"

    plt.figure(figsize=(12, 6))
    bars = plt.bar(names, overheads, color='#2ca02c')
    plt.axhline(y=0, color='gray', linestyle='--')
    plt.ylabel('Overhead (%)')
    plt.title('Overhead de chiffrement par fichier')
    plt.xticks(rotation=45, ha='right')

    max_over = max(overheads) if overheads else 1
    for bar, size_bytes in zip(bars, orig_bytes):
        height = bar.get_height()
        y_pos = height + max_over * 0.02 if height >= 0 else height - max_over * 0.02
        va = 'bottom' if height >= 0 else 'top'
        plt.text(bar.get_x() + bar.get_width()/2, y_pos,
                 f'{height:.1f}%\n{fmt_size(size_bytes)}',
                 ha='center', va=va, fontsize=6, color='black')

    plt.grid(axis='y', linestyle=':', alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()

def generate_overhead_size_comparison_graph(files, output_path):
    data = _get_overhead_data(files)
    if not data:
        return

    names = [d['name'] for d in data]
    orig_bytes = [d['orig_bytes'] for d in data]
    enc_bytes = [d['enc_bytes'] for d in data]

    # Choix automatique de l'unité
    max_val = max(max(orig_bytes), max(enc_bytes))
    if max_val < 1024:
        scale, unit = 1, 'o'
    elif max_val < 1024**2:
        scale, unit = 1024, 'Ko'
    elif max_val < 1024**3:
        scale, unit = 1024**2, 'Mo'
    else:
        scale, unit = 1024**3, 'Go'

    orig_scaled = [o / scale for o in orig_bytes]
    enc_scaled = [e / scale for e in enc_bytes]

    x = np.arange(len(names))
    width = 0.35
    plt.figure(figsize=(12, 6))
    bars1 = plt.bar(x - width/2, orig_scaled, width, label='Original')
    bars2 = plt.bar(x + width/2, enc_scaled, width, label='Chiffré')
    plt.xticks(x, names, rotation=45, ha='right')
    plt.ylabel(f'Taille ({unit})')
    plt.title('Comparaison taille originale vs chiffrée')
    plt.legend()

    for bar, val in zip(bars1, orig_scaled):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(orig_scaled)*0.01,
                 f'{val:.1f}', ha='center', va='bottom', fontsize=6)
    for bar, val in zip(bars2, enc_scaled):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(enc_scaled)*0.01,
                 f'{val:.1f}', ha='center', va='bottom', fontsize=6)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()

def generate_overhead_scatter_graph(files, output_path):
    data = _get_overhead_data(files)
    if not data:
        return

    orig_bytes = [d['orig_bytes'] for d in data]
    overheads = [d['overhead'] for d in data]

    # Conversion des tailles en Ko pour l'axe des X
    orig_kb = [o / 1024 for o in orig_bytes]

    plt.figure(figsize=(10, 6))
    plt.scatter(orig_kb, overheads, c='#d62728')
    plt.xlabel('Taille originale (Ko)')
    plt.ylabel('Overhead (%)')
    plt.title('Impact de la taille sur l\'overhead')

    if len(orig_kb) > 1:
        z = np.polyfit(orig_kb, overheads, 1)
        p = np.poly1d(z)
        plt.plot(orig_kb, p(orig_kb), "r--")

    plt.grid(True, linestyle=':', alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()

def set_plot_style():
    """Configure le style des graphiques de manière robuste"""
    try:
        available_styles = plt.style.available
        preferred_styles = [
            'seaborn-v0_8',  # Matplotlib >= 3.6
            'seaborn',       # Anciennes versions
            'ggplot',        # Alternative populaire
            'default'        # Style de base
        ]
        
        for style in preferred_styles:
            if style in available_styles:
                plt.style.use(style)
                print(f"Style utilisé: {style}")
                return
        
        print("⚠️ Aucun style préféré disponible, utilisation du style par défaut")
        plt.style.use('default')
    except Exception as e:
        print(f"Erreur configuration style: {e}")
        plt.style.use('default')

# Dans generate_performance_graphs():
set_plot_style()


def generate_performance_graphs(result_data, algo_id, timestamp, output_root, storage_manager=None):
    """Génère les visualisations de performance améliorées"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    try:
        # Configuration du style
        set_plot_style()
        
        # Créer le dossier graphs d'abord
        graph_dir = storage_manager.get_directory("performance_outputs") / "graphs" / algo_id
        graph_dir.mkdir(parents=True, exist_ok=True)  # ← Créer récursivement
        
        # Filtrage des fichiers
        files = [f for f in result_data['file_details'] if not f['filename'].startswith('.')]
        if not files:
            print("⚠️ Aucun fichier valide pour les graphiques")
            return
        
        # Génération des graphiques
        generate_encryption_graph(
            files,
            str(graph_dir / f"encryption_stats_{timestamp}.png")
        )
        
        generate_signing_graph(
            files,
            str(graph_dir / f"signing_stats_{timestamp}.png")
        )
        
        generate_phases_graph(
            files,
            str(graph_dir / f"phases_detail_{timestamp}.png")
        )
        
        print(f"✅ Graphiques générés dans: {graph_dir}")
        
    except Exception as e:
        print(f"❌ Erreur génération graphiques: {str(e)}")
        import traceback
        traceback.print_exc()


def generate_performance_report(result_data, algo_id, timestamp, output_root, storage_manager=None):
    """Génère un rapport PDF détaillé avec statistiques et graphiques"""
    if storage_manager is None:
        from utils.storage import storage_manager
        
    try:
        # Créer le dossier reports d'abord
        report_dir = storage_manager.get_directory("performance_outputs") / "reports" / algo_id
        report_dir.mkdir(parents=True, exist_ok=True)
        
        from fpdf import FPDF
        import unicodedata

        def clean_text(text):
            """Normalise le texte pour les polices non-Unicode"""
            return unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii') if text else ""
        
        class PDF(FPDF):
            def __init__(self):
                super().__init__()
                # Chemin vers les polices Unicode (à adapter selon votre système)
                self.font_dir = os.path.join(os.path.dirname(__file__), 'fonts')
                
            def header(self):
                if hasattr(self, 'unicode_font'):
                    self.set_font(self.unicode_font, '', 12)
                else:
                    self.set_font('Arial', 'B', 12)
                self.cell(0, 10, clean_text(f'Rapport de Performance - {algo_id}'),
                          new_x="LMARGIN", new_y="next", align='C')
                self.set_font('', '', 8)
                self.cell(0, 6, clean_text(f"Généré le {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M')}"),
                          new_x="LMARGIN", new_y="next", align='C')
                self.ln(8)
                
            def footer(self):
                self.set_y(-15)
                self.set_font('', 'I', 8)
                self.cell(0, 10, f'Page {self.page_no()}', align='C')

            def try_add_unicode_font(self):
                """Tente d'ajouter une police Unicode"""
                try:
                    for font in ['DejaVuSansCondensed', 'ArialUnicode', 'FreeSans']:
                        font_path = os.path.join(self.font_dir, f"{font}.ttf")
                        if os.path.exists(font_path):
                            self.add_font(font, '', font_path, unicode=True)
                            self.unicode_font = font
                            return True
                    return False
                except:
                    return False

        # Initialisation du PDF
        pdf = PDF()

        if not pdf.try_add_unicode_font():
            print("⚠️ Police Unicode non trouvée, utilisation de la police standard (certains caractères peuvent ne pas s'afficher)")

        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Style de base
        current_font = getattr(pdf, 'unicode_font', 'Arial')
        pdf.set_font(current_font, '', 10)
        
        # 1. Page de résumé général
        pdf.set_font('', 'B', 12)
        pdf.cell(0, 8, "Résumé Global", 0, 1)
        pdf.set_font('', '', 10)
        
        # Métadonnées de l'opération
        meta_data = [
            ("Dossier traité", result_data['metadata']['folder_path']),
            ("Algorithme utilisé", algo_id),
            ("Date de traitement", result_data['metadata']['start_time']),
            ("Fichiers traités", str(result_data['processed_files'])),
            ("Fichiers en échec", str(result_data['failed_files'])),
            ("Temps total", f"{result_data['timings']['total']:.2f} secondes"),
            ("Temps moyen par fichier", f"{result_data['timings']['total']/max(1, result_data['processed_files']):.2f} secondes")
        ]
        
        for label, value in meta_data:
            pdf.cell(40, 6, label + ":", 0, 0)
            pdf.set_font('', 'B', 10)
            pdf.cell(0, 6, value, 0, 1)
            pdf.set_font('', '', 10)
        
        pdf.ln(10)
        
        # 2. Détails par fichier
        pdf.add_page()
        pdf.set_font('', 'B', 12)
        pdf.cell(0, 8, "Détails par Fichier", 0, 1)
        pdf.set_font('', '', 8)
        
        # En-tête du tableau
        pdf.set_fill_color(200, 200, 200)
        pdf.cell(60, 6, "Fichier", border=1, align='C', fill=True)
        pdf.cell(20, 6, "Taille (Mo)", border=1, align='C', fill=True)
        pdf.cell(20, 6, "Chiffrement", border=1, align='C', fill=True)
        pdf.cell(20, 6, "Signature", border=1, align='C', fill=True)
        pdf.cell(20, 6, "Total", border=1, align='C', fill=True)
        pdf.cell(40, 6, "Statut", border=1, align='C', fill=True, new_x="LMARGIN", new_y="next")
    
        # Données des fichiers
        pdf.set_font('', '', 8)
        for file_data in result_data['file_details']:
            if file_data['filename'].startswith('.'):
                continue
                
            pdf.cell(60, 6, clean_text(file_data['filename'][:40]) + ('...' if len(file_data['filename']) > 40 else ''), 1)
            pdf.cell(20, 6, f"{file_data.get('file_size_kb', 0)/1024:.2f}", 1, 0, 'R')
            pdf.cell(20, 6, f"{file_data['steps'].get('encryption', 0):.2f}s", 1, 0, 'R')
            pdf.cell(20, 6, f"{file_data['steps'].get('signing', 0):.2f}s", 1, 0, 'R')
            pdf.cell(20, 6, f"{file_data['time']:.2f}s", 1, 0, 'R')
            pdf.cell(40, 6, clean_text("Dossier traité") + ":", new_x="RIGHT", new_y="current")
            pdf.set_font('', 'B', 10)
            pdf.cell(0, 6, result_data['metadata']['folder_path'], new_x="LMARGIN", new_y="next")
            
            if file_data['success']:
                pdf.set_text_color(0, 128, 0)
                pdf.cell(40, 6, "SUCCÈS", 1, 1, 'C')
            else:
                pdf.set_text_color(255, 0, 0)
                pdf.cell(40, 6, f"ÉCHEC: {file_data['error'][:30]}", 1, 1, 'C')
            pdf.set_text_color(0, 0, 0)
        
        pdf.ln(10)
        
        # 3. Graphiques
        graphs_dir = os.path.join(output_root, "graphs", algo_id)
        
        # Graphique de chiffrement
        enc_graph = os.path.join(graphs_dir, f"encryption_stats_{timestamp}.png")
        if os.path.exists(enc_graph):
            pdf.add_page()
            pdf.set_font('', 'B', 12)
            pdf.cell(0, 8, "Performances de Chiffrement", 0, 1)
            pdf.image(enc_graph, x=10, w=190)
            pdf.ln(2)
            pdf.set_font('', 'I', 8)
            pdf.multi_cell(0, 5, "Temps de chiffrement par fichier avec indication de la taille des fichiers.")
        
        # Graphique de signature
        sig_graph = os.path.join(graphs_dir, f"signing_stats_{timestamp}.png")
        if os.path.exists(sig_graph):
            pdf.add_page()
            pdf.set_font('', 'B', 12)
            pdf.cell(0, 8, "Performances de Signature", 0, 1)
            pdf.image(sig_graph, x=10, w=190)
            pdf.ln(2)
            pdf.set_font('', 'I', 8)
            pdf.multi_cell(0, 5, "Temps de signature par fichier avec indication de la taille des fichiers.")
        
        # Graphique des phases
        phases_graph = os.path.join(graphs_dir, f"phases_detail_{timestamp}.png")
        if os.path.exists(phases_graph):
            pdf.add_page()
            pdf.set_font('', 'B', 12)
            pdf.cell(0, 8, "Détail des Phases de Traitement", 0, 1)
            pdf.image(phases_graph, x=10, w=190)
            pdf.ln(2)
            pdf.set_font('', 'I', 8)
            pdf.multi_cell(0, 5, "Répartition du temps de traitement pour chaque phase opérationnelle.")
        
        # 4. Statistiques détaillées
        pdf.add_page()
        pdf.set_font('', 'B', 12)
        pdf.cell(0, 8, "Statistiques Avancées", 0, 1)
        pdf.set_font('', '', 10)
        
        # Calcul des statistiques
        if result_data['file_details']:
            files = [f for f in result_data['file_details'] if not f['filename'].startswith('.')]
            total_sizes = [f.get('file_size_kb', 0)/1024 for f in files]
            encrypt_times = [f['steps'].get('encryption', 0) for f in files]
            sign_times = [f['steps'].get('signing', 0) for f in files]
            
            stats = [
                ("Taille moyenne des fichiers", f"{np.mean(total_sizes):.2f} Mo"),
                ("Taille maximale", f"{max(total_sizes):.2f} Mo"),
                ("Taille minimale", f"{min(total_sizes):.2f} Mo"),
                ("", ""),
                ("Temps moyen de chiffrement", f"{np.mean(encrypt_times):.2f} s"),
                ("Temps max de chiffrement", f"{max(encrypt_times):.2f} s"),
                ("Temps min de chiffrement", f"{min(encrypt_times):.2f} s"),
                ("", ""),
                ("Temps moyen de signature", f"{np.mean(sign_times):.2f} s"),
                ("Temps max de signature", f"{max(sign_times):.2f} s"),
                ("Temps min de signature", f"{min(sign_times):.2f} s")
            ]
            
            for label, value in stats:
                if label:  # Skip empty lines
                    pdf.cell(50, 6, label + ":", 0, 0)
                    pdf.set_font('', 'B', 10)
                    pdf.cell(30, 6, value, 0, 1)
                    pdf.set_font('', '', 10)
                else:
                    pdf.ln(4)
        
        # Sauvegarde du rapport
        report_file = report_dir / f"full_report_{timestamp}.pdf"
        pdf.output(str(report_file))
        
        print(f"📊 Rapport complet généré: {report_file}")
        
    except Exception as e:
        print(f"❌ Erreur génération rapport: {str(e)}")
        import traceback
        traceback.print_exc()

def generate_asymmetric_keygen_graph(asymmetric_gen_time, output_path):
    plt.figure(figsize=(4, 6))
    plt.bar(['Clé asymétrique'], [asymmetric_gen_time], color='#9467bd')
    plt.ylabel('Temps (s)')
    plt.title('Temps de génération de la clé asymétrique')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

def generate_aes_keygen_graph(files, output_path):
    """Temps de génération AES par fichier – annotations lisibles"""
    plt.figure(figsize=(12, 6))
    plt.style.use('default')
    plt.rcParams.update({
        'font.size': 8, 'axes.titlesize': 10, 'axes.labelsize': 9,
        'xtick.labelsize': 8, 'ytick.labelsize': 8
    })

    filenames = [f['filename'][:15]+'...' if len(f['filename']) > 15 else f['filename'] for f in files]
    aes_times = [f['steps'].get('aes_key_gen', 0) for f in files]
    file_sizes_mb = [f.get('file_size_kb', 0) / 1024 for f in files]   # en Mo

    bars = plt.bar(filenames, aes_times, color='#ff7f0e', alpha=0.7)
    plt.ylabel('Temps de génération AES (s)')
    plt.xlabel('Fichiers')
    plt.title('Génération de la clé AES par fichier')
    plt.xticks(rotation=45, ha='right')

    max_time = max(aes_times) if aes_times else 1
    offset = max_time * 0.02
    for bar, size in zip(bars, file_sizes_mb):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height + offset,
                 f'{height:.4f}s\n{size:.2f} Mo',
                 ha='center', va='bottom', fontsize=6, color='black')

    plt.grid(axis='y', linestyle=':', alpha=0.5)
    plt.gca().set_facecolor('white')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()

def generate_decryption_graph(decrypt_details, output_path):
    """Génère un graphique pour le temps de déchiffrement par fichier"""
    plt.figure(figsize=(12, 6))
    plt.style.use('default')
    plt.rcParams.update({
        'font.size': 8,
        'axes.titlesize': 10,
        'axes.labelsize': 9,
        'xtick.labelsize': 8,
        'ytick.labelsize': 8
    })
    filenames = [f['filename'][:15]+'...' if len(f['filename']) > 15 else f['filename'] for f in decrypt_details]
    dec_times = [f.get('decrypt_time', 0) for f in decrypt_details]
    
    bars = plt.bar(filenames, dec_times, color='#9467bd', alpha=0.7)
    plt.ylabel('Temps de déchiffrement (s)', fontsize=9)
    plt.xlabel('Fichiers', fontsize=9)
    plt.title('Temps de déchiffrement par fichier', fontsize=10, pad=12)
    plt.xticks(rotation=45, ha='right')
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, height + 0.001,
                f'{height:.4f}s', ha='center', va='bottom', fontsize=7)
    plt.grid(False)
    plt.gca().set_facecolor('white')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()

def save_metrics_json(result_data, operation_id, storage_manager=None):
    """
    Compile les métriques de l'opération et les sauvegarde au format JSON.
    - Ne crée le fichier que si l'opération est un succès (≥ 1 fichier traité, sans erreur fatale).
    - Stocke le JSON dans : vault_data/metrics_graphs/{algo_keysize}/{operation_id}.json
    - + copie locale dans vault_data/runs/{operation_id}/metrics.json
    - Calcule le repetition_index basé uniquement sur les opérations réussies.
    """
    if storage_manager is None:
        from utils.storage import storage_manager

    algorithm = result_data['metadata']['algorithm']
    key_size = result_data['metadata']['key_size']
    timestamp = result_data['metadata'].get('timestamp') or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    folder_path = result_data['metadata'].get('folder_path', '')
    storage_location = str(storage_manager.base_dir)
    hash_algorithm = result_data['metadata'].get('hash_algorithm') or 'SHA-256'
    operation_type = result_data['metadata'].get('operation_type', 'unknown')

    # Vérification du succès global : au moins un fichier traité et pas d'erreur bloquante
    files_processed = result_data.get('processed_files', 0)
    global_success = files_processed > 0 and result_data.get('error') is None
    if not global_success:
        print(f"⚠️  Opération {operation_id} non réussie (fichiers={files_processed}, erreur={result_data.get('error')}). Aucun JSON sauvegardé.")
        return None

    # --- Enrichissement des détails (overhead) ---
    overheads = []
    for file in result_data.get('file_details', []):
        if file.get('success') and file.get('encrypted_path') and file.get('original_path'):
            try:
                orig_size = os.path.getsize(file['original_path'])
                enc_size = os.path.getsize(file['encrypted_path'])
                file['original_size_bytes'] = orig_size
                file['encrypted_size_bytes'] = enc_size
                if orig_size > 0:
                    oh = ((enc_size - orig_size) / orig_size) * 100
                    file['overhead_percent'] = oh
                    overheads.append(oh)
                else:
                    file['overhead_percent'] = 0.0
                    overheads.append(0.0)
            except Exception:
                pass

    # --- Métriques système ---
    op_id = result_data.get('op_id')
    cpu_samples, ram_samples = [], []
    if op_id:
        op_data = perf_tracker.operations.get(op_id, {})
        raw_system = op_data.get('system_metrics', {})
        cpu_samples = raw_system.get('cpu_samples', [])
        ram_samples = raw_system.get('ram_samples', [])

    cpu_mean = float(np.mean(cpu_samples)) if cpu_samples else 0.0
    cpu_std = float(np.std(cpu_samples)) if len(cpu_samples) > 1 else 0.0
    ram_max = float(np.max(ram_samples)) if ram_samples else 0.0
    ram_mean = float(np.mean(ram_samples)) if ram_samples else 0.0

    # --- Temps des phases ---
    file_details = result_data.get('file_details', [])
    keygen_times = [f['steps'].get('aes_key_gen', 0) + f['steps'].get('key_wrapping', 0) for f in file_details if 'steps' in f]
    encap_times = [f['steps'].get('encryption', 0) for f in file_details if 'steps' in f]
    sign_times = [f['steps'].get('signing', 0) for f in file_details if 'steps' in f]
    dec_times = result_data.get('_dec_times', [])
    verif_times = result_data.get('_verif_times', [])

    avg_keygen = float(np.mean(keygen_times)) if keygen_times else 0.0
    avg_encap = float(np.mean(encap_times)) if encap_times else 0.0
    avg_sign = float(np.mean(sign_times)) if sign_times else 0.0
    avg_dec = float(np.mean(dec_times)) if dec_times else 0.0
    avg_verif = float(np.mean(verif_times)) if verif_times else 0.0
    total_time = float(result_data.get('timings', {}).get('total', 0.0))

    # --- Calcul du repetition_index basé sur les opérations réussies précédentes ---
    metrics_graphs_dir = storage_manager.get_metrics_graphs_dir() / f"{algorithm}_{key_size}"
    metrics_graphs_dir.mkdir(parents=True, exist_ok=True)
    successful_runs = 0
    for f in metrics_graphs_dir.glob("*.json"):
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
                if data.get('success', False):
                    successful_runs += 1
        except Exception:
            pass
    repetition_index = successful_runs + 1  # +1 pour l'opération courante

    # --- Données de calibration pour l'assistant de décision ---
    calibration_sizes = []
    calibration_times = []
    for f in file_details:
        if f.get('success') and f.get('original_size_bytes') and f.get('steps', {}).get('encryption'):
            calibration_sizes.append(f['original_size_bytes'])
            calibration_times.append(f['steps']['encryption'])

    calibration_data = None
    if calibration_sizes:
        # Conserver un échantillon de 100 points maximum
        indices = np.argsort(calibration_sizes)
        step = max(1, len(indices) // 100)
        sample_idx = indices[::step][:100]
        calibration_data = {
            'file_sizes_bytes': [calibration_sizes[i] for i in sample_idx],
            'encryption_times_sec': [calibration_times[i] for i in sample_idx],
            'description': 'Échantillon (taille_fichier, temps_chiffrement) pour régression'
        }
    
    # --- Construction de l'objet métrique ---
    compiled_metrics = {
        "metadata": {
            "operation_id": operation_id,
            "operation_type": operation_type,
            "algorithm": algorithm,
            "key_size": key_size,
            "timestamp": timestamp,
            "folder_path": folder_path,
            "storage_location": storage_location,
            "hash_algorithm": hash_algorithm,
            "repetition_index": repetition_index
        },
        "timings": {
            "key_generation": avg_keygen,
            "encapsulation": avg_encap,
            "signature": avg_sign,
            "verification": avg_verif,
            "decapsulation": avg_dec,
            "total": total_time
        },
        "resources": {
            "cpu_mean": cpu_mean,
            "cpu_std": cpu_std,
            "ram_max": ram_max,
            "ram_mean": ram_mean
        },
        "overhead": float(np.mean(overheads)) if overheads else 0.0,
        "files_processed": files_processed,
        "success": True, # toujours True ici car on ne sauvegarde que si succès
        "calibration": calibration_data 
    }

    # --- Sauvegarde du JSON principal ---
    global_metrics_path = metrics_graphs_dir / f"{operation_id}.json"
    # Gestion de conflit
    if global_metrics_path.exists():
        old_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        old_path = metrics_graphs_dir / f"{operation_id}_old_{old_ts}.json"
        try:
            global_metrics_path.rename(old_path)
        except Exception:
            pass

    with open(global_metrics_path, 'w', encoding='utf-8') as f:
        json.dump(compiled_metrics, f, indent=4, ensure_ascii=False)
    print(f"✅ Métriques sauvegardées : {global_metrics_path}")

    # --- Copie locale dans runs/{operation_id}/metrics.json ---
    local_metrics_path = storage_manager.base_dir / "runs" / operation_id / "metrics.json"
    local_metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with open(local_metrics_path, 'w', encoding='utf-8') as f:
        json.dump(compiled_metrics, f, indent=4, ensure_ascii=False)
    print(f"✅ Copie locale sauvegardée : {local_metrics_path}")

    return global_metrics_path

def generate_performance_outputs(result_data, algorithm, key_size, operation_type="encryption_and_signature", storage_manager=None):
    if storage_manager is None:
        from utils.storage import storage_manager

    print(f"\n=== GENERATION DES OUTPUTS ({operation_type}) ===")
    try:
        algo_id = f"{algorithm}_{key_size}"
        timestamp_ms = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        operation_id = f"{algo_id}_{timestamp_ms}"

        graphs_dir = storage_manager.get_directory("performance_outputs") / "graphs" / algo_id
        graphs_dir.mkdir(parents=True, exist_ok=True)

        resources_sys_dir = storage_manager.get_directory("performance_resources") / algo_id / "system_metrics"
        resources_sys_dir.mkdir(parents=True, exist_ok=True)

        # Métriques système
        op_id = result_data.get('op_id')
        system_metrics_data = {}
        if op_id:
            op_data = perf_tracker.operations.get(op_id, {})
            system_metrics_data = op_data.get('system_metrics', {})

        # Mesure directe déchiffrement/vérification (pour chiffrement+signature)
        decrypt_details = []
        verif_times = []
        if operation_type == "encryption_and_signature":
            print("⚙️  Mesure en direct des phases de Déchiffrement et Vérification...")
            try:
                from handlers.verify import verify_signature
                from handlers.decrypt import decrypt_file, load_metadata, decrypt_aes_key
                encrypted_keys = result_data.get('encrypted_files', [])
                signature_paths = result_data.get('signed_files', [])
                for enc_p, sig_p in zip(encrypted_keys, signature_paths):
                    if os.path.exists(enc_p) and os.path.exists(sig_p):
                        sub_start = time.time()
                        verify_signature(enc_p, sig_p, algorithm, key_size)
                        verif_times.append(time.time() - sub_start)
                for enc_p in encrypted_keys:
                    if os.path.exists(enc_p):
                        sub_start = time.time()
                        meta = load_metadata(enc_p, algorithm, key_size)
                        aes_key = decrypt_aes_key(meta['encrypted_key'], algorithm, key_size)
                        temp_dec = decrypt_file(enc_p, aes_key, meta['nonce'], meta['file_type'].lower(), meta.get('_header_size', 0))
                        decrypt_details.append({
                            'filename': os.path.basename(enc_p),
                            'decrypt_time': time.time() - sub_start
                        })
                        if os.path.exists(temp_dec):
                            os.unlink(temp_dec)
            except Exception as sim_ex:
                print(f"⚠️  Simulation de déchiffrement/vérification incomplète : {sim_ex}")
            result_data['_dec_times'] = [d['decrypt_time'] for d in decrypt_details]
            result_data['_verif_times'] = verif_times

        files = [f for f in result_data.get('file_details', []) if not f['filename'].startswith('.')]

        # Génération conditionnelle des graphiques
        if operation_type == "encryption_and_signature":
            if files:
                generate_encryption_graph(files, str(graphs_dir / "encryption_stats.png"))
                generate_signing_graph(files, str(graphs_dir / "signing_stats.png"))
                generate_phases_graph(files, str(graphs_dir / "phases_detail.png"))
                # Graphiques de génération de clés
                generate_aes_keygen_graph(files, str(graphs_dir / "aes_keygen_time.png"))
                asym_time = result_data.get('asymmetric_gen_time')
                if asym_time is not None:
                    generate_asymmetric_keygen_graph(asym_time, str(graphs_dir / "asymmetric_keygen_time.png"))
                # Overhead
                generate_overhead_percent_graph(files, str(graphs_dir / "overhead_percent.png"))
                generate_overhead_size_comparison_graph(files, str(graphs_dir / "overhead_size_comparison.png"))
                generate_overhead_scatter_graph(files, str(graphs_dir / "overhead_scatter.png"))
        elif operation_type == "decryption":
            if decrypt_details:
                generate_decryption_graph(decrypt_details, str(graphs_dir / "decryption_stats.png"))
        elif operation_type == "verification":
            if verif_times:
                plt.figure(figsize=(12, 6))
                plt.bar(range(len(verif_times)), verif_times, color='#d62728')
                plt.xlabel('Fichier')
                plt.ylabel('Temps (s)')
                plt.title('Temps de vérification par fichier')
                plt.tight_layout()
                plt.savefig(str(graphs_dir / "verification_stats.png"), dpi=150)
                plt.close()

        # Métriques système toujours générées
        if system_metrics_data and op_id:
            generate_system_metrics_analysis(system_metrics_data, str(resources_sys_dir), "system_metrics")
            generated_files = sorted(resources_sys_dir.glob("system_metrics_*.png"))
            if generated_files:
                latest = generated_files[-1]
                target = resources_sys_dir / "system_metrics.png"
                if target.exists():
                    target.unlink()
                latest.rename(target)

        # Sauvegarde JSON
        result_data['metadata']['operation_type'] = operation_type
        save_metrics_json(result_data, operation_id, storage_manager)

        print(f"✅ Sorties de performance sauvegardées dans : {graphs_dir}")
        print(f"✅ Métriques système dans : {resources_sys_dir}")

    except Exception as e:
        print(f"\n❌ ERREUR CRITIQUE dans generate_performance_outputs : {str(e)}")
        import traceback
        traceback.print_exc()


def setup_output_dirs(base_dir, algorithm, key_size):
    """Organise les dossiers de sortie"""
    algo_id = f"{algorithm}_{key_size}"
    dirs = {
        'base': os.path.join(base_dir, algo_id),
        'system_metrics': os.path.join(base_dir, algo_id, "system_metrics"),
        # 'cpu': os.path.join(base_dir, algo_id, "cpu_metrics"),  # Ajouté
        # 'ram': os.path.join(base_dir, algo_id, "ram_metrics"),  # Ajouté
        'overhead': os.path.join(base_dir, algo_id, "overhead_analysis"),
        'reports': os.path.join(base_dir, algo_id, "Reports")
    }
    
    for dir_path in dirs.values():
        os.makedirs(dir_path, exist_ok=True)
        
    return dirs


def generate_cpu_analysis(metrics, file_details, output_dir, timestamp):
    """Génère tous les graphiques liés au CPU"""
    # 1. Charge CPU globale
    plt.figure(figsize=(12, 6))
    plt.plot(metrics['timestamps'], metrics['cpu_samples'], 'r-', linewidth=1.5)
    plt.title("Charge CPU pendant l'opération")
    plt.ylabel("Utilisation CPU (%)")
    plt.xlabel("Temps (s)")
    plt.grid(True, linestyle=':', alpha=0.7)
    plt.savefig(os.path.join(output_dir, f"cpu_global_{timestamp}.png"), dpi=120)
    plt.close()

    # 2. Charge CPU par fichier
    if file_details:
        fig, ax = plt.subplots(figsize=(14, 6))
        
        # Créer une timeline
        for i, file in enumerate(file_details):
            if file['success']:
                # Utiliser get() avec des valeurs par défaut
                start = file.get('start_time', 0)
                end = file.get('end_time', start + 1)  # 1 seconde par défaut si end_time manquant
                avg_cpu = np.mean(metrics['cpu_samples'])
                
                # Vérifier que les timestamps sont valides
                if start > 0 and end > start:
                    ax.barh(i, end-start, left=start, color='salmon', alpha=0.6)
                    ax.text(start + (end-start)/2, i, 
                          f"{file['filename'][:10]}...\n{avg_cpu:.1f}%", 
                          ha='center', va='center')
        
        ax.set_yticks(range(len(file_details)))
        ax.set_yticklabels([f['filename'][:15]+'...' for f in file_details])
        ax.set_title("Charge CPU par fichier")
        ax.set_xlabel("Temps (s)")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"cpu_par_fichier_{timestamp}.png"), dpi=120)
        plt.close()


def generate_ram_analysis(metrics, file_details, output_dir, timestamp):
    """Génère tous les graphiques liés à la mémoire"""
    # 1. Consommation RAM globale
    plt.figure(figsize=(12, 6))
    plt.plot(metrics['timestamps'], metrics['ram_samples'], 'b-', linewidth=1.5)
    plt.title("Consommation RAM pendant l'opération")
    plt.ylabel("Mémoire utilisée (MB)")
    plt.xlabel("Temps (s)")
    plt.grid(True, linestyle=':', alpha=0.7)
    plt.savefig(os.path.join(output_dir, f"ram_global_{timestamp}.png"), dpi=120)
    plt.close()

    # 2. Allocation mémoire par fichier
    if file_details:
        fig, ax = plt.subplots(figsize=(14, 6))
        
        ram_usage = []
        filenames = []
        for file in file_details:
            if file['success']:
                ram_usage.append(np.mean(metrics['ram_samples']))
                filenames.append(file['filename'][:15]+'...')
        
        bars = ax.barh(filenames, ram_usage, color='skyblue')
        ax.bar_label(bars, fmt='%.1f MB')
        ax.set_title("Utilisation RAM par fichier")
        ax.set_xlabel("Mémoire moyenne utilisée (MB)")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"ram_par_fichier_{timestamp}.png"), dpi=120)
        plt.close()


def generate_system_resources_plot(result_data, algorithm, key_size, storage_manager=None):
    """Génère un graphique complet des ressources système"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    try:
        # Récupération des données de performance
        op_id = result_data.get('op_id', None)
        if not op_id:
            print("⚠️ Aucun ID d'opération trouvé pour les métriques système")
            return

        metrics = perf_tracker.operations.get(op_id, {}).get('system_metrics', {})
        if not metrics or 'timestamps' not in metrics:
            print("⚠️ Données système insuffisantes")
            return

        # Création de la figure
        plt.figure(figsize=(15, 10))
        plt.suptitle(f"Utilisation des Ressources Système - {algorithm} {key_size}", fontsize=16, y=1.02)

        # 1. CPU avec phases
        ax1 = plt.subplot(2, 1, 1)
        ax1.plot(metrics['timestamps'], metrics['cpu_samples'], 'r-', linewidth=2, label='CPU %')
        
        # Marquage des phases
        phases = {
            'Setup': (result_data['timings'].get('setup_initialization', 0), 
                     result_data['timings'].get('setup', 0)),
            'Traitement': (result_data['timings'].get('setup', 0),
                     result_data['timings'].get('setup', 0) + result_data['timings'].get('processing', 0)),
            'Nettoyage': (result_data['timings'].get('setup', 0) + result_data['timings'].get('processing', 0),
                     result_data['timings'].get('total', 0))
        }
        
        colors = ['#1f77b4', '#2ca02c', '#9467bd']
        for (label, (start, end)), color in zip(phases.items(), colors):
            ax1.axvspan(start, end, alpha=0.1, color=color)
            ax1.text((start + end)/2, max(metrics['cpu_samples'])*0.9, label, 
                    ha='center', backgroundcolor='white')
        
        ax1.set_ylabel('Utilisation CPU (%)')
        ax1.grid(True, linestyle=':', alpha=0.5)
        ax1.legend()

        # 2. RAM avec phases
        ax2 = plt.subplot(2, 1, 2)
        ax2.plot(metrics['timestamps'], metrics['ram_samples'], 'b-', linewidth=2, label='RAM (MB)')
        
        for (label, (start, end)), color in zip(phases.items(), colors):
            ax2.axvspan(start, end, alpha=0.1, color=color)
        
        ax2.set_xlabel('Temps (secondes)')
        ax2.set_ylabel('Utilisation Mémoire (MB)')
        ax2.grid(True, linestyle=':', alpha=0.5)
        ax2.legend()

        # Sauvegarde avec StorageManager
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = storage_manager.save_file(
            "", "dummy.txt", "performance_outputs", f"graphs/{algorithm}_{key_size}"
        ).parent
        
        output_path = output_dir / f"system_resources_{timestamp}.png"
        
        plt.tight_layout()
        plt.savefig(str(output_path), dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"✅ Graphique des ressources système généré: {output_path}")
        return output_path

    except Exception as e:
        print(f"❌ Erreur génération graphique des ressources: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    

def generate_complete_overhead_plot(result_data, algorithm, key_size, storage_manager=None):
    """Génère un graphique complet d'overhead avec 4 sous-graphiques"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    try:
        # Préparation des données
        files = [f for f in result_data['file_details'] if f['success']]
        if not files:
            print("⚠️ Aucun fichier valide pour l'analyse d'overhead")
            return

        original_sizes = []
        encrypted_sizes = []
        filenames = []
        
        for file in files:
            if 'original_path' in file and 'encrypted_path' in file:
                if os.path.exists(file['original_path']) and os.path.exists(file['encrypted_path']):
                    orig_size = os.path.getsize(file['original_path'])
                    enc_size = os.path.getsize(file['encrypted_path'])
                    if orig_size > 0 and enc_size > 0:
                        original_sizes.append(orig_size / 1024)  # Convertir en KB
                        encrypted_sizes.append(enc_size / 1024)
                        filenames.append(file['filename'][:15] + '...')

        if not original_sizes:
            print("❌ Aucune donnée valide pour l'overhead")
            return

        overhead = [(enc - orig)/orig*100 for orig, enc in zip(original_sizes, encrypted_sizes)]

        # Création de la figure
        plt.figure(figsize=(18, 12))
        plt.suptitle(f"Analyse d'Overhead - {algorithm} {key_size}", fontsize=16, y=1.02)

        # 1. Comparaison des tailles
        ax1 = plt.subplot(2, 2, 1)
        x = np.arange(len(filenames))
        width = 0.35
        bars1 = ax1.bar(x - width/2, original_sizes, width, label='Original', color='#1f77b4')
        bars2 = ax1.bar(x + width/2, encrypted_sizes, width, label='Chiffré', color='#ff7f0e')
        ax1.set_ylabel('Taille (KB)')
        ax1.set_title('Comparaison des Tailles')
        ax1.set_xticks(x)
        ax1.set_xticklabels(filenames, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(True, linestyle=':', alpha=0.5)
        
        # Ajout des valeurs sur les barres
        for rect in bars1 + bars2:
            height = rect.get_height()
            ax1.text(rect.get_x() + rect.get_width()/2., height,
                    f'{height:.1f}',
                    ha='center', va='bottom', fontsize=8)

        # 2. Overhead en pourcentage - CORRIGÉ
        ax2 = plt.subplot(2, 2, 2)
        bars = ax2.bar(filenames, overhead, color='#2ca02c')
        ax2.axhline(y=0, color='gray', linestyle='--')
        ax2.set_ylabel('Overhead (%)')
        ax2.set_title('Surcoût de Chiffrement')
        
        # CORRECTION : set_xticks avant set_xticklabels
        ax2.set_xticks(range(len(filenames)))
        ax2.set_xticklabels(filenames, rotation=45, ha='right')
        
        ax2.grid(True, linestyle=':', alpha=0.5)
        
        # Ajout des valeurs sur les barres
        for rect in bars:
            height = rect.get_height()
            ax2.text(rect.get_x() + rect.get_width()/2., height,
                    f'{height:.1f}%',
                    ha='center', va='bottom', fontsize=8)

        # 3. Relation taille originale/overhead
        ax3 = plt.subplot(2, 2, 3)
        scatter = ax3.scatter(original_sizes, overhead, c='#d62728', s=100)
        ax3.set_xlabel('Taille Originale (KB)')
        ax3.set_ylabel('Overhead (%)')
        ax3.set_title('Impact de la Taille sur l\'Overhead')
        ax3.grid(True, linestyle=':', alpha=0.5)
        
        # Ajout de la ligne de tendance
        z = np.polyfit(original_sizes, overhead, 1)
        p = np.poly1d(z)
        ax3.plot(original_sizes, p(original_sizes), "r--")

        # 4. Distribution de l'overhead
        ax4 = plt.subplot(2, 2, 4)
        ax4.hist(overhead, bins=15, color='#9467bd', edgecolor='black')
        ax4.set_xlabel('Overhead (%)')
        ax4.set_ylabel('Nombre de Fichiers')
        ax4.set_title('Distribution des Overheads')
        ax4.grid(True, linestyle=':', alpha=0.5)

        # Sauvegarde dans le dossier performance_resources
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = storage_manager.save_file(
            "", "dummy.txt", "performance_resources", f"{algorithm}_{key_size}/overhead_analysis"
        ).parent
        
        output_path = output_dir / f"overhead_analysis_{timestamp}.png"
        
        plt.tight_layout()
        plt.savefig(str(output_path), dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"✅ Graphique d'overhead complet généré: {output_path}")
        return output_path

    except Exception as e:
        print(f"❌ Erreur génération graphique d'overhead: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    

def generate_system_metrics_analysis(metrics, output_dir, base_name="system_metrics", storage_manager=None):
    if not metrics or 'timestamps' not in metrics:
        print("⚠️ Données système insuffisantes")
        return

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    timestamps = metrics['timestamps']
    cpu = metrics.get('cpu_samples', [])
    ram = metrics.get('ram_samples', [])

    # --- Correction : alignement des longueurs ---
    min_len = min(len(timestamps), len(cpu), len(ram))
    if min_len == 0:
        print("⚠️ Aucune donnée à tracer")
        return
    timestamps = timestamps[:min_len]
    cpu = cpu[:min_len]
    ram = ram[:min_len]

    t0 = timestamps[0]
    elapsed = [t - t0 for t in timestamps]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
    
    ax1.plot(elapsed, cpu, 'r-', label='CPU (%)')
    ax1.set_ylabel('Utilisation CPU (%)')
    ax1.set_title('Utilisation des ressources système')
    ax1.legend(loc='upper right')
    ax1.grid(True, linestyle=':', alpha=0.5)

    ax2.plot(elapsed, ram, 'b-', label='RAM (MB)')
    ax2.set_xlabel('Temps (s)')
    ax2.set_ylabel('Utilisation Mémoire (MB)')
    ax2.legend(loc='upper right')
    ax2.grid(True, linestyle=':', alpha=0.5)

    plt.tight_layout()
    output_path = os.path.join(output_dir, f"{base_name}.png")
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"✅ Métriques système sauvegardées dans {output_path}")


def generate_performance_resources(op_id, algorithm, key_size, file_details, storage_manager=None):
    """Génère des visualisations claires et organisées des ressources"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    try:
        # Configuration
        algo_id = f"{algorithm}_{key_size}"
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Créer les dossiers avec StorageManager
        base_dir = storage_manager.get_directory("performance_resources")
        system_metrics_dir = storage_manager.save_file("","performance_resources", f"{algo_id}/system_metrics").parent
        reports_dir = storage_manager.save_file("", "performance_resources", f"{algo_id}/Reports").parent
        
        # Récupération des données
        op_data = perf_tracker.operations.get(op_id, {})
        metrics = op_data.get('system_metrics', {})
        
        # 1. Analyse des métriques système
        generate_system_metrics_analysis(metrics, str(system_metrics_dir), timestamp)
        
        # 2. Nouvelle analyse d'overhead améliorée
        generate_complete_overhead_plot({
            'file_details': file_details,
            'op_id': op_id,
            'timings': op_data.get('timings', {})
        }, algorithm, key_size, storage_manager)
        
        print(f"✅ Rapports ressources générés dans: {base_dir}")
        return str(base_dir)

    except Exception as e:
        print(f"❌ Erreur génération rapports: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def generate_consolidated_report(dirs, algo_id, timestamp):
    """Génère un rapport PDF unifié"""
    from fpdf import FPDF
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, txt=f"Rapport complet - {algo_id}", ln=1, align='C')
    pdf.set_font(size=10)
    
    # Ajout des graphiques
    graphs = [
        ("CPU Global", "cpu_global_*.png"),
        ("CPU par Fichier", "cpu_par_fichier_*.png"), 
        ("RAM Globale", "ram_global_*.png"),
        ("RAM par Fichier", "ram_par_fichier_*.png")
    ]
    
    for title, pattern in graphs:
        graph_path = next(iter(glob.glob(os.path.join(dirs[pattern.split('_')[0]], pattern))), None)
        if graph_path:
            pdf.add_page()
            pdf.cell(200, 10, txt=title, ln=1)
            pdf.image(graph_path, x=10, w=190)
    
    # Statistiques finales
    pdf.add_page()
    pdf.set_font(size=12)
    pdf.cell(200, 10, txt="Statistiques Finales", ln=1)
    
    report_path = os.path.join(dirs['reports'], f"full_report_{timestamp}.pdf")
    pdf.output(report_path)


def generate_full_report(dirs, algo_id, timestamp, metrics, file_details):
    """Génère un rapport PDF complet avec tous les graphiques"""
    from fpdf import FPDF
    
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=14)
        pdf.cell(200, 10, txt=f"Rapport de Performance - {algo_id}", ln=1, align='C')
        pdf.set_font(size=10)
        
        # 1. Graphique CPU
        if 'cpu' in dirs:
            cpu_graph = os.path.join(dirs['cpu'], f"cpu_global_{timestamp}.png")
            if os.path.exists(cpu_graph):
                pdf.add_page()
                pdf.set_font('', 'B', 12)
                pdf.cell(0, 8, "Utilisation CPU", 0, 1)
                pdf.image(cpu_graph, x=10, w=190)
        
        # 2. Graphique RAM
        if 'ram' in dirs:
            ram_graph = os.path.join(dirs['ram'], f"ram_global_{timestamp}.png")
            if os.path.exists(ram_graph):
                pdf.add_page()
                pdf.set_font('', 'B', 12)
                pdf.cell(0, 8, "Utilisation Mémoire", 0, 1)
                pdf.image(ram_graph, x=10, w=190)
        
        # 3. Graphiques d'overhead
        overhead_graph = os.path.join(dirs['overhead'], f"overhead_comparison_{timestamp}.png")
        if os.path.exists(overhead_graph):
            pdf.add_page()
            pdf.set_font('', 'B', 12)
            pdf.cell(0, 8, "Analyse d'Overhead", 0, 1)
            pdf.image(overhead_graph, x=10, w=190)
        
        # 4. Statistiques
        pdf.add_page()
        pdf.set_font('', 'B', 12)
        pdf.cell(0, 8, "Statistiques", 0, 1)
        pdf.set_font('', '', 10)
        
        # Calcul des moyennes
        if metrics:
            avg_cpu = np.mean(metrics['cpu_samples']) if 'cpu_samples' in metrics else 0
            max_cpu = max(metrics['cpu_samples']) if 'cpu_samples' in metrics else 0
            avg_ram = np.mean(metrics['ram_samples']) if 'ram_samples' in metrics else 0
            max_ram = max(metrics['ram_samples']) if 'ram_samples' in metrics else 0
            
            stats = [
                ("CPU moyen", f"{avg_cpu:.1f}%"),
                ("CPU max", f"{max_cpu:.1f}%"),
                ("RAM moyen", f"{avg_ram:.1f} MB"),
                ("RAM max", f"{max_ram:.1f} MB")
            ]
            
            for label, value in stats:
                pdf.cell(40, 6, label + ":", 0, 0)
                pdf.set_font('', 'B', 10)
                pdf.cell(30, 6, value, 0, 1)
                pdf.set_font('', '', 10)
        
        # Sauvegarde du rapport
        report_path = os.path.join(dirs['reports'], f"full_report_{timestamp}.pdf")
        pdf.output(report_path)
        print(f"📊 Rapport complet généré: {report_path}")
        
    except Exception as e:
        print(f"❌ Erreur génération rapport: {str(e)}")
        raise




# ----------------------------------------------------------------------------------
# 15. Fonction Traitement Globale pour un dossier
# ----------------------------------------------------------------------------------
def encrypt_file_worker(file_path_str, algorithm, key_size, storage_manager_base_dir, hash_name):
    from utils.storage import StorageManager
    storage_manager = StorageManager(base_dir=storage_manager_base_dir)

    file_path = Path(file_path_str)
    filename = file_path.name
    file_size = file_path.stat().st_size
    file_data = {
        'filename': filename,
        'original_path': str(file_path),
        'file_size_kb': round(file_size/1024, 2),
        'success': False,
        'start_time': time.time(),
        'end_time': 0,
        'time': 0,
        'error': None,
        'steps': {},
        'encrypted_path': None,
        'signature_path': None
    }
    file_start = time.time()
    temp_path = None
    try:
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"Permission refusée pour {filename}")

        # --- Génération AES ---
        aes_start = time.time()
        aes_key = generate_aes_key()
        file_data['steps']['aes_key_gen'] = time.time() - aes_start

        # --- Nonce (très rapide, on l'inclut dans key_wrapping ou on le garde séparé) ---
        nonce_start = time.time()
        nonce = generate_nonce()
        file_data['steps']['nonce_gen'] = time.time() - nonce_start  # optionnel, on le garde

        # --- Chiffrement de la clé AES (wrapping) ---
        wrap_start = time.time()
        encrypted_key = encrypt_aes_key(aes_key, algorithm, key_size)
        file_data['steps']['key_wrapping'] = time.time() - wrap_start

        # --- Chiffrement du fichier ---
        encrypt_start = time.time()
        res_enc = encrypt_file(str(file_path), aes_key, nonce)
        temp_path = res_enc if isinstance(res_enc, str) else (res_enc['result'] if isinstance(res_enc, dict) else res_enc)
        if hasattr(res_enc, '_metrics'):
            metrics_data = getattr(res_enc, '_metrics', None)
            file_data['steps']['encryption'] = metrics_data['time'] if metrics_data else time.time() - encrypt_start
        else:
            file_data['steps']['encryption'] = time.time() - encrypt_start
        if isinstance(temp_path, tuple):
            temp_path = str(temp_path[0])

        # --- Validation (hash) ---
        validate_start = time.time()
        hmac_value = validate_file(temp_path, hash_name)
        if not hmac_value:
            raise ValueError("Échec de validation/hachage du fichier chiffré")
        file_data['steps']['validation'] = time.time() - validate_start
        file_data['steps']['hmac'] = 0  # fusionné

        # --- Métadonnées ---
        meta_start = time.time()
        file_type = file_path.suffix[1:].upper() or 'BIN'
        algo_id = f"{algorithm}_{key_size}"
        meta_file, metadata = save_metadata(filename, file_type, encrypted_key, nonce, hmac_value, algorithm, key_size, hash_name, storage_manager)
        file_data['steps']['meta'] = time.time() - meta_start

        # --- Déplacement final ---
        move_start = time.time()
        final_path_obj = storage_manager.get_file_path(filename, "encrypted_files", algo_id, create_dirs=True)
        final_path = write_metadata_header(temp_path, metadata, str(final_path_obj))
        file_data['encrypted_path'] = final_path
        Path(temp_path).unlink()
        file_data['steps']['final_move'] = time.time() - move_start

        # --- Signature ---
        sign_start = time.time()
        res_sig = sign_file(str(final_path), algorithm, key_size, hash_name, storage_manager)
        signature_path = res_sig if isinstance(res_sig, str) else (res_sig['result'] if isinstance(res_sig, dict) else res_sig)
        if isinstance(signature_path, tuple):
            signature_path = signature_path[0]
        if hasattr(res_sig, '_metrics'):
            metrics_data = getattr(res_sig, '_metrics', None)
            file_data['steps']['signing'] = metrics_data['time'] if metrics_data else time.time() - sign_start
        else:
            file_data['steps']['signing'] = time.time() - sign_start

        file_data['signature_path'] = str(signature_path)
        file_data['success'] = True

    except Exception as e:
        file_data['error'] = str(e)
        if temp_path and os.path.exists(str(temp_path)):
            try:
                os.remove(str(temp_path))
            except:
                pass
    finally:
        file_data['time'] = time.time() - file_start
        file_data['end_time'] = time.time()

    return (str(file_path), file_data['success'], file_data)


def process_folder(folder_path, algorithm, key_size, hash_name, storage_manager=None):
    """Processus complet avec tracking de performance et StorageManager"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    # Initialisation du tracking
    op_id = perf_tracker.start_operation(
        "crypto_processing",
        algorithm=algorithm,
        key_size=key_size,
        folder_path=folder_path,
        storage_location=str(storage_manager.base_dir)
    )
    
    # Initialisation des résultats
    result_data = {
        'metadata': {
            'folder_path': folder_path,
            'algorithm': algorithm,
            'key_size': key_size,
            'hash_algorithm': hash_name,
            'start_time': datetime.datetime.now().isoformat(),
            'storage_location': str(storage_manager.base_dir)
        },
        'processed_files': 0,
        'failed_files': 0,
        'encrypted_files': [],
        'signed_files': [],
        'error': None,
        'timings': {
            'total': 0,
            'setup': 0,
            'processing': 0,
            'cleanup': 0
        },
        'file_details': []
    }

    start_time = time.time()

    try:
        # Phase 1: Setup
        perf_tracker.add_step(op_id, "setup_initialization")
        setup_init_start = time.time()
        
        try:
            check_folder_permissions(folder_path)
        except (ValueError, PermissionError) as e:
            result_data['error'] = str(e)
            return result_data

        # Normalisation et validation
        if algorithm == "ECC" and isinstance(key_size, str):
            key_size = key_size.replace("P-", "")
        
        validate_algorithm_choice(algorithm, key_size)
        algo_id = f"{algorithm}_{key_size}"
        
        print(f"\n🔧 Configuration: {algo_id}")
        log_file = setup_logging(algorithm=algo_id, storage_manager=storage_manager)

        perf_tracker.end_step(op_id, "setup_initialization")
        result_data['timings']['setup_initialization'] = time.time() - setup_init_start

        # Nettoyage des anciens dossiers via StorageManager
        perf_tracker.add_step(op_id, "setup_folder_cleanup")
        setup_cleanup_start = time.time()

        # Nettoyer les dossiers de sortie pour cet algorithme
        for dir_type in ["encrypted_files", "signed_files", "metadata"]:
            algo_dir = storage_manager.get_directory(dir_type) / algo_id
            if algo_dir.exists():
                shutil.rmtree(algo_dir)

        perf_tracker.end_step(op_id, "setup_folder_cleanup")
        result_data['timings']['setup_folder_cleanup'] = time.time() - setup_cleanup_start
        result_data['timings']['setup'] = time.time() - setup_init_start

        # Phase 2: Traitement des fichiers
        perf_tracker.add_step(op_id, "file_processing")
        processing_start = time.time()

        perf_tracker.add_step(op_id, "public_key_loading")
        pk_start = time.time()
        public_key = load_public_key_cached(algorithm, key_size, storage_manager)
        perf_tracker.end_step(op_id, "public_key_loading")
        result_data['timings']['public_key_loading'] = time.time() - pk_start

        folder = Path(folder_path)
        files_to_process = [f for f in folder.iterdir() if f.is_file() and not f.name.startswith(('.', '~$'))]
        
        # Multiprocessing implementation
        import multiprocessing
        max_workers = multiprocessing.cpu_count()
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    encrypt_file_worker,
                    str(file_path),
                    algorithm,
                    key_size,
                    str(storage_manager.base_dir),
                    hash_name
                ): file_path for file_path in files_to_process
            }
            
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    filepath, success, file_data = future.result()
                    
                    if success:
                        result_data['processed_files'] += 1
                        if file_data.get('encrypted_path'):
                            result_data['encrypted_files'].append(file_data['encrypted_path'])
                        if file_data.get('signature_path'):
                            result_data['signed_files'].append(file_data['signature_path'])
                    else:
                        result_data['failed_files'] += 1
                        
                    result_data['file_details'].append(file_data)
                except Exception as e:
                    logging.error(f"Erreur worker pour un fichier: {str(e)}")
                    result_data['failed_files'] += 1

        # NOTE: Les étapes individuelles ne sont plus reportées dans perf_tracker 
        # car exécutées dans des workers distincts. Le rapport global affichera
        # néanmoins la performance globale via _metrics ou les temps mesurés ci-dessus.
        
        perf_tracker.end_step(op_id, "file_processing")
        result_data['timings']['processing'] = time.time() - processing_start

        # Génération des rapports de performance
        try:
            result_data['op_id'] = op_id
            # perf_tracker.generate_report(op_id)
            # generate_performance_outputs(result_data, algorithm, key_size, storage_manager)
            
            # Ajouter l'appel pour performance_resources
            # generate_performance_resources(
            #     op_id=op_id,
            #     algorithm=algorithm,
            #     key_size=key_size,
            #     file_details=result_data['file_details'],
            #     storage_manager=storage_manager  
            # )
            
        except Exception as e:
            logging.error(f"Erreur génération rapports: {str(e)}")

    finally:
        perf_tracker.add_step(op_id, "cleanup")
        cleanup_start = time.time()
        
        try:
            cleanup_temp_files(folder_path)
            cleanup_metadata_files(storage_manager)
            cleanup_signature_files(storage_manager)
        except Exception as e:
            logging.error(f"Erreur lors du nettoyage: {str(e)}")

        cleanup_duration = time.time() - cleanup_start
        perf_tracker.end_step(op_id, "cleanup")
        result_data['timings']['cleanup'] = cleanup_duration
        result_data['timings']['total'] = time.time() - start_time

    return result_data