import datetime
from logging.handlers import RotatingFileHandler
import os
import json
import logging
from pathlib import Path
import sys
import time
import numpy as np
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

from fpdf import FPDF
from matplotlib import pyplot as plt
from handlers.perf import perf_tracker, measure_performance

from handlers.encrypt_sign import save_metrics_json, generate_system_metrics_analysis
import matplotlib.pyplot as plt


def setup_logging():
    """Configure un logging propre avec rotation des fichiers"""
    log_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler console (seulement les erreurs)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(log_formatter)
    
    # Handler fichier (tous les niveaux)
    file_handler = RotatingFileHandler(
        'decrypt.log', 
        maxBytes=1_000_000,
        backupCount=3
    )
    file_handler.setFormatter(log_formatter)
    
    # Configuration globale
    logging.basicConfig(
        level=logging.INFO,
        handlers=[console_handler, file_handler]
    )

# ----------------------------------------------------------------------------------
# 1. Chargement de la clé privée
# ----------------------------------------------------------------------------------
def load_private_key(algorithm, key_size, storage_manager=None):
    """Charge la clé privée via StorageManager - VERSION CORRIGÉE"""
    if storage_manager is None:
        from utils.storage import storage_manager
    
    # ⚠️ MÊME LOGIQUE QUE load_public_key() ⚠️
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
    
    # Recherche via StorageManager (identique à public key)
    key_file = storage_manager.get_file_path(filename, "keys_generated", subfolder)
    
    # Fallback: chercher any private key file (identique)
    if not key_file.exists():
        key_dir = storage_manager.get_directory("keys_generated") / subfolder
        if key_dir.exists():
            private_files = list(key_dir.glob("*private*.pem"))
            if private_files:
                key_file = private_files[0]
    
    if not key_file.exists():
        raise FileNotFoundError(f"❌ Aucune clé privée trouvée dans {key_file.parent}")

    print(f"🔑 DEBUG Chargement clé privée: {key_file}")
    
    with open(key_file, "rb") as f:
        pem_data = f.read()
        
        if algorithm == "RSA":
            key = serialization.load_pem_private_key(pem_data, None)
            print(f"✅ Clé RSA privée chargée - Taille: {key.key_size}")
            return key
            
        elif algorithm == "ECC":
            key = serialization.load_pem_private_key(pem_data, None)
            print(f"🔧 Type de clé chargée: {type(key)}")
            
            if isinstance(key, ec.EllipticCurvePrivateKey):
                print(f"✅ Clé ECC privée valide - Courbe: {key.curve.name}")
                return key
            else:
                print(f"❌ MAUVAIS TYPE: {type(key)}")
                raise ValueError("❌ La clé chargée n'est pas une clé ECC privée valide")
                
        elif algorithm == "ElGamal":
            key = serialization.load_pem_private_key(pem_data, None)
            print(f"✅ Clé ElGamal privée chargée")
            return key

# ----------------------------------------------------------------------------------
# 2. Déchiffrement de la clé AES
# ----------------------------------------------------------------------------------
def decrypt_aes_key(encrypted_aes_key, algorithm, key_size, storage_manager=None):
    """Déchiffre la clé AES avec la clé privée via StorageManager"""
    try:
        # Charger la clé privée UNE SEULE FOIS
        private_key = load_private_key(algorithm, key_size, storage_manager)
        
        print(f"🔓 Déchiffrement clé AES avec {algorithm}_{key_size}...")
        print(f"Taille clé chiffrée reçue: {len(encrypted_aes_key)} bytes")
        
        if algorithm == "RSA":
            # Vérification spéciale pour les clés RSA
            if len(encrypted_aes_key) == 32:
                print("⚠️ Format spécial détecté - tentative de déchiffrement direct")
                return encrypted_aes_key
                
            # Déchiffrement standard avec OAEP
            decrypted = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if len(decrypted) != 32:
                raise ValueError(f"Taille clé AES incorrecte: {len(decrypted)} bytes")
                
            return decrypted
            
        elif algorithm == "ECC":
            # ✅ UTILISER LA CLÉ DÉJÀ CHARGÉE - PAS DE RE-CHARGEMENT !
            curve = private_key.curve
            print(f"📐 Courbe ECC utilisée: {curve.name} (P-{curve.key_size})")

            # Cas particulier: clé AES en clair (pour debug)
            if len(encrypted_aes_key) == 32:
                print("⚠️ Format spécial détecté - tentative de déchiffrement direct")
                return encrypted_aes_key  
            
            # Tailles attendues POUR TOUTES LES COURBES
            curve_sizes = {
                192: (49, 32),    # P-192: 1 + 2*24 = 49 bytes
                224: (57, 32),    # P-224: 1 + 2*28 = 57 bytes  
                256: (65, 32),    # P-256: 1 + 2*32 = 65 bytes  
                384: (97, 32),    # P-384: 1 + 2*48 = 97 bytes 
                521: (133, 32)    # P-521: 1 + 2*66 = 133 bytes
            }
            
            if curve.key_size not in curve_sizes:
                supported_curves = ", ".join([f"P-{size}" for size in curve_sizes.keys()])
                raise ValueError(f"Courbe P-{curve.key_size} non supportée. Courbes supportées: {supported_curves}")
            
            pubkey_len, ciphertext_len = curve_sizes[curve.key_size]
            expected_len = pubkey_len + ciphertext_len
            
            if len(encrypted_aes_key) != expected_len:
                raise ValueError(
                    f"Taille incorrecte: {len(encrypted_aes_key)} bytes "
                    f"(attendu: {expected_len} pour P-{curve.key_size})"
                )
            
            # Extraction des composants
            pubkey_bytes = encrypted_aes_key[:pubkey_len]
            ciphertext = encrypted_aes_key[pubkey_len:pubkey_len + ciphertext_len]
            
            print(f"🔧 Composants extraits - Clé publique: {len(pubkey_bytes)} bytes, Ciphertext: {len(ciphertext)} bytes")
            
            # Reconstruction clé éphémère
            public_key_ephem = ec.EllipticCurvePublicKey.from_encoded_point(
                curve,
                pubkey_bytes
            )
            
            # Échange de clé ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key_ephem)
            
            # Dérivation de clé avec HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecc_key_wrap',
            ).derive(shared_key)
            
            # Déchiffrement XOR
            decrypted_key = bytes(a ^ b for a, b in zip(ciphertext, derived_key))
            
            print(f"✅ Clé AES déchiffrée: {len(decrypted_key)} bytes")
            return decrypted_key
            
        elif algorithm == "ElGamal":
            # Cas particulier: clé AES en clair
            if len(encrypted_aes_key) == 32:
                print("⚠️ Format brut détecté - utilisation directe")
                return encrypted_aes_key
            
            # Vérification taille pour ElGamal
            expected_size = key_size // 8 
            if len(encrypted_aes_key) != expected_size:
                raise ValueError(
                    f"Taille ciphertext ElGamal invalide : {len(encrypted_aes_key)} bytes "
                    f"(attendu : {expected_size} bytes)"
                )
            
            # Déchiffrement avec OAEP
            decrypted = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if len(decrypted) != 32:
                raise ValueError("Taille clé AES incorrecte après déchiffrement")
            
            return decrypted
        
    except Exception as e:
        print(f"❌ Erreur déchiffrement: {str(e)}")
        raise


# ----------------------------------------------------------------------------------
# Lecture de l'en-tête de métadonnées
# ----------------------------------------------------------------------------------
def read_metadata_header(filepath):
    import json
    try:
        with open(filepath, 'rb') as f:
            size_bytes = f.read(4)
            if len(size_bytes) < 4:
                return None, 0
            meta_size = int.from_bytes(size_bytes, byteorder='big')
            if meta_size <= 0 or meta_size > 10 * 1024 * 1024:  # Sanity check 10MB max
                return None, 0
            meta_json = f.read(meta_size)
            if len(meta_json) < meta_size:
                return None, 0
            metadata = json.loads(meta_json.decode('utf-8'))
            return metadata, 4 + meta_size
    except Exception:
        return None, 0


# ----------------------------------------------------------------------------------
# 3. Chargement des métadonnées
# ----------------------------------------------------------------------------------
def load_metadata(filepath, algorithm, key_size, storage_manager=None):
    """Charge les métadonnées via StorageManager - VERSION CORRIGÉE"""
    metadata = None
    meta_data, header_size = read_metadata_header(filepath)
    if meta_data:
        meta_data['_header_size'] = header_size
        print(f"✅ En-tête métadonnées trouvé dans: {filepath}")
        metadata = meta_data
    else:
        filename = os.path.basename(filepath)
        if storage_manager is None:
            from utils.storage import storage_manager
            
        try:
            # ⚠️ MÊME LOGIQUE QUE save_metadata() ⚠️
            # Utiliser directement l'ID algorithme comme sous-dossier
            subfolder = f"{algorithm}_{key_size}"  # ← Format direct comme dans save_metadata()
            
            print(f"🔍 DEBUG load_metadata: {filename}")
            print(f"📁 Recherche dans: metadata/{subfolder}")
            
            # Recherche via StorageManager
            metadata_dir = storage_manager.get_directory("metadata") / subfolder
            meta_file = metadata_dir / f"{filename}.meta"
            
            # Fallback: chercher le fichier avec différentes extensions
            if not meta_file.exists():
                # Essayer différentes variantes
                possible_files = [
                    meta_file,
                    metadata_dir / f"{filename}.meta.json",
                    metadata_dir / filename,  # Sans extension
                ]
                
                for possible_file in possible_files:
                    if possible_file.exists():
                        meta_file = possible_file
                        print(f"🔍 Fichier trouvé avec variante: {meta_file.name}")
                        break
            
            if not meta_file.exists():
                raise FileNotFoundError(f"❌ Fichier de métadonnées introuvable: {meta_file}")
            
            print(f"✅ Fichier métadonnées trouvé: {meta_file}")
            
            # Lecture du fichier JSON
            with open(meta_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
        
        except Exception as e:
            print(f"❌ Erreur de chargement métadonnées: {str(e)}")
            raise
        
        # Le hash_algorithm est conservé sans valeur par défaut (laissé tel quel)
        
    # Conversion des champs hexadécimaux en bytes
    try:
        if isinstance(metadata.get('encrypted_key'), str):
            metadata['encrypted_key'] = bytes.fromhex(metadata['encrypted_key'])
        if isinstance(metadata.get('nonce'), str):
            metadata['nonce'] = bytes.fromhex(metadata['nonce'])
        if isinstance(metadata.get('hmac'), str):
            metadata['hmac'] = bytes.fromhex(metadata['hmac'])
        
        print(f"   Encrypted key: {len(metadata['encrypted_key'])} bytes")
        print(f"   Nonce: {len(metadata['nonce'])} bytes")
        print(f"   HMAC: {len(metadata['hmac'])} bytes")
        
    except ValueError as ve:
        print(f"❌ Erreur conversion hexadécimale: {ve}")
        raise
    
    return metadata


# ----------------------------------------------------------------------------------
# Fonction de déchiffrement 
# ----------------------------------------------------------------------------------
@measure_performance
def decrypt_file(encrypted_path, key, nonce, original_extension, header_size=0):
    """
    Déchiffre un fichier avec AES-CTR. de manière robuste"""
    try:
        # Chemin de sortie
        base_name = os.path.splitext(os.path.basename(encrypted_path))[0]
        decrypted_path = os.path.join(
            os.path.dirname(encrypted_path),
            f"{base_name}_decrypted.{original_extension}"
        )
        
        # Réinitialisation du nonce pour CTR
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        with open(encrypted_path, 'rb') as f_in, open(decrypted_path, 'wb') as f_out:
            if header_size > 0:
                f_in.seek(header_size)
            while True:
                chunk = f_in.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                f_out.write(decryptor.update(chunk))
            f_out.write(decryptor.finalize())
            
        return decrypted_path
    except Exception as e:
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)
        raise ValueError(f"Échec déchiffrement: {str(e)}")


# ----------------------------------------------------------------------------------
# Fonction de validation du fichier déchiffré
# ----------------------------------------------------------------------------------
def validate_decrypted_file(file_path, original_ext):
    """Validation approfondie du fichier déchiffré"""
    try:
        # Vérifications de base
        if not os.path.exists(file_path):
            raise ValueError("Fichier introuvable")
        if os.path.getsize(file_path) < 4:
            raise ValueError("Fichier trop petit")
            
        # Vérification par type de fichier
        with open(file_path, 'rb') as f:
            header = f.read(8)
            
        if original_ext.lower() == 'pdf' and not header.startswith(b'%PDF'):
            raise ValueError("Signature PDF invalide")
        elif original_ext.lower() in ['jpg','jpeg'] and not header.startswith(b'\xFF\xD8'):
            raise ValueError("Signature JPEG invalide")
        
        return True
    except Exception as e:
        logging.error(f"Validation failed: {str(e)}")
        return False


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
# 4. Fonction de validation
# ----------------------------------------------------------------------------------
def validate_file(temp_path, expected_hash, hash_name, header_size=0):
    """Valide l'intégrité du fichier chiffré en le comparant avec l'empreinte attendue."""
    from utils.hash_utils import get_hash_algorithm
    try:
        # Vérifier la taille
        if os.path.getsize(temp_path) == 0:
            raise ValueError("Fichier chiffré vide")

        # Calculer le hachage avec l'algorithme des métadonnées
        hash_algo = get_hash_algorithm(hash_name)
        digest = hashes.Hash(hash_algo, backend=default_backend())
        with open(temp_path, "rb") as f:
            if header_size > 0:
                f.seek(header_size)
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        
        hash_calcule = digest.finalize()
        print(f"🔎 Empreinte calculée : {hash_calcule.hex()[:32]}...")
        
        # Comparaison stricte (temps constant pour éviter attaques temporelles)
        import hmac
        if not hmac.compare_digest(hash_calcule, expected_hash):
            logging.error(f"Intégrité compromise : empreinte différente pour {temp_path}")
            return False
            
        return True

    except Exception as e:
        logging.error(f"Erreur de validation pour {temp_path} : {e}")
        return False


# ----------------------------------------------------------------------------------
# 13. Clean les fichiers temporaires (notamment les ".DS_Store" hidden files)
# ----------------------------------------------------------------------------------
def cleanup_temp_files(folder_path):
    """Nettoie tous les fichiers .tmp et .DS_Store.tmp dans le dossier spécifié"""
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        # Supprimer les fichiers .tmp et toutes les variantes de .DS_Store.tmp
        if (filename.endswith('.tmp') or 
            filename.startswith('.DS_Store') and '.tmp' in filename):
            try:
                os.remove(file_path)
                print(f"🗑️ Fichier temporaire supprimé: {filename}")
            except Exception as e:
                print(f"⚠️ Erreur suppression {filename}: {e}")


def perform_decryption(encrypted_dir, algorithm, key_size, storage_manager=None):
    if storage_manager is None:
        from utils.storage import storage_manager

    op_id = perf_tracker.start_operation(
        "decryption",
        algorithm=algorithm,
        key_size=key_size,
        storage_location=str(storage_manager.base_dir)
    )

    result_data = {
        'metadata': {
            'algorithm': algorithm,
            'key_size': key_size,
            'start_time': datetime.datetime.now().isoformat(),
            'storage_location': str(storage_manager.base_dir),
            'operation_type': 'decryption'
        },
        'encrypted_dir': encrypted_dir,
        'processed_files': 0,
        'failed_files': 0,
        'decrypted_files': [],
        'file_details': [],
        'total_size_mb': 0,
        'total_time': 0,
        'success': False,
        'error': None,
        'op_id': op_id
    }

    try:
        perf_tracker.add_step(op_id, "decryption_process")
        start_time = time.time()

        # Appel à la logique de déchiffrement existante (decrypt_folder)
        decrypt_results = decrypt_folder(encrypted_dir, algorithm, key_size, storage_manager)
        result_data.update(decrypt_results)
        result_data['success'] = result_data['failed_files'] == 0 and result_data['processed_files'] > 0

        perf_tracker.end_step(op_id, "decryption_process")
        result_data['timings'] = {'total': time.time() - start_time}

        generate_decryption_outputs(result_data, algorithm, key_size, storage_manager)

    except Exception as e:
        result_data['error'] = str(e)
        logging.error(f"Erreur déchiffrement: {e}")
    finally:
        perf_tracker.stop_operation(op_id)

    return result_data

def generate_decryption_outputs(result_data, algorithm, key_size, storage_manager=None):
    if storage_manager is None:
        from utils.storage import storage_manager

    algo_id = f"{algorithm}_{key_size}"
    timestamp_ms = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    operation_id = f"{algo_id}_{timestamp_ms}"

    graphs_dir = storage_manager.get_directory("performance_outputs") / "graphs" / algo_id
    graphs_dir.mkdir(parents=True, exist_ok=True)

    resources_sys_dir = storage_manager.get_directory("performance_resources") / algo_id / "system_metrics"
    resources_sys_dir.mkdir(parents=True, exist_ok=True)

    # 1. Graphique des temps de déchiffrement
    file_details = result_data.get('file_details', [])
    if file_details:
        plt.figure(figsize=(12, 6))
        names = [os.path.basename(f['filename']) for f in file_details]
        times = [f.get('decrypt_time', 0) for f in file_details]
        colors = ['#4a9c50' if f.get('success') else '#d62728' for f in file_details]

        plt.barh(names, times, color=colors, edgecolor='black', linewidth=0.5)
        plt.xlabel('Temps de déchiffrement (s)')
        plt.ylabel('Fichiers')
        plt.title(f'Déchiffrement - {algo_id}')
        plt.gca().invert_yaxis()

        for i, (t, f) in enumerate(zip(times, file_details)):
            if f.get('success'):
                plt.text(t + max(times)*0.01, i, f"{t:.3f}s", va='center', fontsize=7)

        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor='#4a9c50', label='Succès'),
                           Patch(facecolor='#d62728', label='Échec')]
        plt.legend(handles=legend_elements, fontsize=8, loc='lower right')
        plt.tight_layout()
        plt.savefig(str(graphs_dir / "decryption_stats.png"), dpi=150)
        plt.close()

    # 2. Métriques système
    op_id = result_data.get('op_id')
    if op_id:
        op_data = perf_tracker.operations.get(op_id, {})
        system_metrics_data = op_data.get('system_metrics', {})
        if system_metrics_data:
            generate_system_metrics_analysis(system_metrics_data, str(resources_sys_dir), "system_metrics")
            generated_files = sorted(resources_sys_dir.glob("system_metrics_*.png"))
            if generated_files:
                latest = generated_files[-1]
                target = resources_sys_dir / "system_metrics.png"
                if target.exists():
                    target.unlink()
                latest.rename(target)

    # 3. JSON de métriques
    result_data['metadata']['operation_type'] = 'decryption'
    result_data['metadata']['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    save_metrics_json(result_data, operation_id, storage_manager)

    print(f"✅ Sorties de déchiffrement sauvegardées dans : {graphs_dir}")


def generate_decryption_report(decrypt_results, algo_id, timestamp, output_root="decryption_outputs"):
    """Génère un rapport PDF professionnel avec graphique intégré"""
    try:
        from fpdf import FPDF
        import unicodedata

        def clean_text(text):
            """Normalise le texte pour les polices non-Unicode"""
            return unicodedata.normalize('NFKD', str(text)).encode('ascii', 'ignore').decode('ascii') if text else ""

        class PDF(FPDF):
            def __init__(self):
                super().__init__()
                self.font_dir = os.path.join(os.path.dirname(__file__), 'fonts')
                self.unicode_font = None
                self.setup_fonts()

            def setup_fonts(self):
                """Configure les polices avec fallback"""
                # Essaye d'abord avec Arial Unicode
                if self.try_add_font('ArialUnicode', 'arialuni.ttf'):
                    self.unicode_font = 'ArialUnicode'
                # Fallback sur DejaVu
                elif self.try_add_font('DejaVu', 'DejaVuSans.ttf'):
                    self.unicode_font = 'DejaVu'
                # Fallback sur Arial standard
                elif self.try_add_font('Arial', 'arial.ttf'):
                    self.unicode_font = 'Arial'
                # Dernier recours: Helvetica
                else:
                    print("⚠️ Utilisation de la police Helvetica standard (Unicode limité)")

            def try_add_font(self, font_name, font_file):
                """Tente d'ajouter une police"""
                try:
                    font_path = os.path.join(self.font_dir, font_file)
                    if os.path.exists(font_path):
                        self.add_font(font_name, '', font_path, uni=True)
                        self.add_font(font_name, 'B', font_path, uni=True)
                        self.add_font(font_name, 'I', font_path, uni=True)
                        return True
                    return False
                except:
                    return False

            def header(self):
                self.set_header_font('B', 16)
                self.cell(0, 10, clean_text(f'Rapport de Déchiffrement - {algo_id}'), 0, 1, 'C')
                self.set_header_font('I', 10)
                self.cell(0, 6, clean_text(f"Généré le {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}"), 0, 1, 'C')
                self.ln(10)

            def footer(self):
                self.set_y(-15)
                self.set_footer_font('I', 8)
                self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

            def set_header_font(self, style='', size=12):
                if self.unicode_font:
                    self.set_font(self.unicode_font, style, size)
                else:
                    self.set_font('helvetica', style, size)

            def set_footer_font(self, style='', size=8):
                if self.unicode_font:
                    self.set_font(self.unicode_font, style, size)
                else:
                    self.set_font('helvetica', style, size)

        # Initialisation du PDF
        pdf = PDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Utiliser la police Unicode si disponible, sinon Helvetica
        current_font = pdf.unicode_font if pdf.unicode_font else 'helvetica'
        pdf.set_font(current_font, '', 10)

        # 1. Page de titre
        pdf.set_font(current_font, 'B', 16)
        pdf.cell(0, 10, clean_text("Rapport de Déchiffrement"), 0, 1, 'C')
        pdf.set_font(current_font, 'I', 14)
        pdf.cell(0, 10, clean_text(algo_id), 0, 1, 'C')
        pdf.ln(20)

        # 2. Résumé exécutif
        pdf.add_page()
        pdf.set_font(current_font, 'B', 14)
        pdf.cell(0, 10, clean_text("Résumé Exécutif"), 0, 1)
        pdf.set_font(current_font, '', 10)

        # Calcul des statistiques
        total_files = decrypt_results['processed_files'] + decrypt_results['failed_files']
        success_rate = (decrypt_results['processed_files'] / total_files * 100) if total_files > 0 else 0
        avg_speed = decrypt_results['total_size_mb'] / decrypt_results['total_time'] if decrypt_results['total_time'] > 0 else 0

        # Tableau de résumé
        pdf.set_fill_color(240, 240, 240)
        pdf.set_draw_color(200, 200, 200)
        
        summary_data = [
            ("Dossier source:", decrypt_results['encrypted_dir']),
            ("Dossier de destination:", decrypt_results['decrypted_dir']),
            ("Nombre total de fichiers:", str(total_files)),
            ("Déchiffrements réussis:", f"{decrypt_results['processed_files']} ({success_rate:.1f}%)"),
            ("Échecs de déchiffrement:", str(decrypt_results['failed_files'])),
            ("Taille totale des fichiers:", f"{decrypt_results['total_size_mb']:.2f} MB"),
            ("Temps total de déchiffrement:", f"{decrypt_results['total_time']:.2f} secondes"),
            ("Vitesse moyenne:", f"{avg_speed:.2f} MB/s")
        ]

        for label, value in summary_data:
            pdf.cell(60, 8, clean_text(label), 'LR', 0, 'L')
            pdf.set_font(current_font, 'B', 10)
            pdf.cell(0, 8, clean_text(value), 'LR', 1, 'L')
            pdf.set_font(current_font, '', 10)

        pdf.ln(10)

        # 3. Graphique en barres
        graphs_dir = os.path.join(output_root, "graphs", algo_id)
        bar_chart = os.path.join(graphs_dir, f"decrypt_bars_{timestamp}.png")
        
        if os.path.exists(bar_chart):
            pdf.add_page()
            pdf.set_font(current_font, 'B', 14)
            pdf.cell(0, 10, clean_text("Performance de Déchiffrement"), 0, 1)
            
            # Insertion du graphique
            pdf.image(bar_chart, x=10, y=pdf.get_y(), w=190)
            pdf.ln(90)
            
            # Légende
            pdf.set_font(current_font, 'I', 8)
            pdf.multi_cell(0, 5, clean_text(
                "Graphique montrant le temps de déchiffrement pour chaque fichier. "
                "Les barres vertes indiquent les succès, les rouges les échecs. "
                "Les annotations montrent la taille du fichier et le temps pris."
            ))

        # 4. Détails par fichier
        if decrypt_results.get('file_details'):
            pdf.add_page()
            pdf.set_font(current_font, 'B', 14)
            pdf.cell(0, 10, clean_text("Détails par Fichier"), 0, 1)
            pdf.ln(5)
            
            # En-tête du tableau
            col_widths = [70, 25, 25, 20, 30, 20]
            headers = ["Fichier", "Taille (MB)", "Temps (s)", "Statut", "Type", "Vitesse"]
            
            pdf.set_font(current_font, 'B', 10)
            for i, header in enumerate(headers):
                pdf.cell(col_widths[i], 8, clean_text(header), 1, 0, 'C', 1)
            pdf.ln()
            
            # Données des fichiers
            pdf.set_font(current_font, '', 8)
            for file_data in decrypt_results['file_details']:
                name = file_data['filename']
                if len(name) > 40:
                    name = name[:20] + "..." + name[-15:]
                
                pdf.cell(col_widths[0], 8, clean_text(name), 'LR')
                pdf.cell(col_widths[1], 8, f"{file_data['size_mb']:.2f}", 'LR', 0, 'R')
                pdf.cell(col_widths[2], 8, f"{file_data['decrypt_time']:.3f}", 'LR', 0, 'R')
                
                if file_data['success']:
                    pdf.set_text_color(0, 128, 0)
                    pdf.cell(col_widths[3], 8, clean_text("SUCCÈS"), 'LR', 0, 'C')
                    speed = file_data['size_mb'] / file_data['decrypt_time'] if file_data['decrypt_time'] > 0 else 0
                    pdf.cell(col_widths[4], 8, clean_text(file_data['file_type']), 'LR', 0, 'C')
                    pdf.cell(col_widths[5], 8, f"{speed:.1f} MB/s", 'LR', 1, 'R')
                else:
                    pdf.set_text_color(255, 0, 0)
                    pdf.cell(col_widths[3], 8, clean_text("ÉCHEC"), 'LR', 0, 'C')
                    pdf.cell(col_widths[4], 8, clean_text(file_data['file_type']), 'LR', 0, 'C')
                    pdf.cell(col_widths[5], 8, "N/A", 'LR', 1, 'C')
                
                pdf.set_text_color(0, 0, 0)

        # Sauvegarde du rapport
        report_dir = os.path.join(output_root, "reports", algo_id)
        os.makedirs(report_dir, exist_ok=True)
        report_file = os.path.join(report_dir, f"decrypt_report_{timestamp}.pdf")
        pdf.output(report_file)
        
        print(f"📊 Rapport professionnel généré: {report_file}")
        return report_file
        
    except Exception as e:
        print(f"❌ Erreur génération rapport: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    


def decrypt_folder(encrypted_dir, algorithm, key_size, storage_manager=None):
    """Processus complet de déchiffrement avec StorageManager"""
    if storage_manager is None:
        from utils.storage import storage_manager
        
    # Initialisation des résultats
    results = {
        'encrypted_dir': encrypted_dir,
        'processed_files': 0,
        'failed_files': 0,
        'decrypted_files': [],
        'decrypted_dir': '',
        'file_details': [],
        'total_size_mb': 0,
        'total_time': 0
    }

    try:
        check_folder_permissions(encrypted_dir)
    except (ValueError, PermissionError) as e:
        print(f"❌ Erreur dossier: {str(e)}")
        results['error'] = str(e)
        return results
    
    # Normalisation pour ECC
    if algorithm == "ECC" and isinstance(key_size, str):
        key_size = key_size.replace("P-", "")

    elif algorithm != "ECC":
        try:
            int_key_size = int(key_size)
        except ValueError:
            raise ValueError(f"Taille de clé invalide : {key_size}")
        validate_algorithm_choice(algorithm, int_key_size)
    else:
        validate_algorithm_choice(algorithm, key_size)
        
    algo_id = f"{algorithm}_{key_size}"
    
    print(f"\n🔧 Configuration de déchiffrement: {algo_id}")
    
    # Création du dossier de sortie
    try:
        # Essayer avec StorageManager d'abord
        decrypted_dir = storage_manager.get_directory("decrypted_files") / algo_id
    except ValueError:
        # Fallback : créer le dossier manuellement à la racine
        decrypted_dir = storage_manager.base_dir / "decrypted_files" / algo_id
        print(f"📁 Création manuelle du dossier: {decrypted_dir}")
    
    decrypted_dir.mkdir(parents=True, exist_ok=True)  # ← Créer récursivement
    results['decrypted_dir'] = str(decrypted_dir)
    
    # Chargement de la clé privée
    private_key = load_private_key(algorithm, key_size, storage_manager)
    
    # Vérifier si le dossier contient des fichiers
    files_to_process = [f for f in os.listdir(encrypted_dir)
                       if os.path.isfile(os.path.join(encrypted_dir, f))]
    if not files_to_process:
        msg = f"Aucun fichier trouvé dans le dossier chiffré : {encrypted_dir}"
        print(f"❌ {msg}")
        results['error'] = msg
        return results
    
    for filename in sorted(os.listdir(encrypted_dir)):
        encrypted_path = os.path.join(encrypted_dir, filename)
        
        if os.path.isdir(encrypted_path):
            continue
        
        file_detail = {
            'filename': filename,
            'size_mb': 0,
            'decrypt_time': 0,
            'success': False,
            'file_type': 'inconnu'
        }
        
        try:
            if not os.access(encrypted_path, os.R_OK):
                raise PermissionError(f"Permission refusée pour {filename}")
            
            file_size = os.path.getsize(encrypted_path) / (1024 * 1024)  # Taille en MB
            file_detail['size_mb'] = file_size
            results['total_size_mb'] += file_size
            
            print(f"\n🔹 Déchiffrement: {filename} ({file_size:.2f} MB)")
            start_time = time.time()
            
            # 1. Chargement des métadonnées
            metadata = load_metadata(encrypted_path, algorithm, key_size)
            file_detail['file_type'] = metadata['file_type']
            
            # 2. Déchiffrement de la clé AES
            aes_key = decrypt_aes_key(metadata['encrypted_key'], algorithm, key_size)
            
            # 3. Vérification de l'intégrité
            hash_name = metadata.get('hash_algorithm')
            if not hash_name:
                raise ValueError("hash_algorithm manquant dans les métadonnées")
            
            if not validate_file(encrypted_path, metadata['hmac'], hash_name, metadata.get('_header_size', 0)):
                raise ValueError("Intégrité invalide - Fichier corrompu ou modifié")
            
            # 4. Déchiffrement du fichier
            temp_path = decrypt_file(encrypted_path, aes_key, metadata['nonce'], metadata['file_type'].lower(), metadata.get('_header_size', 0))
            
            # 5. Validation et déplacement final
            if validate_decrypted_file(temp_path, metadata['file_type'].lower()):
                final_path = os.path.join(decrypted_dir, f"{os.path.splitext(filename)[0]}.{metadata['file_type'].lower()}")
                os.rename(temp_path, final_path)
                results['decrypted_files'].append(final_path)
                
                decrypt_time = time.time() - start_time
                file_detail.update({
                    'decrypt_time': decrypt_time,
                    'success': True
                })
                results['total_time'] += decrypt_time
                
                print(f"✅ Succès en {decrypt_time:.2f}s")
                results['processed_files'] += 1
        
        except Exception as e:
            file_detail['success'] = False
            results['failed_files'] += 1
            print(f"❌ Échec: {str(e)}")
        
        results['file_details'].append(file_detail)
    
    # Nettoyage final
    cleanup_temp_files(decrypted_dir)
    
    # Calcul des statistiques
    if results['processed_files'] > 0:
        results['avg_time'] = results['total_time'] / results['processed_files']
        results['avg_speed'] = results['total_size_mb'] / results['total_time'] if results['total_time'] > 0 else 0
    
    # Rapport final
    print(f"\n🎉 Résultat du déchiffrement:")
    print(f"- Algorithm: {algo_id}")
    print(f"- Fichiers déchiffrés: {results['processed_files']}")
    print(f"- Échecs: {results['failed_files']}")
    print(f"- Taille totale: {results['total_size_mb']:.2f} MB")
    print(f"- Temps total: {results['total_time']:.2f} s")
    if 'avg_speed' in results:
        print(f"- Vitesse moyenne: {results['avg_speed']:.2f} MB/s")
    
    return results


def decrypt_and_report(encrypted_dir, algorithm, key_size, storage_manager=None):
    """Effectue le déchiffrement avec StorageManager"""
    if storage_manager is None:
        from utils.storage import storage_manager
        
    # Structure de résultat par défaut
    default_result = {
        'encrypted_dir': encrypted_dir,
        'processed_files': 0,
        'failed_files': 0,
        'decrypted_files': [],
        'total_size_mb': 0,
        'total_time': 0,
        'error': None
    }

    try:
        # GESTION ROBUSTE DE TOUS LES DOSSIERS
        algo_id = f"{algorithm}_{key_size}"
        
        try:
            output_root = storage_manager.get_directory("decryption_outputs")
        except ValueError:
            output_root = storage_manager.base_dir / "decryption_outputs"
            output_root.mkdir(exist_ok=True)
            print(f"📁 Dossier decryption_outputs créé: {output_root}")
        
        # 2. Créer les sous-dossiers nécessaires
        graphs_dir = output_root / "graphs" / algo_id
        reports_dir = output_root / "reports" / algo_id
        graphs_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # 2. Exécution du déchiffrement
        decrypt_results = decrypt_folder(encrypted_dir, algorithm, key_size, storage_manager)
        if not decrypt_results:
            default_result['error'] = "Aucun résultat de déchiffrement"
            return default_result

        # 3. Génération des graphiques (avec chemin direct)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        generate_decryption_graphs(decrypt_results, algo_id, timestamp, str(output_root))

        # 4. Génération du rapport PDF (avec chemin direct)
        generate_decryption_report(decrypt_results, algo_id, timestamp, str(output_root))
        
        return decrypt_results

    except Exception as e:
        default_result['error'] = str(e)
        logging.error(f"Erreur dans decrypt_and_report: {str(e)}", exc_info=True)
        return default_result