import os
import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pathlib import Path

def generate_rsa_keys(key_size, storage_manager=None):
    """
    Génère une paire de clés RSA et les sauvegarde via le StorageManager
    """
    if storage_manager is None:
        from utils.storage import storage_manager
    
    start_time = time.time()

    # Générer la paire de clés RSA
    key = RSA.generate(key_size)

    # Exporter les clés au format PEM
    private_key_pem = key.export_key(format="PEM")
    public_key_pem = key.publickey().export_key(format="PEM")

    # Sauvegarder via le StorageManager
    private_key_path = storage_manager.save_file(
        private_key_pem,
        f"rsa_private_{key_size}.pem",
        "keys_generated",
        f"RSA_{key_size}"
    )
    try:
        private_key_path.chmod(0o600)
    except Exception as e:
        print(f"⚠️ Impossible d'appliquer chmod 600 sur {private_key_path}: {e}")


    public_key_path = storage_manager.save_file(
        public_key_pem,
        f"rsa_public_{key_size}.pem",
        "keys_generated",
        f"RSA_{key_size}"
    )

    end_time = time.time()
    generation_time = end_time - start_time

    return str(private_key_path), str(public_key_path), generation_time

def generate_ecc_keys(curve_name, storage_manager=None):
    """
    Génère une paire de clés ECC et les sauvegarde via le StorageManager
    """
    if storage_manager is None:
        from utils.storage import storage_manager
    
    start_time = time.time()

    # Vérifier que la courbe est valide
    valid_curves = {
        "P-192": ec.SECP192R1(),
        "P-224": ec.SECP224R1(),
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }
    
    if curve_name not in valid_curves:
        raise ValueError(f"Courbe ECC non valide : {curve_name}")

    # Générer la paire de clés ECC
    private_key = ec.generate_private_key(valid_curves[curve_name])
    public_key = private_key.public_key()

    # Exporter les clés au format PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Normaliser le nom de la courbe pour le dossier
    curve_folder_name = curve_name.replace("-", "_")
    
    # Sauvegarder via le StorageManager
    private_key_path = storage_manager.save_file(
        private_key_pem,
        f"ecc_private_{curve_folder_name}.pem",
        "keys_generated",
        f"ECC_{curve_folder_name}"
    )
    try:
        private_key_path.chmod(0o600)
    except Exception as e:
        print(f"⚠️ Impossible d'appliquer chmod 600 sur {private_key_path}: {e}")


    public_key_path = storage_manager.save_file(
        public_key_pem,
        f"ecc_public_{curve_folder_name}.pem",
        "keys_generated",
        f"ECC_{curve_folder_name}"
    )

    end_time = time.time()
    generation_time = end_time - start_time

    return str(private_key_path), str(public_key_path), generation_time

def generate_elgamal_keys(key_size, storage_manager=None):
    """
    Génère une paire de clés ElGamal et les sauvegarde via le StorageManager
    """
    if storage_manager is None:
        from utils.storage import storage_manager
    
    start_time = time.time()

    # Générer la paire de clés (utilise RSA pour l'exemple)
    key = RSA.generate(key_size)

    # Exporter les clés au format PEM
    private_key_pem = key.export_key(format="PEM")
    public_key_pem = key.publickey().export_key(format="PEM")

    # Sauvegarder via le StorageManager
    private_key_path = storage_manager.save_file(
        private_key_pem,
        f"elgamal_private_{key_size}.pem",
        "keys_generated",
        f"ElGamal_{key_size}"
    )
    try:
        private_key_path.chmod(0o600)
    except Exception as e:
        print(f"⚠️ Impossible d'appliquer chmod 600 sur {private_key_path}: {e}")


    public_key_path = storage_manager.save_file(
        public_key_pem,
        f"elgamal_public_{key_size}.pem",
        "keys_generated",
        f"ElGamal_{key_size}"
    )

    end_time = time.time()
    generation_time = end_time - start_time

    return str(private_key_path), str(public_key_path), generation_time