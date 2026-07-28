import datetime
import os
import time
import logging
import numpy as np
from pathlib import Path
from matplotlib import pyplot as plt

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from utils.storage import storage_manager
from utils.hash_utils import get_hash_algorithm
from handlers.perf import measure_performance, perf_tracker
from handlers.decrypt import load_metadata
from utils.storage import storage_manager


# ----------------------------------------------------------------------
# Vérification individuelle d'une signature
# ----------------------------------------------------------------------
@measure_performance
def verify_signature(encrypted_file_path, signature_path, algorithm, key_size):
    """
    Vérifie la signature d'un fichier chiffré.
    Retourne (bool, message).
    """
    try:
        print(f"\n🔍 Vérification de {os.path.basename(encrypted_file_path)}")
        print(f"Algorithme: {algorithm} {key_size}")

        public_key = load_public_key(algorithm, key_size)
        metadata = load_metadata(encrypted_file_path, algorithm, key_size)
        hash_name = metadata.get('hash_algorithm')
        if not hash_name:
            raise KeyError("hash_algorithm introuvable dans les métadonnées")

        with open(encrypted_file_path, 'rb') as f:
            file_data = f.read()
        with open(signature_path, 'rb') as f:
            signature = f.read()

        hash_algo = get_hash_algorithm(hash_name)

        if algorithm == "RSA":
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hash_algo),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_algo
            )
        elif algorithm == "ECC":
            digest = hashes.Hash(hash_algo, backend=default_backend())
            digest.update(file_data)
            hashed_data = digest.finalize()
            public_key.verify(
                signature,
                hashed_data,
                ec.ECDSA(utils.Prehashed(hash_algo))
            )
        elif algorithm == "ElGamal":
            digest = hashes.Hash(hash_algo, backend=default_backend())
            digest.update(file_data)
            hashed_data = digest.finalize()
            public_key.verify(
                signature,
                hashed_data,
                padding.PKCS1v15(),
                hash_algo
            )
        else:
            raise ValueError(f"Algorithme non supporté : {algorithm}")

        msg = f"✅ {os.path.basename(encrypted_file_path)}"
        print(msg)
        return (True, msg)

    except InvalidSignature:
        msg = f"❌ Signature invalide pour {os.path.basename(encrypted_file_path)}"
        print(msg)
        logging.warning(msg)
        return (False, msg)
    except Exception as e:
        msg = f"⛔ Erreur : {e}"
        print(msg)
        logging.error(msg)
        return (False, msg)


# ----------------------------------------------------------------------
# Cache & chargement de la clé publique
# ----------------------------------------------------------------------
_key_cache = {}

def load_public_key(algorithm, key_size, storage_manager=None):
    if storage_manager is None:
        from utils.storage import storage_manager

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

    key_file = storage_manager.get_file_path(filename, "keys_generated", subfolder)
    if not key_file.exists():
        key_dir = storage_manager.get_directory("keys_generated") / subfolder
        if key_dir.exists():
            public_files = list(key_dir.glob("*public*.pem"))
            if public_files:
                key_file = public_files[0]
    if not key_file.exists():
        raise FileNotFoundError(f"Aucune clé publique trouvée dans {key_file.parent}")

    with open(key_file, "rb") as f:
        pem_data = f.read()
        if algorithm == "RSA":
            return serialization.load_pem_public_key(pem_data)
        elif algorithm == "ECC":
            key = serialization.load_pem_public_key(pem_data)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError("Clé ECC invalide")
            return key
        elif algorithm == "ElGamal":
            return serialization.load_pem_public_key(pem_data)

def load_public_key_cached(algorithm, key_size, storage_manager=None):
    cache_key = f"{algorithm}_{key_size}"
    if cache_key not in _key_cache:
        _key_cache[cache_key] = load_public_key(algorithm, key_size, storage_manager)
    return _key_cache[cache_key]



def generate_verification_outputs(result_data, algorithm, key_size, storage_manager=None):
    """
    Génère les graphiques et les métriques pour une opération de vérification.
    - verification_stats.png : temps de vérification par fichier (couleur selon statut)
    - system_metrics.png : CPU/RAM pendant la vérification
    - JSON de métriques dans metrics_graphs/{algo_id}/
    """
    if storage_manager is None:
        from utils.storage import storage_manager

    algo_id = f"{algorithm}_{key_size}"
    timestamp_ms = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    operation_id = f"{algo_id}_{timestamp_ms}"

    # Dossiers de sortie
    graphs_dir = storage_manager.get_directory("performance_outputs") / "graphs" / algo_id
    graphs_dir.mkdir(parents=True, exist_ok=True)

    resources_sys_dir = storage_manager.get_directory("performance_resources") / algo_id / "system_metrics"
    resources_sys_dir.mkdir(parents=True, exist_ok=True)

    # 1. Graphique des temps de vérification (verification_stats.png)
    file_details = result_data.get('file_details', [])
    if file_details:
        plt.figure(figsize=(12, 6))
        plt.style.use('default')
        plt.rcParams.update({'font.size': 8, 'axes.titlesize': 10})

        names = [os.path.basename(f['filename']) for f in file_details]
        times = [f['verif_time'] for f in file_details]
        status = ['valide' if f['valid'] else 'manquant' if f['message'].startswith('⚠️') else 'invalide'
                  for f in file_details]
        colors = {'valide': '#4CAF50', 'invalide': '#F44336', 'manquant': '#FF9800'}
        bar_colors = [colors[s] for s in status]

        bars = plt.barh(names, times, color=bar_colors, edgecolor='black', linewidth=0.5)
        plt.xlabel('Temps de vérification (s)')
        plt.ylabel('Fichiers')
        plt.title(f'Vérification des signatures - {algo_id}')
        plt.gca().invert_yaxis()

        # Annotations
        for i, (t, s) in enumerate(zip(times, status)):
            if s != 'manquant':
                plt.text(t + max(times)*0.01, i, f"{t:.3f}s", va='center', fontsize=7)
            else:
                plt.text(max(times)*0.01, i, "Manquant", va='center', fontsize=7, color='#FF9800')

        # Légende
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor=colors['valide'], label='Valide'),
                           Patch(facecolor=colors['invalide'], label='Invalide'),
                           Patch(facecolor=colors['manquant'], label='Manquant')]
        plt.legend(handles=legend_elements, fontsize=8, loc='lower right')
        plt.tight_layout()
        plt.savefig(str(graphs_dir / "verification_stats.png"), dpi=150)
        plt.close()

    # 2. Graphique des ressources système (system_metrics.png)
    op_id = result_data.get('op_id')
    if op_id:
        op_data = perf_tracker.operations.get(op_id, {})
        system_metrics_data = op_data.get('system_metrics', {})
        if system_metrics_data:
            # Utilise la fonction déjà existante dans encrypt_sign.py
            from handlers.encrypt_sign import generate_system_metrics_analysis
            generate_system_metrics_analysis(system_metrics_data, str(resources_sys_dir), "system_metrics")
            # Renommer pour avoir un nom fixe
            generated_files = sorted(resources_sys_dir.glob("system_metrics_*.png"))
            if generated_files:
                latest = generated_files[-1]
                target = resources_sys_dir / "system_metrics.png"
                if target.exists():
                    target.unlink()
                latest.rename(target)

    # 3. Sauvegarde du JSON de métriques
    result_data['metadata']['operation_type'] = 'verification'
    result_data['metadata']['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    # Appelle save_metrics_json (importé depuis encrypt_sign)
    from handlers.encrypt_sign import save_metrics_json
    save_metrics_json(result_data, operation_id, storage_manager)

    print(f"✅ Sorties de vérification sauvegardées dans : {graphs_dir}")


# ----------------------------------------------------------------------
# Vérification par lot avec tracking & génération des sorties
# ----------------------------------------------------------------------
def perform_verification(algorithm, key_size):
    """
    Vérifie toutes les signatures d'un dossier avec tracking de performance,
    puis génère les graphiques, le JSON de métriques et les rapports.
    """
    op_id = perf_tracker.start_operation(
        "verification",
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
            'operation_type': 'verification'
        },
        'valid': [],
        'invalid': [],
        'missing': [],
        'file_details': [],
        'verif_times': [],
        'total_size': 0,
        'processed_files': 0,
        'success': False,
        'error': None,
        'op_id': op_id
    }

    try:
        perf_tracker.add_step(op_id, "verification_process")
        start_time = time.time()

        folder_name = f"{algorithm}_{key_size}"
        encrypted_dir = storage_manager.get_directory("encrypted_files") / folder_name
        signed_dir = storage_manager.get_directory("signed_files") / folder_name

        if not encrypted_dir.exists() or not signed_dir.exists():
            raise FileNotFoundError("Dossiers chiffrés ou signés introuvables")

        encrypted_files = [f for f in encrypted_dir.iterdir()
                           if f.is_file() and not f.name.startswith('.')]

        for file_path in encrypted_files:
            filename = file_path.name
            sig_path = signed_dir / f"{filename}.sig"

            file_detail = {
                'filename': filename,
                'size_kb': file_path.stat().st_size / 1024,
                'valid': False,
                'verif_time': 0,
                'message': ''
            }

            t0 = time.time()
            if not sig_path.exists():
                file_detail['message'] = f"⚠️ Signature manquante pour {filename}"
                result_data['missing'].append(filename)
            else:
                valid, msg = verify_signature(str(file_path), str(sig_path), algorithm, key_size)
                file_detail['valid'] = valid
                file_detail['message'] = msg
                if valid:
                    result_data['valid'].append(filename)
                else:
                    result_data['invalid'].append(filename)

            file_detail['verif_time'] = time.time() - t0
            result_data['file_details'].append(file_detail)
            result_data['verif_times'].append(file_detail['verif_time'])
            result_data['total_size'] += file_detail['size_kb'] * 1024
            result_data['processed_files'] += 1

        perf_tracker.end_step(op_id, "verification_process")
        result_data['timings'] = {'total': time.time() - start_time}
        result_data['success'] = len(result_data['invalid']) == 0 and len(result_data['missing']) == 0

        # Génération des sorties via la fonction unifiée
        from handlers.verify import generate_verification_outputs
        generate_verification_outputs(result_data, algorithm, key_size, storage_manager)

    except Exception as e:
        result_data['error'] = str(e)
        logging.error(f"Erreur vérification: {e}")
    finally:
        perf_tracker.stop_operation(op_id)

    return result_data