from cryptography.hazmat.primitives import hashes

def get_hash_algorithm(name: str):
    """
    Retourne l'objet d'algorithme de hachage correspondant au nom.
    Par défaut, retourne SHA-256 si inconnu.
    """
    algorithms = {
        'SHA-256': hashes.SHA256(),
        'SHA-384': hashes.SHA384(),
        'SHA-512': hashes.SHA512(),
    }
    return algorithms.get(name.upper(), hashes.SHA256())
