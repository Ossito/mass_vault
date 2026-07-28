import os
import json
import shutil
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple
import logging

logger = logging.getLogger(__name__)

class StorageManager:
    def __init__(self, base_dir: Optional[str] = None):
        """
        Gestionnaire de stockage pour l'application de cryptographie
        
        Args:
            base_dir: Répertoire de base choisi par l'utilisateur
                     Si None, utilise la racine du projet par défaut
        """
        if base_dir is None:
            # Essayer d'importer la configuration globale
            try:
                # Ajout du chemin parent au sys.path si nécessaire pour l'import
                import sys
                parent_dir = str(Path(__file__).resolve().parent.parent)
                if parent_dir not in sys.path:
                    sys.path.append(parent_dir)
                
                from config import STORAGE_PATH, save_settings
                self.base_dir = STORAGE_PATH
                self.save_settings = save_settings
            except ImportError:
                # Repli sécurisé si config n'est pas accessible
                self.base_dir = Path.cwd() / "vault_data"
        else:
            self.base_dir = Path(base_dir)
        
        # S'assurer que le dossier de base existe
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        self.directories = {
            'encrypted_files': self.base_dir / "encrypted_files",
            'keys_generated': self.base_dir / "keys_generated", 
            'logs': self.base_dir / "logs",
            'metadata': self.base_dir / "metadata",
            'performance_outputs': self.base_dir / "performance_outputs",
            'performance_resources': self.base_dir / "performance_resources",
            'signed_files': self.base_dir / "signed_files",
            'temp': self.base_dir / "temp",
            'decryption_outputs': self.base_dir / "decryption_outputs",
            'verified_files': self.base_dir / "verified_files",
            'decrypted_files': self.base_dir / "decrypted_files",
            'metrics_graphs': self.base_dir / "metrics_graphs",
            'runs': self.base_dir / "runs",
            # 'comparison_graphs': self.base_dir / "comparison_graphs",
            'decision_reports': self.base_dir / "decision_reports",
        }


    
    def set_base_directory(self, new_base_dir: str) -> None:
        """
        Change le répertoire de base (choisi par l'utilisateur)
        
        Args:
            new_base_dir: Nouveau chemin de base
        """
        self.base_dir = Path(new_base_dir)
        
        # Met à jour tous les chemins des dossiers
        for dir_name in self.directories.keys():
            self.directories[dir_name] = self.base_dir / dir_name
        
        logger.info(f"Répertoire de base changé vers: {self.base_dir}")
        
        # Sauvegarder dans le fichier de configuration pour persistance
        if hasattr(self, 'save_settings'):
            try:
                # Tenter d'importer BASE_DIR de config
                from config import BASE_DIR
                
                # Si le nouveau chemin est à l'intérieur de BASE_DIR, on le sauvegarde en relatif
                # Cela permet de fonctionner aussi bien sur Mac que dans Docker
                if str(self.base_dir).startswith(str(BASE_DIR)):
                    rel_path = "./" + str(self.base_dir.relative_to(BASE_DIR))
                    self.save_settings({"storage_path": rel_path})
                    logger.info(f"Paramètre sauvegardé en relatif: {rel_path}")
                else:
                    # Sinon on garde l'absolu
                    self.save_settings({"storage_path": str(self.base_dir)})
                    logger.info(f"Paramètre sauvegardé en absolu: {self.base_dir}")
            except Exception as e:
                # Repli en cas d'erreur de calcul de chemin relatif
                self.save_settings({"storage_path": str(self.base_dir)})
                logger.warning(f"Impossible de sauvegarder en relatif, repli sur absolu: {e}")
    
    def ensure_directories(self, dir_names: Optional[List[str]] = None) -> None:
        """
        Crée les répertoires spécifiés s'ils n'existent pas
        Si dir_names est None, crée tous les répertoires
        """
        if dir_names is None:
            dir_names = list(self.directories.keys())
        
        for dir_name in dir_names:
            if dir_name in self.directories:
                dir_path = self.directories[dir_name]
                dir_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Dossier créé: {dir_path}")
    
    def ensure_directory(self, dir_name: str) -> Path:
        """
        Crée un dossier spécifique s'il n'existe pas et retourne son chemin
        
        Args:
            dir_name: Nom du dossier à créer/assurer
        
        Returns:
            Chemin du dossier
        """
        if dir_name not in self.directories:
            raise ValueError(f"Dossier inconnu: {dir_name}")
        
        dir_path = self.directories[dir_name]
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path
    
    def get_directory(self, dir_name: str, create_if_missing: bool = False) -> Path:
        """
        Retourne le chemin d'un dossier spécifique
        
        Args:
            dir_name: Nom du dossier
            create_if_missing: Si True, crée le dossier s'il n'existe pas
        
        Returns:
            Chemin du dossier
        """
        if dir_name not in self.directories:
            raise ValueError(f"Dossier inconnu: {dir_name}")
        
        dir_path = self.directories[dir_name]
        
        if create_if_missing:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        return dir_path
    
    
    def save_file(self, content: Union[str, bytes], filename: str, 
                 subdirectory: str, subfolder: Optional[str] = None, 
                 create_dirs: bool = True) -> Path:
        """
        Sauvegarde un fichier dans le dossier spécifié
        
        Args:
            create_dirs: Si True, crée les dossiers nécessaires
        """
        dir_path = self.get_directory(subdirectory, create_if_missing=create_dirs)
        
        if subfolder:
            dir_path = dir_path / subfolder
            if create_dirs:
                dir_path.mkdir(parents=True, exist_ok=True)
        
        file_path = dir_path / filename
        
        mode = 'w' if isinstance(content, str) else 'wb'
        encoding = 'utf-8' if isinstance(content, str) else None
        
        try:
            with open(file_path, mode, encoding=encoding) as f:
                f.write(content)
            
            logger.info(f"Fichier sauvegardé: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Erreur sauvegarde fichier {file_path}: {e}")
            raise
    
    
    def read_file(self, filename: str, subdirectory: str, 
                 subfolder: Optional[str] = None, as_bytes: bool = False) -> Union[str, bytes]:
        """
        Lit un fichier depuis le stockage
        """
        dir_path = self.get_directory(subdirectory)
        
        if subfolder:
            dir_path = dir_path / subfolder
        
        file_path = dir_path / filename
        
        if not file_path.exists():
            raise FileNotFoundError(f"Fichier introuvable: {file_path}")
        
        mode = 'rb' if as_bytes else 'r'
        encoding = None if as_bytes else 'utf-8'
        
        with open(file_path, mode, encoding=encoding) as f:
            return f.read()
    
    def list_files(self, subdirectory: str, subfolder: Optional[str] = None, 
                  pattern: str = "*", create_if_missing: bool = False) -> List[Path]:
        """
        Liste les fichiers dans un dossier
        """
        dir_path = self.get_directory(subdirectory, create_if_missing=create_if_missing)
        
        if subfolder:
            dir_path = dir_path / subfolder
            if create_if_missing:
                dir_path.mkdir(parents=True, exist_ok=True)
        
        return list(dir_path.glob(pattern))
    
    def file_exists(self, filename: str, subdirectory: str, 
                   subfolder: Optional[str] = None) -> bool:
        """
        Vérifie si un fichier existe
        """
        dir_path = self.get_directory(subdirectory)
        
        if subfolder:
            dir_path = dir_path / subfolder
        
        return (dir_path / filename).exists()
    
    def get_file_path(self, filename: str, subdirectory: str, 
                     subfolder: Optional[str] = None, 
                     create_dirs: bool = False) -> Path:
        """
        Retourne le chemin complet d'un fichier
        """
        dir_path = self.get_directory(subdirectory, create_if_missing=create_dirs)
        
        if subfolder:
            dir_path = dir_path / subfolder
            if create_dirs:
                dir_path.mkdir(parents=True, exist_ok=True)
        
        return dir_path / filename
    
    def save_metadata(self, data: Dict, filename: str, 
                     subfolder: Optional[str] = None) -> Path:
        """
        Sauvegarde des métadonnées JSON (crée les dossiers automatiquement)
        """
        json_content = json.dumps(data, indent=2, ensure_ascii=False)
        return self.save_file(json_content, filename, 'metadata', subfolder, create_dirs=True)
    
    def read_metadata(self, filename: str, subfolder: Optional[str] = None) -> Dict:
        """
        Lit des métadonnées JSON
        """
        content = self.read_file(filename, 'metadata', subfolder)
        return json.loads(content)
    
    def get_current_structure(self) -> Dict[str, Path]:
        """
        Retourne la structure actuelle des dossiers
        """
        return self.directories.copy()
    
    def migrate_existing_data(self, old_base_dir: Path) -> None:
        """
        Migre les données existantes vers le nouveau répertoire
        """
        # D'abord, créer tous les dossiers dans le nouvel emplacement
        self.ensure_directories()
        
        for dir_name, new_dir_path in self.directories.items():
            old_dir_path = old_base_dir / dir_name
            
            if old_dir_path.exists() and old_dir_path != new_dir_path:
                try:
                    # Copie récursive du contenu
                    if new_dir_path.exists():
                        shutil.rmtree(new_dir_path)
                    shutil.copytree(old_dir_path, new_dir_path)
                    logger.info(f"Données migrées de {old_dir_path} vers {new_dir_path}")
                except Exception as e:
                    logger.error(f"Erreur migration {dir_name}: {e}")
    
    def directory_exists(self, dir_name: str) -> bool:
        """
        Vérifie si un dossier existe
        """
        if dir_name not in self.directories:
            return False
        return self.directories[dir_name].exists()
    
    def get_existing_directories(self) -> List[str]:
        """
        Retourne la liste des dossiers qui existent réellement
        """
        return [dir_name for dir_name, dir_path in self.directories.items() 
                if dir_path.exists()]

    def get_metrics_graphs_dir(self) -> Path:
        """Retourne le dossier centralisé metrics_graphs/"""
        return self.get_directory("metrics_graphs", create_if_missing=True)

    def get_run_dir(self, operation_id: str) -> Path:
        """
        Crée et retourne le chemin d'un run spécifique : runs/{operation_id}/
        Garantit la création des sous-dossiers requis : graphs/, reports/, system_metrics/.
        """
        run_dir = self.base_dir / "runs" / operation_id
        
        # En cas de conflit (doublon d'id), on génère un suffixe unique
        if run_dir.exists():
            logger.warning(f"Dossier de run {operation_id} existe déjà.")
            counter = 1
            while True:
                suffix_run_dir = self.base_dir / "runs" / f"{operation_id}_{counter}"
                if not suffix_run_dir.exists():
                    run_dir = suffix_run_dir
                    break
                counter += 1
                
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "graphs").mkdir(parents=True, exist_ok=True)
        (run_dir / "reports").mkdir(parents=True, exist_ok=True)
        (run_dir / "system_metrics").mkdir(parents=True, exist_ok=True)
        
        # S'assurer que le dossier centralisé metrics_graphs existe également
        self.get_metrics_graphs_dir()
        return run_dir





# Instance globale
storage_manager = StorageManager()

# === FONCTIONS UTILITAIRES ===

def choose_storage_location():
    """
    Ouvre une boîte de dialogue pour que l'utilisateur choisisse où sauvegarder
    Retourne True si un nouvel emplacement a été choisi
    """
    root = tk.Tk()
    root.withdraw()  # Cache la fenêtre principale
    
    # Déterminer le dossier initial pour Docker
    # On commence par le dossier actuel du stockage s'il existe
    initial_dir = storage_manager.base_dir
    
    # Si on est sur Mac (ou conteneur avec accès Mac), on peut essayer de pointer vers le home
    if not initial_dir or not initial_dir.exists():
        initial_dir = Path.home()
        if os.path.exists("/Users/germainh."):
            initial_dir = Path("/Users/germainh.")

    # Ouvre la boîte de dialogue de sélection de dossier
    chosen_dir = filedialog.askdirectory(
        title="Choisissez où sauvegarder vos fichiers cryptographiques",
        initialdir=initial_dir
    )
    
    if chosen_dir:  # Si l'utilisateur a choisi un dossier
        # Forcer le chemin absolu pour Docker
        chosen_path = Path(chosen_dir).resolve()
        
        # Test de permission d'écriture immédiat
        try:
            test_file = chosen_path / ".mass_vault_test"
            test_file.touch()
            test_file.unlink()
        except Exception as e:
            messagebox.showerror(
                "Erreur de permission",
                f"L'application n'a pas le droit d'écrire dans ce dossier.\n\n"
                f"Chemin: {chosen_path}\nErreur: {str(e)}"
            )
            return False

        # Demande confirmation si le dossier n'est pas vide
        if any(chosen_path.iterdir()):
            confirm = messagebox.askyesno(
                "Confirmation",
                f"Le dossier '{chosen_path.name}' n'est pas vide. "
                "Voulez-vous vraiment l'utiliser ?"
            )
            if not confirm:
                return False
        
        # Sauvegarde l'ancien emplacement pour migration
        old_base_dir = storage_manager.base_dir
        
        # Change le répertoire de base
        storage_manager.set_base_directory(str(chosen_path))
        
        # Migre les données existantes si nécessaire
        storage_manager.migrate_existing_data(old_base_dir)
        
        return True
    
    return False

def get_storage_info() -> Dict[str, Dict[str, Union[str, int, bool]]]:
    """
    Retourne des informations sur le stockage actuel
    
    Returns:
        Dict avec les informations de chaque dossier
    """
    info = {}
    for dir_name, dir_path in storage_manager.get_current_structure().items():
        file_count = len(list(dir_path.glob('*'))) if dir_path.exists() else 0
        dir_size = sum(f.stat().st_size for f in dir_path.rglob('*') if f.is_file()) if dir_path.exists() else 0
        
        info[dir_name] = {
            'path': str(dir_path),
            'file_count': file_count,
            'total_size_bytes': dir_size,
            'total_size_mb': dir_size / (1024 * 1024),
            'exists': dir_path.exists()
        }
    return info

def get_storage_location() -> str:
    """Retourne l'emplacement de stockage actuel"""
    return str(storage_manager.base_dir)

def set_storage_location(new_path: str) -> None:
    """Définit un nouvel emplacement de stockage"""
    storage_manager.set_base_directory(new_path)

def get_storage_stats() -> Dict[str, Dict[str, Union[int, float]]]:
    stats = {}
    for dir_name, dir_path in storage_manager.directories.items():
        if dir_path.exists():
            files = [f for f in dir_path.rglob('*') if f.is_file()]
            file_count = len(files)
            total_size = sum(f.stat().st_size for f in files)
            stats[dir_name] = {
                'file_count': file_count,
                'total_size': total_size,
                'total_size_mb': total_size / (1024 * 1024)
            }
    return stats

def show_storage_details():
    """Affiche les détails du stockage dans une boîte de message"""
    info = get_storage_info()
    
    details = "DÉTAILS DU STOCKAGE\n\n"
    details += f"Emplacement de base: {storage_manager.base_dir}\n\n"
    
    for dir_name, dir_info in info.items():
        details += f"{dir_name.upper()}:\n"
        details += f"  Chemin: {dir_info['path']}\n"
        details += f"  Fichiers: {dir_info['file_count']}\n"
        details += f"  Taille: {dir_info['total_size_mb']:.2f} MB\n"
        details += f"  Existe: {'Oui' if dir_info['exists'] else 'Non'}\n\n"
    
    messagebox.showinfo("Détails du Stockage", details)

def migrate_data_to_new_location(new_location: str) -> bool:
    """
    Migre toutes les données vers un nouvel emplacement
    
    Args:
        new_location: Nouveau chemin de stockage
    
    Returns:
        True si la migration a réussi
    """
    try:
        new_storage = StorageManager(new_location)
        old_storage = StorageManager()
        
        # Migrer chaque dossier
        for dir_name in storage_manager.directories.keys():
            old_dir = old_storage.get_directory(dir_name)
            new_dir = new_storage.get_directory(dir_name)
            
            if old_dir.exists() and old_dir != new_dir:
                if new_dir.exists():
                    shutil.rmtree(new_dir)
                shutil.copytree(old_dir, new_dir)
                logger.info(f"Données migrées de {old_dir} vers {new_dir}")
        
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la migration: {e}")
        return False

def get_directory_size(directory: str) -> int:
    """
    Retourne la taille totale d'un dossier en octets
    
    Args:
        directory: Nom du dossier (encrypted_files, keys_generated, etc.)
    
    Returns:
        Taille en octets
    """
    dir_path = storage_manager.get_directory(directory)
    if dir_path.exists():
        return sum(f.stat().st_size for f in dir_path.rglob('*') if f.is_file())
    return 0

def list_files_in_directory(directory: str, pattern: str = "*") -> List[Path]:
    """
    Liste tous les fichiers dans un dossier spécifique
    
    Args:
        directory: Nom du dossier
        pattern: Pattern de recherche (ex: "*.pem")
    
    Returns:
        Liste des chemins de fichiers
    """
    dir_path = storage_manager.get_directory(directory)
    if dir_path.exists():
        return list(dir_path.rglob(pattern))
    return []

def cleanup_directory(directory: str) -> None:
    """
    Nettoie complètement un dossier
    
    Args:
        directory: Nom du dossier à nettoyer
    """
    dir_path = storage_manager.get_directory(directory)
    if dir_path.exists():
        shutil.rmtree(dir_path)
        logger.info(f"Dossier {directory} nettoyé")

def ensure_operation_directories(operation_type: str):
    """
    Crée les dossiers nécessaires pour une opération spécifique
    
    Args:
        operation_type: Type d'opération ('encrypt', 'decrypt', 'sign', 'verify')
    """
    if operation_type == 'encrypt_sign':
        storage_manager.ensure_directories([
            'encrypted_files', 'metadata', 'performance_outputs'
        ])
    elif operation_type == 'decrypt':
        storage_manager.ensure_directories([
            'decrypted_files', 'decryption_outputs'
        ])
    elif operation_type == 'sign':
        storage_manager.ensure_directories([
            'signed_files', 'metadata'
        ])
    elif operation_type == 'verify':
        storage_manager.ensure_directories([
            'verified_files'
        ])
        
        