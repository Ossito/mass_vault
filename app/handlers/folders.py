import os
import re
from tkinter import filedialog

def select_folder():
    from pathlib import Path
    initial_dir = Path.home()
    if os.path.exists("/Users/germainh."):
        initial_dir = "/Users/germainh."
        
    folder_selected = filedialog.askdirectory(initialdir=initial_dir)
    if not folder_selected:
        print("❌ Aucun dossier sélectionné")
        return [], 0, None

    # Forcer le chemin absolu pour Docker
    folder_selected = str(Path(folder_selected).resolve())

    print(f"📁 Diagnostic Docker Path: {folder_selected}")
    print(f"   - Existe: {os.path.exists(folder_selected)}")
    print(f"   - Est un dossier: {os.path.isdir(folder_selected)}")
    try:
        stat_info = os.stat(folder_selected)
        print(f"   - Mode (Permissions): {oct(stat_info.st_mode)}")
        print(f"   - Liste brute: {os.listdir(folder_selected)}")
    except Exception as e:
        print(f"   - Erreur stat/listdir: {e}")

    files = []
    total_size = 0

    try:
        # Vérifier si le dossier est accessible
        if not os.access(folder_selected, os.R_OK):
            print(f"🚫 Erreur : Accès refusé au dossier {folder_selected}")
            return [], 0, folder_selected

        items = os.listdir(folder_selected)
        for file in items:
            file_path = os.path.join(folder_selected, file)
            # Accepter tout ce qui est un fichier (pas de filtre d'extension strict)
            is_file = os.path.isfile(file_path)
            if is_file and not file.startswith('.'): 
                try:
                    file_size = os.path.getsize(file_path)
                    file_size_mo = file_size / (1024 * 1024)
                    files.append((file, file_size_mo))
                    total_size += file_size
                except Exception as e:
                    print(f"⚠️ Impossible de lire la taille de {file}: {e}")

        print(f"✅ Scanning terminé : {len(files)} fichiers trouvés.")
    except Exception as e:
        print(f"❌ Erreur lors du scanning : {e}")

    formatted_files = [f"{get_file_size(os.path.join(folder_selected, f[0]))} => {f[0]}" for f in files]
    
    return formatted_files, total_size, folder_selected


def get_file_size(file_path):
    size = os.path.getsize(file_path)
    if size < 1024:
        return f"{size} octets"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} Ko"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} Mo"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} Go"

def extract_size_and_name(formatted_string):
    match = re.match(r"([\d.]+)\s*(\w+)\s*=>\s*(.+)", formatted_string)
    if match:
        size_value, size_unit, file_name = match.groups()
        return float(size_value), size_unit, file_name
    return None, None, None