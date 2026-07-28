import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from tkinter import simpledialog
from typing import List, Optional
import datetime
import json

# Try to import PIL for image thumbnails
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    Image = None
    ImageTk = None


class ExplorerManager:
    def __init__(self, storage_manager):
        self.storage_manager = storage_manager
        self.show_sensitive_folders = False
        self.current_operation_type = None
        self.current_algorithm = None
        self.current_key_size = None
        self._thumbnail_refs = []

    # ----------------------------------------------------------------------
    # Interface principale
    # ----------------------------------------------------------------------
    def create_explorer_interface(self, parent_window, operation_type: str,
                                  algorithm: str, key_size: str) -> Optional[tk.Toplevel]:
        try:
            self.current_operation_type = operation_type
            self.current_algorithm = algorithm
            self.current_key_size = key_size
            algo_id = f"{algorithm}_{key_size}"

            result_dirs = self.get_all_result_directories(operation_type, algorithm, key_size)
            if not result_dirs:
                messagebox.showinfo("Information", f"Aucun résultat trouvé pour {algo_id}.")
                return None

            explorer_window = tk.Toplevel(parent_window)
            explorer_window.title(f"🔍 Explorateur - {algorithm} {key_size}")
            explorer_window.geometry("1100x650")
            explorer_window.configure(bg="#f0f2f5")

            # ---- Barre supérieure ----
            header = ttk.Frame(explorer_window, padding=15)
            header.pack(fill="x")

            title_frame = ttk.Frame(header)
            title_frame.pack(fill="x")

            type_labels = {
                "encrypt_sign": "🔐 Chiffrement & Signature",
                "decryption": "🔓 Déchiffrement",
                "verification": "✅ Vérification"
            }
            op_label = type_labels.get(operation_type, "Opération")
            ttk.Label(title_frame, text=f"{op_label} - {algorithm} {key_size}",
                      font=("Arial", 16, "bold"), background="#f0f2f5").pack(side="left")

            stats = self._get_operation_stats(operation_type, algorithm, key_size)
            ttk.Label(title_frame, text=stats, font=("Arial", 10),
                      foreground="#666", background="#f0f2f5").pack(side="right")

            # ---- PanedWindow gauche / droite ----
            paned = ttk.PanedWindow(explorer_window, orient="horizontal")
            paned.pack(fill="both", expand=True, padx=10, pady=5)

            # ** Volet gauche : arbre de navigation **
            left_frame = ttk.Frame(paned, width=280)
            paned.add(left_frame, weight=0)

            ttk.Label(left_frame, text="📂 Navigation", font=("Arial", 11, "bold"),
                      padding=10).pack(fill="x")

            tree_nav = ttk.Treeview(left_frame, show="tree", selectmode="browse", height=20)
            tree_nav.pack(fill="both", expand=True, padx=5, pady=5)

            nav_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=tree_nav.yview)
            nav_scroll.pack(side="right", fill="y")
            tree_nav.configure(yscrollcommand=nav_scroll.set)

            # ** Volet droit : contenu dynamique **
            right_frame = ttk.Frame(paned)
            paned.add(right_frame, weight=1)

            content_label = ttk.Label(right_frame, text="Sélectionnez un dossier dans l'arbre",
                                      font=("Arial", 11), foreground="#999")
            content_label.pack(expand=True)

            content_frame = ttk.Frame(right_frame)
            content_frame.pack(fill="both", expand=True, padx=10, pady=10)

            # ---- Barre d'outils ----
            toolbar = ttk.Frame(explorer_window, padding=10)
            toolbar.pack(fill="x")

            ttk.Button(toolbar, text="📂 Ouvrir le dossier de base",
                       command=lambda: self.open_file_explorer(self.storage_manager.base_dir)
                       ).pack(side="left", padx=5)

            if operation_type == "encrypt_sign":
                if not self.show_sensitive_folders:
                    ttk.Button(toolbar, text="🔓 Accès avancé",
                            command=lambda: self._unlock_sensitive(
                                explorer_window, tree_nav, content_frame,
                                operation_type, algorithm, key_size)
                            ).pack(side="left", padx=5)
                else:
                    ttk.Button(toolbar, text="🔒 Masquer données sensibles",
                            command=lambda: self._lock_sensitive(
                                explorer_window, tree_nav, content_frame,
                                operation_type, algorithm, key_size)
                            ).pack(side="left", padx=5)

            ttk.Button(toolbar, text="📋 Copier tous les chemins",
                       command=lambda: self._copy_all_paths(operation_type, algorithm, key_size)
                       ).pack(side="left", padx=5)

            ttk.Button(toolbar, text="❌ Fermer", command=explorer_window.destroy
                       ).pack(side="right", padx=5)

            self._populate_navigation_tree(tree_nav, operation_type, algorithm, key_size)

            def on_nav_select(event):
                selected = tree_nav.selection()
                if not selected:
                    return
                item = tree_nav.item(selected[0])
                values = item.get("values", [])
                if values and values[0]:
                    path = Path(values[0])
                    if path.exists():
                        self._load_content(content_frame, path)

            tree_nav.bind("<<TreeviewSelect>>", on_nav_select)

            self._center_window(explorer_window)
            return explorer_window

        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de créer l'explorateur: {str(e)}")
            return None

    def _get_image_thumbnail(self, image_path, size=(150, 150)):
        """Retourne une miniature PhotoImage si PIL est disponible, sinon None."""
        if not HAS_PIL or Image is None or ImageTk is None:
            return None
        try:
            img = Image.open(image_path)
            img.thumbnail(size)
            return ImageTk.PhotoImage(img)
        except Exception:
            return None

    # ----------------------------------------------------------------------
    # Résolution des dossiers ECC
    # ----------------------------------------------------------------------
    def _get_algo_dir_candidates(self, algorithm: str, key_size: str) -> List[str]:
        """Retourne les noms de dossier possibles pour un algorithme donné."""
        if algorithm == "ECC":
            clean_size = str(key_size).replace("P-", "")
            return [f"ECC_P-{clean_size}", f"ECC_{clean_size}"]
        return [f"{algorithm}_{key_size}"]

    def _resolve_algo_dir(self, base_dir: Path, algorithm: str, key_size: str, prefer_no_prefix: bool = False) -> Path:
        """
        Retourne le premier dossier existant parmi les variantes.
        Si prefer_no_prefix est True, essaie d'abord le format sans 'P-' (pour vérification/déchiffrement).
        """
        candidates = self._get_algo_dir_candidates(algorithm, key_size)
        if prefer_no_prefix:
            # Inverse l'ordre pour privilégier ECC_384 au lieu de ECC_P-384
            candidates = candidates[::-1]
        for candidate in candidates:
            dir_path = base_dir / candidate
            if dir_path.exists():
                return dir_path
        # Aucun trouvé, retourner le premier candidat (ordre original)
        return base_dir / candidates[0]

    
    def _filter_graph_items(self, items, operation_type):
        """Filtre les fichiers du dossier graphs pour ne garder que ceux de l'opération en cours."""
        allowed = {
            "encrypt_sign": [
                "encryption_stats.png",
                "signing_stats.png",
                "phases_detail.png",
                "aes_keygen_time.png",
                "asymmetric_keygen_time.png",
                "overhead_percent.png",
                "overhead_size_comparison.png",
                "overhead_scatter.png"
            ],
            "decryption": [
                "decryption_stats.png"
            ],
            "verification": [
                "verification_stats.png"
            ]
        }
        names = allowed.get(operation_type, [])
        return [f for f in items if f.name in names]
    
    # ----------------------------------------------------------------------
    # Arbre de navigation
    # ----------------------------------------------------------------------
    def _populate_navigation_tree(self, tree_nav, operation_type, algorithm, key_size):
        for item in tree_nav.get_children():
            tree_nav.delete(item)

        base = self.storage_manager.base_dir
        sections = []

        # Pour ECC, les fichiers sont toujours sans P-
        if algorithm == "ECC":
            clean_size = str(key_size).replace("P-", "")
            file_algo_id = f"ECC_{clean_size}"
        else:
            file_algo_id = f"{algorithm}_{key_size}"

        if operation_type == "encrypt_sign":
            # Fichiers chiffrés / signés (format sans P- pour ECC)
            enc_dir = base / "encrypted_files" / file_algo_id
            if enc_dir.exists():
                sections.append(("🔒 Fichiers chiffrés", enc_dir))

            sig_dir = base / "signed_files" / file_algo_id
            if sig_dir.exists():
                sections.append(("📝 Fichiers signés", sig_dir))

            # Graphiques (format avec P- pour ECC)
            graphs_dir = self._resolve_algo_dir(base / "performance_outputs" / "graphs", algorithm, key_size)
            if graphs_dir.exists():
                sections.append(("📊 Graphiques de performance", graphs_dir))

            # Métriques système (format avec P- pour ECC)
            sys_algo_dir = self._resolve_algo_dir(base / "performance_resources", algorithm, key_size)
            sys_dir = sys_algo_dir / "system_metrics"
            if sys_dir.exists():
                sections.append(("📈 Métriques système", sys_dir))

            if self.show_sensitive_folders:
                meta_dir = base / "metadata" / file_algo_id
                if meta_dir.exists():
                    sections.append(("🔑 Métadonnées", meta_dir))
                keys_dir = base / "keys_generated" / file_algo_id
                if keys_dir.exists():
                    sections.append(("🔐 Clés générées", keys_dir))

        elif operation_type == "decryption":
            dec_dir = base / "decrypted_files" / file_algo_id
            if dec_dir.exists():
                sections.append(("📄 Fichiers déchiffrés", dec_dir))

            # Pour le déchiffrement, on privilégie le dossier sans P- (ECC_384)
            graphs_dir = self._resolve_algo_dir(
                base / "performance_outputs" / "graphs",
                algorithm, key_size,
                prefer_no_prefix=True
            )
            if graphs_dir.exists():
                sections.append(("📊 Graphiques de déchiffrement", graphs_dir))

        elif operation_type == "verification":
            graphs_dir = self._resolve_algo_dir(
                base / "performance_outputs" / "graphs",
                algorithm, key_size,
                prefer_no_prefix=True
            )
            if graphs_dir.exists():
                sections.append(("📊 Graphiques de vérification", graphs_dir))

        for label, path in sections:
            node = tree_nav.insert("", "end", text=label, values=(str(path),))
            if path.is_dir():
                self._add_sub_nodes(tree_nav, node, path)

    def _add_sub_nodes(self, tree, parent, path, max_depth=1, current_depth=0):
        if current_depth >= max_depth or not path.is_dir():
            return
        try:
            items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            for item in items:
                if item.name.startswith('.'):
                    continue
                if item.is_dir():
                    node = tree.insert(parent, "end", text=f"📁 {item.name}", values=(str(item),))
                    self._add_sub_nodes(tree, node, item, max_depth, current_depth + 1)
                else:
                    icon = self._get_file_icon(item.name)
                    tree.insert(parent, "end", text=f"{icon} {item.name}", values=(str(item),))
        except PermissionError:
            pass

    def _get_file_icon(self, filename):
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        icons = {
            'png': '🖼️', 'jpg': '🖼️', 'jpeg': '🖼️',
            'json': '📋', 'meta': '📋',
            'sig': '✍️', 'pem': '🔑',
            'csv': '📄', 'txt': '📄', 'pdf': '📕'
        }
        return icons.get(ext, '📄')

    # ----------------------------------------------------------------------
    # Panneau de contenu
    # ----------------------------------------------------------------------
    def _load_content(self, content_frame, path):
        for widget in content_frame.winfo_children():
            widget.destroy()
        if not path.exists():
            ttk.Label(content_frame, text="Dossier inaccessible").pack()
            return

        header = ttk.Frame(content_frame)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text=f"📂 {path.name}", font=("Arial", 13, "bold")).pack(side="left")
        ttk.Button(header, text="📂 Ouvrir dans l'explorateur",
                   command=lambda: self.open_file_explorer(path)).pack(side="right")

        if path.is_dir():
            self._display_folder_content(content_frame, path)
        else:
            items = [f for f in path.parent.iterdir() if not f.name.startswith('.')] if path.parent.exists() else [path]
            self._display_file_preview(content_frame, path, items)

    
    def _display_folder_content(self, parent, path):
        items = [f for f in path.iterdir() if not f.name.startswith('.')]

        # Filtrage selon l'opération si on est dans le dossier des graphiques
        base = self.storage_manager.base_dir
        # Utiliser la même priorité que dans l'arbre de navigation
        prefer_no_prefix = self.current_operation_type in ("verification", "decryption")
        graphs_dir = self._resolve_algo_dir(
            base / "performance_outputs" / "graphs",
            self.current_algorithm, # type: ignore
            self.current_key_size, # type: ignore
            prefer_no_prefix=prefer_no_prefix
        ).resolve()

        if path.resolve() == graphs_dir and self.current_operation_type:
            items = self._filter_graph_items(items, self.current_operation_type)

        image_exts = {'.png', '.jpg', '.jpeg'}
        if items and sum(1 for f in items if f.suffix.lower() in image_exts) > len(items) * 0.5:
            self._display_image_grid(parent, path, items)
        else:
            self._display_file_list(parent, path, items)
    

    def _open_file_with_viewer(self, file_path: Path, all_items_in_dir: Optional[List[Path]] = None):
        suffix = file_path.suffix.lower()
        if suffix in ('.png', '.jpg', '.jpeg', '.gif', '.bmp'):
            image_list = [f for f in all_items_in_dir if f.suffix.lower() in ('.png','.jpg','.jpeg','.gif','.bmp')] if all_items_in_dir else [file_path]
            self._open_image_viewer(file_path, image_list)
        elif suffix == '.json':
            self._open_json_viewer(file_path)
        else:
            self._open_file_with_default_app(file_path)

    def _display_file_list(self, parent, path, items):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)

        columns = ("name", "size", "type", "modified")
        tree = ttk.Treeview(frame, columns=columns, show="tree headings", height=12)
        tree.heading("name", text="Nom")
        tree.heading("size", text="Taille")
        tree.heading("type", text="Type")
        tree.heading("modified", text="Modifié")
        tree.column("name", width=250)
        tree.column("size", width=100, anchor="e")
        tree.column("type", width=100, anchor="center")
        tree.column("modified", width=150)
        tree.column("#0", width=0, stretch=False)

        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        for item in sorted(items, key=lambda x: (not x.is_dir(), x.name.lower())):
            if item.is_dir():
                tree.insert("", "end", values=(f"📁 {item.name}", "", "Dossier",
                            datetime.datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M")))
            else:
                size = self._get_size_string(item.stat().st_size)
                ext = item.suffix.lower()
                file_type = "Fichier"
                if ext in ['.png', '.jpg']: file_type = "Image"
                elif ext == '.json': file_type = "JSON"
                elif ext == '.csv': file_type = "CSV"
                elif ext == '.sig': file_type = "Signature"
                tree.insert("", "end", values=(f"📄 {item.name}", size, file_type,
                            datetime.datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M")))

        def on_double_click(event):
            selected = tree.selection()
            if selected:
                values = tree.item(selected[0])["values"]
                name = values[0].replace("📁 ", "").replace("📄 ", "")
                file_path = path / name
                if file_path.exists():
                    if file_path.is_file():
                        self._open_file_with_viewer(file_path, items)
                    else:
                        self._load_content(parent.master.master, file_path)

        tree.bind("<Double-1>", on_double_click)

    def _display_image_grid(self, parent, path, items):
        canvas = tk.Canvas(parent, bg="white")
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        grid_frame = ttk.Frame(canvas)
        grid_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=grid_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        row, col = 0, 0
        self._thumbnail_refs.clear()

        for item in items:
            if item.suffix.lower() not in ['.png', '.jpg', '.jpeg']:
                continue
            frame = ttk.Frame(grid_frame, relief="solid", borderwidth=1)
            frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

            thumb = self._get_image_thumbnail(item)
            if thumb:
                self._thumbnail_refs.append(thumb)
                lbl = ttk.Label(frame, image=thumb)
                lbl.image = thumb  # type: ignore
                lbl.pack(pady=5)
                lbl.bind("<Button-1>", lambda e, p=item: self._open_image_viewer(item, items))
            else:
                ttk.Label(frame, text="🖼️ Aperçu non disponible", font=("Arial", 8)).pack(pady=10)

            ttk.Label(frame, text=item.name[:30] + ('...' if len(item.name) > 30 else ''),
                      font=("Arial", 9, "bold")).pack(pady=2)
            ttk.Label(frame, text=f"Taille: {self._get_size_string(item.stat().st_size)}",
                      font=("Arial", 8)).pack()
            ttk.Button(frame, text="👁️ Ouvrir",
                       command=lambda p=item: self._open_image_viewer(p, items)).pack(pady=5)

            col += 1
            if col >= 3:
                col = 0
                row += 1

    def _display_file_preview(self, parent, path, items):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)

        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text=f"📄 {path.name}", font=("Arial", 13, "bold")).pack(side="left")
        ttk.Button(header, text="📂 Ouvrir dans l'explorateur",
                command=lambda: self.open_file_explorer(path.parent)).pack(side="right")

        suffix = path.suffix.lower()
        if suffix in ('.png', '.jpg', '.jpeg', '.gif', '.bmp'):
            thumb = self._get_image_thumbnail(path, size=(300, 300))
            if thumb:
                self._thumbnail_refs.append(thumb)
                lbl = ttk.Label(frame, image=thumb)
                lbl.image = thumb  # type: ignore
                lbl.pack(pady=10)
                lbl.bind("<Button-1>", lambda e: self._open_image_viewer(path, items if items else [path]))
            else:
                ttk.Label(frame, text="🖼️ Aperçu non disponible (PIL manquant)", font=("Arial", 10)).pack(pady=20)

            info_frame = ttk.Frame(frame)
            info_frame.pack(fill="x", pady=10)
            ttk.Label(info_frame, text=f"Taille : {self._get_size_string(path.stat().st_size)}",
                    font=("Arial", 9)).pack(side="left", padx=5)
            ttk.Button(info_frame, text="👁️ Voir en grand",
                    command=lambda: self._open_image_viewer(path, items if items else [path])).pack(side="right", padx=5)

        elif suffix == '.json':
            ttk.Button(frame, text="📂 Ouvrir le fichier",
                    command=lambda: self._open_file_with_default_app(path)).pack(pady=5)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                text = tk.Text(frame, wrap="word", height=20)
                text.pack(fill="both", expand=True)
                if "metadata" in data:
                    text.insert("end", "=== MÉTADONNÉES ===\n")
                    for k, v in data["metadata"].items():
                        text.insert("end", f"• {k}: {v}\n")
                    text.insert("end", "\n")
                if "timings" in data:
                    text.insert("end", "=== TEMPS ===\n")
                    for k, v in data["timings"].items():
                        text.insert("end", f"• {k}: {v:.4f}s\n")
                    text.insert("end", "\n")
                text.config(state="disabled")
            except Exception as e:
                ttk.Label(frame, text=f"Erreur lecture JSON: {e}").pack()
        else:
            ttk.Label(frame, text=f"Type de fichier : {suffix}", font=("Arial", 10)).pack(pady=10)
            ttk.Button(frame, text="📂 Ouvrir avec l'application par défaut",
                    command=lambda: self._open_file_with_default_app(path)).pack(pady=5)

    # ----------------------------------------------------------------------
    # Sensitive unlock / lock
    # ----------------------------------------------------------------------
    def _unlock_sensitive(self, window, tree_nav, content_frame, op_type, algo, key_size):
        password = simpledialog.askstring("Authentification", "Mot de passe pour accéder aux dossiers sensibles:", show='*')
        if password == "demo123":
            self.show_sensitive_folders = True
            messagebox.showinfo("Accès autorisé", "Dossiers sensibles déverrouillés.")
            window.destroy()
            self.create_explorer_interface(window.master, op_type, algo, key_size)
        else:
            messagebox.showerror("Accès refusé", "Mot de passe incorrect.")

    def _lock_sensitive(self, window, tree_nav, content_frame, op_type, algo, key_size):
        self.show_sensitive_folders = False
        messagebox.showinfo("Information", "Dossiers sensibles masqués.")
        window.destroy()
        self.create_explorer_interface(window.master, op_type, algo, key_size)

    # ----------------------------------------------------------------------
    # Utilitaires
    # ----------------------------------------------------------------------
    def _get_operation_stats(self, operation_type, algorithm, key_size):
        if algorithm == "ECC":
            clean_size = str(key_size).replace("P-", "")
            algo_id = f"ECC_{clean_size}"
        else:
            algo_id = f"{algorithm}_{key_size}"
        base = self.storage_manager.base_dir
        if operation_type == "encrypt_sign":
            enc = base / "encrypted_files" / algo_id
            sig = base / "signed_files" / algo_id
            enc_cnt = len([f for f in enc.iterdir() if f.is_file()]) if enc.exists() else 0
            sig_cnt = len([f for f in sig.iterdir() if f.is_file()]) if sig.exists() else 0
            return f"📊 {enc_cnt} chiffré(s) | {sig_cnt} signature(s)"
        return ""

    def _copy_all_paths(self, operation_type, algorithm, key_size):
        dirs = self.get_all_result_directories(operation_type, algorithm, key_size)
        text = f"CHEMINS - {algorithm}_{key_size}\n\n" + "\n".join(f"• {d}" for d in dirs)
        try:
            top = tk.Toplevel()
            top.withdraw()
            top.clipboard_clear()
            top.clipboard_append(text)
            top.destroy()
            messagebox.showinfo("Succès", "Chemins copiés.")
        except:
            messagebox.showerror("Erreur", "Impossible de copier.")

    def get_all_result_directories(self, operation_type: str, algorithm: str, key_size: str) -> List[Path]:
        result_dirs = []
        base = self.storage_manager.base_dir

        if algorithm == "ECC":
            clean_size = str(key_size).replace("P-", "")
            file_algo_id = f"ECC_{clean_size}"
        else:
            file_algo_id = f"{algorithm}_{key_size}"

        if operation_type == "encrypt_sign":
            enc_dir = base / "encrypted_files" / file_algo_id
            if enc_dir.exists():
                result_dirs.append(enc_dir)
            sig_dir = base / "signed_files" / file_algo_id
            if sig_dir.exists():
                result_dirs.append(sig_dir)
            graphs_dir = self._resolve_algo_dir(base / "performance_outputs" / "graphs", algorithm, key_size)
            if graphs_dir.exists():
                result_dirs.append(graphs_dir)
            sys_dir = self._resolve_algo_dir(base / "performance_resources", algorithm, key_size) / "system_metrics"
            if sys_dir.exists():
                result_dirs.append(sys_dir)
            if self.show_sensitive_folders:
                meta_dir = base / "metadata" / file_algo_id
                if meta_dir.exists():
                    result_dirs.append(meta_dir)
                keys_dir = base / "keys_generated" / file_algo_id
                if keys_dir.exists():
                    result_dirs.append(keys_dir)

        elif operation_type == "decryption":
            dec_dir = base / "decrypted_files" / file_algo_id
            if dec_dir.exists():
                result_dirs.append(dec_dir)
            # Priorité sans P-
            for candidate in self._get_algo_dir_candidates(algorithm, key_size)[::-1]:  # ordre inversé
                gdir = base / "performance_outputs" / "graphs" / candidate
                if gdir.exists():
                    result_dirs.append(gdir)
                    break

        elif operation_type == "verification":
            for candidate in self._get_algo_dir_candidates(algorithm, key_size)[::-1]:
                gdir = base / "performance_outputs" / "graphs" / candidate
                if gdir.exists():
                    result_dirs.append(gdir)
                    break

        return result_dirs

    def open_file_explorer(self, path: Path) -> bool:
        try:
            if os.name == 'nt':
                os.startfile(path)
            elif sys.platform == 'darwin':
                subprocess.run(['open', str(path)])
            else:
                subprocess.run(['xdg-open', str(path)])
            return True
        except:
            messagebox.showinfo("Emplacement", f"Chemin du dossier:\n{path}")
            return False

    def _open_image_viewer(self, current_image: Path, image_list: List[Path]):
        viewer = tk.Toplevel()
        viewer.title(f"Visionneuse - {current_image.name}")
        viewer.geometry("900x700")
        viewer.configure(bg="black")

        status = ttk.Label(viewer, text="", foreground="white", background="black")
        status.pack(side="bottom", fill="x")

        main_frame = ttk.Frame(viewer)
        main_frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(main_frame, bg="black", highlightthickness=0)
        h_scroll = ttk.Scrollbar(main_frame, orient="horizontal", command=canvas.xview)
        v_scroll = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        canvas.configure(xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        h_scroll.grid(row=1, column=0, sticky="ew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        image_list_sorted = sorted(
            [p for p in image_list if p.suffix.lower() in ('.png', '.jpg', '.jpeg', '.gif', '.bmp')],
            key=lambda p: p.name
        )
        current_index = image_list_sorted.index(current_image) if current_image in image_list_sorted else 0

        photo_ref: list = [None]

        def load_and_display(index: int):
            if not (0 <= index < len(image_list_sorted)):
                return
            path = image_list_sorted[index]
            viewer.title(f"Visionneuse - {path.name}")
            status.config(text=f"Image {index+1} / {len(image_list_sorted)}  •  {path.name}")

            if not HAS_PIL or Image is None or ImageTk is None:
                canvas.create_text(400, 300, text="PIL non installé", fill="white")
                return

            try:
                img = Image.open(path)
                viewer.update_idletasks()
                cw = canvas.winfo_width()
                ch = canvas.winfo_height()
                if cw < 100:
                    cw = 800
                    ch = 600
                max_w = max(1, cw - 20)
                max_h = max(1, ch - 20)
                img.thumbnail((max_w, max_h), Image.LANCZOS) # type: ignore
                photo = ImageTk.PhotoImage(img)
                canvas.delete("all")
                canvas.create_image(0, 0, anchor="nw", image=photo)
                canvas.config(scrollregion=canvas.bbox("all"))
                photo_ref[0] = photo
            except Exception as e:
                canvas.delete("all")
                canvas.create_text(400, 300, text=f"Erreur : {e}", fill="red")

        def next_image():
            nonlocal current_index
            if current_index < len(image_list_sorted) - 1:
                current_index += 1
                load_and_display(current_index)

        def prev_image():
            nonlocal current_index
            if current_index > 0:
                current_index -= 1
                load_and_display(current_index)

        control_frame = ttk.Frame(viewer)
        control_frame.pack(fill="x", pady=5)
        ttk.Button(control_frame, text="◀ Précédent", command=prev_image).pack(side="left", padx=10)
        ttk.Button(control_frame, text="Suivant ▶", command=next_image).pack(side="left")
        ttk.Button(control_frame, text="Fermer", command=viewer.destroy).pack(side="right", padx=10)

        def on_resize(event):
            if event.widget == viewer:
                load_and_display(current_index)
        viewer.bind("<Configure>", on_resize)

        viewer.after(100, lambda: load_and_display(current_index))

    def _open_json_viewer(self, file_path: Path):
        viewer = tk.Toplevel()
        viewer.title(f"JSON - {file_path.name}")
        viewer.geometry("800x600")

        main_frame = ttk.Frame(viewer, padding=10)
        main_frame.pack(fill="both", expand=True)

        ttk.Label(main_frame, text=f"📄 {file_path}", font=("Arial", 9, "bold")).pack(anchor="w", pady=(0,10))

        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill="both", expand=True)

        text_widget = tk.Text(text_frame, wrap="none", font=("Courier", 10))
        v_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        h_scroll = ttk.Scrollbar(text_frame, orient="horizontal", command=text_widget.xview)
        text_widget.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        text_widget.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            formatted = json.dumps(data, indent=4, ensure_ascii=False)
            text_widget.insert("1.0", formatted)

            text_widget.tag_configure("key", foreground="#0000FF")
            text_widget.tag_configure("string", foreground="#008000")
            text_widget.tag_configure("number", foreground="#FF0000")

            start_index = "1.0"
            while True:
                key_start = text_widget.search('"', start_index, stopindex="end")
                if not key_start:
                    break
                key_end = text_widget.search('"', f"{key_start}+1c", stopindex="end")
                if not key_end:
                    break
                after_key = text_widget.get(f"{key_end}+1c", f"{key_end}+3c").strip()
                if after_key.startswith(':'):
                    text_widget.tag_add("key", key_start, f"{key_end}+1c")
                start_index = f"{key_end}+1c"

            text_widget.config(state="disabled")
        except Exception as e:
            text_widget.insert("1.0", f"Erreur lors de la lecture du JSON : {e}")
            text_widget.config(state="disabled")

        ttk.Button(main_frame, text="Fermer", command=viewer.destroy).pack(pady=(10,0))

    def _open_file_with_default_app(self, file_path: Path):
        try:
            if os.name == 'nt':
                os.startfile(file_path)
            elif sys.platform == 'darwin':
                subprocess.run(['open', str(file_path)])
            else:
                subprocess.run(['xdg-open', str(file_path)])
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir le fichier: {e}")

    def _get_size_string(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} octets"
        elif size_bytes < 1024 ** 2:
            return f"{size_bytes / 1024:.2f} Ko"
        elif size_bytes < 1024 ** 3:
            return f"{size_bytes / (1024 ** 2):.2f} Mo"
        else:
            return f"{size_bytes / (1024 ** 3):.2f} Go"

    def _center_window(self, window):
        window.update_idletasks()
        w = window.winfo_width()
        h = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (w // 2)
        y = (window.winfo_screenheight() // 2) - (h // 2)
        window.geometry(f'{w}x{h}+{x}+{y}')

    def set_sensitive_folders_visibility(self, visible: bool):
        self.show_sensitive_folders = visible

    def open_all_result_dirs(self, operation_type: str, algorithm: str, key_size: str):
        for d in self.get_all_result_directories(operation_type, algorithm, key_size):
            self.open_file_explorer(d)

    def get_storage_paths_info(self, operation_type: str, algorithm: str, key_size: str) -> str:
        dirs = self.get_all_result_directories(operation_type, algorithm, key_size)
        if not dirs:
            return f"Aucun résultat pour {algorithm}_{key_size}"
        return f"CHEMINS - {algorithm}_{key_size}\n\n" + "\n".join(f"{i+1}. {d}" for i, d in enumerate(dirs))


# Instance globale
explorer_manager = None


def init_explorer_manager(storage_manager_instance):
    global explorer_manager
    explorer_manager = ExplorerManager(storage_manager_instance)
    return explorer_manager