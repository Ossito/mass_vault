import logging
import os
import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as ttk
from utils.lang import LANGUAGES
from utils.window_utils import center_window, DOCK_OFFSET
from utils.storage import storage_manager
from utils.explorer_manager import explorer_manager
from handlers.verify import perform_verification


class VerificationSignatureWindow:
    def __init__(self, root, change_interface, current_lang, back_button):
        self.root = root
        self.change_interface = change_interface
        self.current_lang = current_lang
        self.language = LANGUAGES[self.current_lang]

        # ---- Back Button ----
        self.back_button = back_button
        self.back_button.config(state="normal")

        # ---- Menu de configuration (bouton Explorer en haut à droite) ----
        self.create_explorer_menu()

        # ---- Conteneur principal ----
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(expand=True, fill="both")

        # ---- Barre de progression (masquée par défaut) ----
        self.progress_var = tk.DoubleVar()
        self.progress_label = ttk.Label(self.frame, text="")
        self.progress_bar = ttk.Progressbar(
            self.frame, variable=self.progress_var, maximum=100, mode='determinate'
        )
        self.progress_bar.grid(row=2, column=0, columnspan=2, pady=(5, 10), sticky="ew")
        self.progress_label.grid(row=3, column=0, columnspan=2, pady=(0, 5))
        self.progress_bar.grid_remove()
        self.progress_label.grid_remove()

        # ---- Configuration des colonnes ----
        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=2)
        self.frame.rowconfigure(0, weight=1)

        # ----------------------------------------------------------------------
        # ---- Left Frame (Algorithm selection) ----
        self.left_frame = ttk.LabelFrame(
            self.frame,
            text=self.language["verification"]["signature_verification"],
            padding=10,
            bootstyle="info"  # type: ignore
        )
        self.left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Algorithm selection
        self.algorithm_label = ttk.Label(self.left_frame,
                                         text=self.language["verification"]["select_algorithm"])
        self.algorithm_label.pack(anchor="w", pady=5)

        self.algorithm_combobox = ttk.Combobox(self.left_frame, values=["RSA", "ECC", "ElGamal"],
                                               state="readonly")
        self.algorithm_combobox.pack(pady=5, padx=10, fill="x")
        self.algorithm_combobox.bind("<<ComboboxSelected>>", self.update_keysize_options)

        self.keysize_label = ttk.Label(self.left_frame,
                                       text=self.language["verification"]["select_keysize"])
        self.keysize_label.pack(anchor="w", pady=5)

        self.keysize_combobox = ttk.Combobox(self.left_frame, state="readonly")
        self.keysize_combobox.pack(pady=5, padx=10, fill="x")
        self.keysize_combobox.config(state="disabled")
        self.keysize_combobox.bind("<<ComboboxSelected>>", self.update_file_lists)

        # Encrypted files list
        self.encrypted_files_label = ttk.Label(
            self.left_frame,
            text=f"{self.language['verification']['sections']['encrypted_files']} \n Total : 0",
            font=('Arial', 12)
        )
        self.encrypted_files_label.pack(anchor="w", pady=5)

        self.encrypted_frame = ttk.Frame(self.left_frame)
        self.encrypted_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.encrypted_scroll = ttk.Scrollbar(self.encrypted_frame, orient="vertical")
        self.encrypted_listbox = tk.Listbox(
            self.encrypted_frame, height=4, width=40, yscrollcommand=self.encrypted_scroll.set,
            selectmode='extended'
        )
        self.encrypted_scroll.config(command=self.encrypted_listbox.yview)
        self.encrypted_listbox.pack(side="left", fill="both", expand=True)
        self.encrypted_scroll.pack(side="right", fill="y")

        # Signed files list
        self.signed_files_label = ttk.Label(
            self.left_frame,
            text=f"{self.language['verification']['sections']['signed_files']} \n Total : 0",
            font=('Arial', 12)
        )
        self.signed_files_label.pack(anchor="w", pady=5)

        self.signed_frame = ttk.Frame(self.left_frame)
        self.signed_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.signed_scroll = ttk.Scrollbar(self.signed_frame, orient="vertical")
        self.signed_listbox = tk.Listbox(
            self.signed_frame, height=4, width=40, yscrollcommand=self.signed_scroll.set,
            selectmode='extended'
        )
        self.signed_scroll.config(command=self.signed_listbox.yview)
        self.signed_listbox.pack(side="left", fill="both", expand=True)
        self.signed_scroll.pack(side="right", fill="y")

        # ----------------------------------------------------------------------
        # ---- Right Frame (Verification results) ----
        self.right_frame = ttk.LabelFrame(
            self.frame,
            text=self.language["verification"]["sections"]["results"],
            padding=10,
            bootstyle="success"  # type: ignore
        )
        self.right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.results_label = ttk.Label(
            self.right_frame,
            text=f"{self.language['verification']['results']['status']}\n Total Vérification(s): 0",
            font=('Arial', 12)
        )
        self.results_label.pack(anchor="w", pady=5)

        self.results_frame = ttk.Frame(self.right_frame)
        self.results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.results_scroll = ttk.Scrollbar(self.results_frame, orient="vertical")
        self.results_text = tk.Text(
            self.results_frame, height=20, width=40, yscrollcommand=self.results_scroll.set,
            state='disabled', wrap=tk.WORD
        )
        self.results_scroll.config(command=self.results_text.yview)
        self.results_text.pack(side="left", fill="both", expand=True)
        self.results_scroll.pack(side="right", fill="y")

        self.results_text.tag_config('success', foreground='green')
        self.results_text.tag_config('error', foreground='red')
        self.results_text.tag_config('warning', foreground='orange')

        # ---- Verify button ----
        self.verify_button = ttk.Button(
            self.frame,
            text=f"🔍 {self.language['verification']['verify_signatures']}",
            command=self.verify_signatures,
            bootstyle="info"  # type: ignore
        )
        self.verify_button.grid(row=1, column=0, columnspan=2, pady=10)

        # ---- Centrage de la fenêtre ----
        top = self.root.winfo_toplevel()
        top.update_idletasks()
        required_width = max(top.winfo_reqwidth(), 950)
        required_height = max(top.winfo_reqheight(), 650)
        center_window(top, required_width, required_height, y_offset=DOCK_OFFSET)

    # ----------------------------------------------------------------------
    # Bouton Explorer (en haut à droite)
    # ----------------------------------------------------------------------
    def create_explorer_menu(self):
        config_frame = ttk.Frame(self.root)
        config_frame.pack(side="top", anchor="ne", padx=10, pady=5)

        self.explore_button = ttk.Button(
            config_frame,
            text="🔍 Explorer",
            command=self.show_explorer_options,
            bootstyle="outline-info",  # type: ignore
            width=15
        )
        self.explore_button.pack(side="left")

    def show_explorer_options(self):
        """Menu contextuel pour l'explorateur (comme dans EncryptSignWindow)"""
        selected_algorithm = self.algorithm_combobox.get()
        selected_keysize = self.keysize_combobox.get()

        menu = tk.Menu(self.root, tearoff=0)

        if not selected_algorithm or not selected_keysize:
            menu.add_command(label="⏳ Sélectionnez un algorithme et une taille", state="disabled")
        else:
            has_operation = self.last_results is not None
            if has_operation:
                menu.add_command(
                    label="🔍 Explorateur avancé",
                    command=lambda: self.open_advanced_explorer(selected_algorithm, selected_keysize)
                )
            else:
                menu.add_command(label="⏳ Aucune vérification effectuée", state="disabled")
                menu.add_command(
                    label="🚀 Lancer la vérification",
                    command=lambda: self.verify_button.invoke()
                )

        menu.add_separator()
        menu.add_command(label="⚙️ Configuration stockage", command=self.show_storage_settings)
        menu.post(self.explore_button.winfo_rootx(),
                  self.explore_button.winfo_rooty() + self.explore_button.winfo_height())

    def open_explorer(self):
        """Ouvre les dossiers de résultats dans l'explorateur système"""
        selected_algorithm = self.algorithm_combobox.get()
        selected_keysize = self.keysize_combobox.get()
        if not selected_algorithm or not selected_keysize:
            return
        if explorer_manager:
            explorer_manager.open_all_result_dirs("verification", selected_algorithm, selected_keysize)

    
    def open_advanced_explorer(self, algorithm, key_size):
        from utils.explorer_manager import explorer_manager
        if explorer_manager is None:
            messagebox.showerror("Erreur", "L'explorateur n'est pas initialisé.")
            return
        explorer_manager.create_explorer_interface(
            self.root, "verification", algorithm, key_size
        )

    def show_storage_settings(self):
        """Affiche les paramètres de stockage (simplifié)"""
        from utils.storage import show_storage_details
        show_storage_details()

    # ----------------------------------------------------------------------
    # Méthodes de gestion de l'interface
    # ----------------------------------------------------------------------
    def toggle_progress(self, show=True):
        if show:
            self.progress_bar.grid()
            self.progress_label.grid()
        else:
            self.progress_bar.grid_remove()
            self.progress_label.grid_remove()
        self.root.update_idletasks()

    def update_keysize_options(self, event=None):
        algorithm = self.algorithm_combobox.get()
        sizes = {
            "RSA": ["1024", "2048", "3072", "4096"],
            "ECC": ["192", "224", "256", "384", "521"],
            "ElGamal": ["1024", "2048", "3072", "4096"]
        }.get(algorithm, [])

        self.keysize_combobox.config(values=sizes, state="readonly" if sizes else "disabled")
        self.keysize_combobox.set('')
        self.clear_file_lists()

    def update_file_lists(self, event=None):
        algorithm = self.algorithm_combobox.get()
        keysize = self.keysize_combobox.get()
        if not algorithm or not keysize:
            return

        algo_id = f"{algorithm}_{keysize}"
        encrypted_dir = storage_manager.get_directory("encrypted_files") / algo_id
        signed_dir = storage_manager.get_directory("signed_files") / algo_id

        self.encrypted_listbox.delete(0, tk.END)
        encrypted_files = []
        if encrypted_dir.exists():
            encrypted_files = [f.name for f in encrypted_dir.iterdir()
                               if f.is_file() and not f.name.startswith('.')]
            for f in encrypted_files:
                self.encrypted_listbox.insert(tk.END, f)

        self.signed_listbox.delete(0, tk.END)
        signed_files = []
        if signed_dir.exists():
            signed_files = [f.name for f in signed_dir.iterdir()
                            if f.is_file() and f.name.endswith('.sig') and not f.name.startswith('.')]
            for f in signed_files:
                self.signed_listbox.insert(tk.END, f)

        self.encrypted_files_label.config(
            text=f"{self.language['verification']['sections']['encrypted_files']} \n Total: {len(encrypted_files)}",
            font=('Arial', 12, 'bold'), foreground="blue"
        )
        self.signed_files_label.config(
            text=f"{self.language['verification']['sections']['signed_files']} \n Total: {len(signed_files)}",
            font=('Arial', 12, 'bold'), foreground="blue"
        )

    def clear_file_lists(self):
        self.encrypted_listbox.delete(0, tk.END)
        self.signed_listbox.delete(0, tk.END)
        self.encrypted_files_label.config(
            text=f"{self.language['verification']['sections']['encrypted_files']} \n Total: 0")
        self.signed_files_label.config(
            text=f"{self.language['verification']['sections']['signed_files']} \n Total: 0")

    # ----------------------------------------------------------------------
    # Vérification
    # ----------------------------------------------------------------------
    def verify_signatures(self):
        algorithm = self.algorithm_combobox.get()
        keysize = self.keysize_combobox.get()
        if not algorithm or not keysize:
            messagebox.showwarning(
                self.language["common"]["warning"],
                self.language["verification"]["messages"]["no_algorithm"]
            )
            return

        # Désactiver le bouton et changer le texte
        self.verify_button.config(state="disabled", text="Vérification en cours...")
        self.explore_button.config(state="disabled")
        self.root.update_idletasks()

        try:
            result = perform_verification(algorithm, keysize)
            self.last_results = result
            self.display_results(result)
            self.update_results_label(result)

            if result['success']:
                messagebox.showinfo(
                    self.language["verification"]["dialogs"]["success_title"],
                    self.language["verification"]["messages"]["success"].format(
                        valid=len(result['valid']),
                        avg_time=sum(result['verif_times'])/max(1, len(result['verif_times']))
                    )
                )
            else:
                messagebox.showwarning(
                    self.language["verification"]["dialogs"]["warning_title"],
                    self.language["verification"]["messages"]["warning"].format(
                        valid=len(result['valid']),
                        invalid=len(result['invalid']),
                        missing=len(result['missing'])
                    )
                )
        except Exception as e:
            messagebox.showerror(
                self.language["common"]["error"],
                f"{self.language['verification']['messages']['error_processing']}: {str(e)}"
            )
        finally:
            # Réactiver les boutons
            self.verify_button.config(
                state="normal",
                text=f"🔍 {self.language['verification']['verify_signatures']}"
            )
            self.explore_button.config(state="normal")
            self.root.update_idletasks()

    def display_results(self, results):
        """Affiche les résultats détaillés avec la liste des fichiers et le récapitulatif"""
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)

        # 1. Liste des fichiers vérifiés
        self.results_text.insert(tk.END, "=== FICHIERS VÉRIFIÉS ===\n", 'header')
        for file_detail in results.get('file_details', []):
            filename = file_detail['filename']
            valid = file_detail['valid']
            msg = file_detail['message']
            if valid:
                self.results_text.insert(tk.END, f"✅ {filename}\n", 'success')
            elif msg.startswith("⚠️"):
                self.results_text.insert(tk.END, f"⚠️ {filename} (signature manquante)\n", 'warning')
            else:
                self.results_text.insert(tk.END, f"❌ {filename}\n", 'error')
        self.results_text.insert(tk.END, "\n")

        # 2. Récapitulatif
        self.results_text.insert(tk.END, "=== RÉCAPITULATIF ===\n", 'header')
        self.results_text.insert(tk.END, f"Signatures valides: {len(results['valid'])}\n", 'success')
        self.results_text.insert(tk.END, f"Signatures invalides: {len(results['invalid'])}\n", 'error')
        self.results_text.insert(tk.END, f"Signatures manquantes: {len(results['missing'])}\n", 'warning')
        self.results_text.insert(tk.END, f"\nTemps moyen de vérification: {sum(results['verif_times'])/max(1,len(results['verif_times'])):.3f}s\n")
        self.results_text.insert(tk.END, f"Taille totale vérifiée: {results.get('total_size', 0)/1024:.2f} Ko\n")

        self.results_text.config(state='disabled')
        self.results_text.see(tk.END)

    def update_results_label(self, results):
        total_files = len(results['valid']) + len(results['invalid']) + len(results['missing'])
        total_size = results.get('total_size', 0)

        # Taille lisible
        if total_size >= 1024 ** 3:
            size_str = f"{total_size / 1024 ** 3:.2f} Go"
        elif total_size >= 1024 ** 2:
            size_str = f"{total_size / 1024 ** 2:.2f} Mo"
        elif total_size >= 1024:
            size_str = f"{total_size / 1024:.2f} Ko"
        else:
            size_str = f"{total_size} octets"

        text_color = "green" if results.get('success', False) else "red"
        self.results_label.config(
            text=f"{self.language['verification']['results']['status']}\n"
                 f"Fichiers vérifiés: {total_files}\n"
                 f"Taille totale: {size_str}",
            font=('Arial', 12, 'bold'),
            foreground=text_color
        )