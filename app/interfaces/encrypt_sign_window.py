import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import ttkbootstrap as ttk 
from utils.lang import LANGUAGES

# Import folder handlers 
from handlers.folders import extract_size_and_name, select_folder

# Import keys generation functions 
from handlers.keys import generate_rsa_keys, generate_ecc_keys, generate_elgamal_keys

# Import process_folder 
from handlers.encrypt_sign import generate_performance_outputs, process_folder

# Import storage manager
from utils.explorer_manager import init_explorer_manager, explorer_manager
from utils.storage import storage_manager, choose_storage_location, get_storage_info
from utils.window_utils import DOCK_OFFSET, center_window


class EncryptSignWindow:
    def __init__(self, root, change_interface, current_lang, back_button):
        self.root = root
        self.change_interface = change_interface
        self.current_lang = current_lang
        self.language = LANGUAGES[self.current_lang]
        
        self.explorer_manager = init_explorer_manager(storage_manager)

        # ---- Root Title ----
        # self.update_window_title()

        # ---- Back Button ----
        self.back_button = back_button
        self.back_button.config(state="normal")

        # ---- Menu de configuration ----
        self.create_storage_menu()

        # ---- Conteneur principal ----
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(expand=True, fill="both")

        # Barre de progression (maintenant après la création de self.frame)
        self.progress_var = tk.DoubleVar()
        self.progress_label = ttk.Label(self.frame, text="")
        self.progress_bar = ttk.Progressbar(
            self.frame, 
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        
        # Positionnement de la barre de progression
        self.progress_bar.grid(row=2, column=0, columnspan=2, pady=(5, 20), sticky="ew")
        self.progress_label.grid(row=3, column=0, columnspan=2, pady=(0, 20)) 
        self.progress_bar.grid_remove()  # Masquer la barre
        self.progress_label.grid_remove()  # Masquer le label

        # ----------------------------------------------------------------------------------
        # ---- LabelFrame de gauche (Sélection de dossier et options) ----
        self.left_frame = ttk.LabelFrame(self.frame, text=self.language["encryption"]["sections"]["selection"], padding=10)
        self.left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # ---- Conteneur pour le texte et le bouton (alignés horizontalement) ----
        self.top_left_frame = ttk.Frame(self.left_frame)
        self.top_left_frame.pack(fill="x", pady=5)  # Remplir horizontalement

        # Texte "Sélectionner un dossier"
        self.folder_label = ttk.Label(self.top_left_frame, text=self.language["encryption"]["select_folder"])
        self.folder_label.pack(side="left", padx=(0, 10))  # Aligner à gauche avec une marge à droite

        # Bouton "Parcourir"
        self.browse_button = ttk.Button(self.top_left_frame, text=self.language["encryption"]["browse"], command=self.browse_folder)
        self.browse_button.pack(side="left")  # Aligner à gauche

        # Ajouter une étiquette pour afficher la taille totale du dossier
        self.total_size_label = ttk.Label(self.left_frame, text=self.language["encryption"]["folder_size"])
        self.total_size_label.pack(anchor="w", pady=5)

        # ---- Liste des fichiers du dossier sélectionné avec Scrollbar ----
        self.folder_frame = ttk.Frame(self.left_frame)
        self.folder_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Scrollbar toujours active
        self.folder_scroll = ttk.Scrollbar(self.folder_frame, orient="vertical")
        self.files_listbox = tk.Listbox(
            self.folder_frame, height=8, width=60, yscrollcommand=self.folder_scroll.set
        )

        # Lier la scrollbar (mais elle sera inutilisable si la liste est vide)
        self.folder_scroll.config(command=lambda *args: self.scroll_if_needed(self.files_listbox, self.folder_scroll, *args))

        self.files_listbox.pack(side="left", fill="both", expand=True)
        self.folder_scroll.pack(side="right", fill="y")

        # ---- Sélection d'algorithme ----
        self.algorithm_label = ttk.Label(self.left_frame, text=self.language["encryption"]["sections"]["algorithm"])
        self.algorithm_label.pack(anchor="w", pady=5)
        
        self.algorithm_combobox = ttk.Combobox(self.left_frame, values=["RSA", "ECC", "ElGamal"], state="readonly")
        self.algorithm_combobox.pack(pady=5, padx=10, fill="x")
        self.algorithm_combobox.bind("<<ComboboxSelected>>", self.update_keysize_options)
        
        self.keysize_label = ttk.Label(self.left_frame, text=self.language["encryption"]["select_keysize"])
        self.keysize_label.pack(anchor="w", pady=5)
        
        self.keysize_combobox = ttk.Combobox(self.left_frame, values=["1024", "2048", "4096"], state="readonly")
        self.keysize_combobox.pack(pady=5, padx=10, fill="x")
        self.keysize_combobox.config(state="disabled")

        # ---- Sélection du hachage ----
        self.hash_label = ttk.Label(self.left_frame, text=self.language["encryption"]["hash_algorithm"])
        self.hash_label.pack(anchor="w", pady=5)
        
        self.hash_var = tk.StringVar()
        self.hash_combobox = ttk.Combobox(self.left_frame, textvariable=self.hash_var, values=["SHA-256", "SHA-384", "SHA-512"], state="readonly")
        self.hash_combobox.pack(pady=5, padx=10, fill="x")

        # Changer la couleur du LabelFrame gauche (Sélection)
        self.left_frame.config(bootstyle="info")  # type: ignore
        
        # ----------------------------------------------------------------------------------
        # ---- LabelFrame de droite (Fichiers chiffrés et signés) ----
        self.right_frame = ttk.LabelFrame(self.frame, text=self.language["encryption"]["sections"]["results"], padding=10)
        self.right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        self.encrypted_label = ttk.Label(
            self.right_frame,
            text=f"{self.language["encryption"]["results"]['encrypted_files']}\n Total : 0.00 Mo", 
            font=('Arial', 12) 
        )
        self.encrypted_label.pack(anchor="w", pady=5)
        
        # ---- Liste des fichiers chiffrés avec Scrollbar ----
        self.encrypted_frame = ttk.Frame(self.right_frame)
        self.encrypted_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.encrypted_scroll = ttk.Scrollbar(self.encrypted_frame, orient="vertical")
        self.encrypted_listbox = tk.Listbox(
            self.encrypted_frame, height=8, width=60, yscrollcommand=self.encrypted_scroll.set
        )

        self.encrypted_scroll.config(command=lambda *args: self.scroll_if_needed(self.encrypted_listbox, self.encrypted_scroll, *args))

        self.encrypted_listbox.pack(side="left", fill="both", expand=True)
        self.encrypted_scroll.pack(side="right", fill="y")

        
        self.signed_label = ttk.Label(
            self.right_frame, 
            text=f"{self.language["encryption"]["results"]['signed_files']} \n Total : 0.00 Mo",
            font=('Arial', 12)
        )
        self.signed_label.pack(anchor="w", pady=5)
        
        # ---- Liste des fichiers signés avec Scrollbar ----
        self.signed_frame = ttk.Frame(self.right_frame)
        self.signed_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.signed_scroll = ttk.Scrollbar(self.signed_frame, orient="vertical")
        self.signed_listbox = tk.Listbox(
            self.signed_frame, height=8, width=60, yscrollcommand=self.signed_scroll.set
        )

        self.signed_scroll.config(command=lambda *args: self.scroll_if_needed(self.signed_listbox, self.signed_scroll, *args))

        self.signed_listbox.pack(side="left", fill="both", expand=True)
        self.signed_scroll.pack(side="right", fill="y")

        # Changer la couleur du LabelFrame droit (Résultats)
        self.right_frame.config(bootstyle="success")  # type: ignore

        # ---- Bouton principal d'action ----
        self.action_button = ttk.Button(self.frame, text=self.language["encryption"]["encrypt_sign"], command=self.encrypt_sign)
        self.action_button.grid(row=1, column=0, columnspan=2, pady=10)
        
        # ---- Ajustement des colonnes ----
        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)
        self.frame.rowconfigure(0, weight=1)  # Pour les frames principaux
        self.frame.rowconfigure(1, weight=0)  # Pour le bouton
        self.frame.rowconfigure(2, weight=0)  # Pour la barre de progression (masquée)
        self.frame.rowconfigure(3, weight=0, pad=10) # Pour le label de progression (masqué)
        self.root.update()

    
    def scroll_if_needed(self, listbox, scrollbar, *args):
        """Affiche la scrollbar seulement si le contenu dépasse la hauteur visible."""
        if listbox.size() > listbox.cget('height'):
            scrollbar.pack(side="right", fill="y")
        else:
            scrollbar.pack_forget()
        scrollbar.set(*args)
    
    def show_storage_settings(self):
        current_dir = storage_manager.base_dir
        settings_window = tk.Toplevel(self.root)
        settings_window.title(self.language["common"]["storage_configuration"])
        settings_window.geometry("500x300")
        settings_window.transient(self.root)
        settings_window.grab_set()

        ttk.Label(settings_window, text=self.language["common"]["storage_configuration"],
                font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(settings_window, text=f"{self.language['common']['current_location']}: {current_dir}",
                font=("Arial", 10)).pack(pady=5)

        btn_frame = ttk.Frame(settings_window)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text=self.language["common"]["change_folder"],
                command=lambda: self.change_storage_location(settings_window)).pack(pady=5)
        ttk.Button(btn_frame, text=self.language["common"]["view_details"],
                command=self.show_storage_details).pack(pady=5)
        ttk.Button(btn_frame, text=self.language["common"]["close"],
                command=settings_window.destroy).pack(pady=5)

    def change_storage_location(self, parent_window):
        """Change l'emplacement de stockage"""
        if choose_storage_location():
            messagebox.showinfo("Succès", f"Emplacement de stockage changé vers:\n{storage_manager.base_dir}")
            parent_window.destroy()

    def show_storage_details(self):
        info = get_storage_info()
        details_window = tk.Toplevel(self.root)
        details_window.title(self.language["common"]["storage_details"])
        details_window.geometry("600x400")
        text_widget = tk.Text(details_window, wrap="word")
        text_widget.pack(expand=True, fill="both", padx=10, pady=10)

        text_widget.insert("end", self.language["common"]["storage_details"] + "\n\n")
        text_widget.insert("end", f"{self.language['common']['base_location']} {storage_manager.base_dir}\n\n")

        for dir_name, dir_info in info.items():
            text_widget.insert("end", f"{dir_name.upper()}:\n")
            text_widget.insert("end", f"  {self.language['common']['path']}: {dir_info['path']}\n")
            text_widget.insert("end", f"  {self.language['common']['files']}: {dir_info['file_count']}\n")
            text_widget.insert("end", f"  {self.language['common']['yes'] if dir_info['exists'] else self.language['common']['no']}\n\n")

        text_widget.config(state="disabled")

    def toggle_progress(self, show=True):
        """Affiche ou masque la barre de progression"""
        if show:
            self.progress_bar.grid()  # Afficher la barre
            self.progress_label.grid()  # Afficher le label
        else:
            self.progress_bar.grid_remove()  # Masquer la barre
            self.progress_label.grid_remove()  # Masquer le label
        self.root.update()

    #Function to make update of keysize if an algorithm is selected 
    def update_keysize_options(self, event=None):
        selected_algorithm = self.algorithm_combobox.get()

        # Define keysize
        if selected_algorithm == "RSA":
            keysizes = ["1024", "2048", "3072", "4096"]
        elif selected_algorithm == "ECC":
            keysizes = ["192","224","256", "384", "521"]
        elif selected_algorithm == "ElGamal":
            keysizes = ["1024", "2048", "3072", "4096"]
        else:
            keysizes = []  # Aucun algorithme sélectionné

        # Mettre à jour la Combobox des tailles de clé
        self.keysize_combobox.config(values=keysizes)
        
        # Vider la sélection actuelle de la Combobox des tailles de clé
        self.keysize_combobox.set("")  # Effacer la valeur sélectionnée

        # Activer ou désactiver la Combobox en fonction de la disponibilité des tailles de clé
        if keysizes:
            self.keysize_combobox.config(state="readonly")  # Activer si des tailles sont disponibles
        else:
            self.keysize_combobox.config(state="disabled")  # Désactiver si aucun algorithme n'est sélectionné

    # Function to deal with selected folder
    def browse_folder(self):
        files, total_size, self.folder_path = select_folder()

        if not self.folder_path:  # Si l'utilisateur a annulé
            return

        # Vider la Listbox actuelle
        self.files_listbox.delete(0, tk.END)

        # Ajouter les fichiers à la Listbox avec des couleurs en fonction de leur taille
        for formatted_string in files:
            size_value, size_unit, file_name = extract_size_and_name(formatted_string)
            if not size_value or not size_unit or not file_name:
                print(f"Format invalide : {formatted_string}")
                continue

            # Convertir la taille en Mo
            if size_unit.lower() == "ko":
                size_mo = size_value / 1024
            elif size_unit.lower() == "mo":
                size_mo = size_value
            else:
                print(f"Unité de taille non supportée : {size_unit}")
                continue

            # Déterminer la balise en fonction de la taille
            if size_mo < 1:  # Moins de 1 Mo
                tag = "light"
            elif 1 <= size_mo < 20:  # Entre 5 Mo et 20 Mo
                tag = "medium"
            else:  # Plus de 20 Mo
                tag = "heavy"

            # Formater la chaîne pour afficher la taille et le nom du fichier
            display_string = f"{size_value} {size_unit} ==> {file_name}"

            # Ajouter le fichier à la Listbox avec la balise appropriée
            self.files_listbox.insert(tk.END, display_string)
            self.files_listbox.itemconfig(tk.END, {'fg': self.get_color_for_tag(tag)})

        # 🔹 Convertir la taille totale en Mo
        total_size_mo = total_size / (1024 * 1024)
        print(total_size_mo)

        # 🔹 Mettre à jour l'étiquette de la taille totale
        self.total_size_label.config(
            text=f"Taille totale du dossier : {total_size_mo:.2f} Mo",
            font=("Arial", 12),  # Police normale pour le texte
        )

        # Mettre en gras et en couleur uniquement la taille
        self.total_size_label.config(
            text=f"Taille totale du dossier : {total_size_mo:.2f} Mo",
            font=("Arial", 12, "bold"),  # Police en gras pour la taille
            foreground="blue"  # Couleur bleue pour la taille
        )   

        # 🔹 Forcer la mise à jour de l'interface immédiatement
        top = self.root.winfo_toplevel()
        top.update_idletasks()
        required_width = max(top.winfo_reqwidth(), 900)
        required_height = max(top.winfo_reqheight(), 700)
        center_window(top, required_width, required_height, y_offset=DOCK_OFFSET)

        if not files:
            messagebox.showwarning(
                self.language["encryption"]["dialogs"]["no_folder_title"],
                self.language["encryption"]["dialogs"]["no_folder_msg"].format(size=f"{total_size_mo:.2f} Mo")
            )
        else:
            messagebox.showinfo(
                self.language["encryption"]["dialogs"]["folder_selected_title"],
                self.language["encryption"]["dialogs"]["folder_selected_msg"].format(size=f"{total_size_mo:.2f} Mo")
            )
    
    def get_color_for_tag(self, tag):
        """
        Retourne la couleur correspondante à une balise.
        """
        colors = {
            "light": "black",  # Fichiers légers en noir
            "medium": "blue",  # Fichiers moyens en orange
            "heavy": "red",  # Fichiers lourds en rouge
        }
        return colors.get(tag, "black")  # Par défaut, noir


    def update_results_lists(self, result_data):
        """Met à jour les Listbox avec les fichiers chiffrés et signés"""
        # Vider les Listbox actuelles
        self.encrypted_listbox.delete(0, tk.END)
        self.signed_listbox.delete(0, tk.END)
        
        # Variables pour calculer les tailles totales
        total_encrypted_size = 0
        total_signed_size = 0
        
        # Ajouter les fichiers chiffrés (en excluant .DS_Store)
        for encrypted_file in result_data.get('encrypted_files', []):
            filename = os.path.basename(encrypted_file)
            if filename != '.DS_Store':  # Filtrage
                self.encrypted_listbox.insert(tk.END, filename)
                self.encrypted_listbox.itemconfig(tk.END, {'fg': 'green'})
                # Ajouter la taille du fichier chiffré
                total_encrypted_size += os.path.getsize(encrypted_file)
        
        # Ajouter les fichiers signés (en excluant .DS_Store.sig)
        for signed_file in result_data.get('signed_files', []):
            filename = os.path.basename(signed_file)
            if not filename.startswith('.DS_Store'):  # Filtrage plus large
                # display_name = os.path.splitext(filename)[0]  # Enlève .sig
                self.signed_listbox.insert(tk.END, filename)
                self.signed_listbox.itemconfig(tk.END, {'fg': 'blue'})
                # Ajouter la taille du fichier signé
                total_signed_size += os.path.getsize(signed_file)
        
        # Convertir les tailles en Mo
        encrypted_size_mo = total_encrypted_size / (1024 * 1024)
        signed_size_mo = total_signed_size / (1024 * 1024)
        
        # Mettre à jour les labels de taille
        self.encrypted_label.config(
            text=f"{self.language["encryption"]["results"]['encrypted_files']} \n Total: {self.get_size_string(total_encrypted_size)}",
            font=("Arial", 12, "bold"),  
            foreground="green"  # Couleur bleue pour la taille
        )
        self.signed_label.config(
            text=f"{self.language["encryption"]["results"]['signed_files']} \n Total: {self.get_size_string(total_signed_size)}",
            font=("Arial", 12, "bold"),  
            foreground="blue"  
        )
        
        # Forcer la mise à jour de l'interface
        top = self.root.winfo_toplevel()
        top.update_idletasks()
        required_width = max(top.winfo_reqwidth(), 900)
        required_height = max(top.winfo_reqheight(), 700)
        center_window(top, required_width, required_height, y_offset=DOCK_OFFSET)

        # self.encrypted_listbox.see(tk.END)
        # self.signed_listbox.see(tk.END)
        

    def get_size_string(self, size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} {self.language['common']['bytes']}"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.2f} {self.language['common']['kb']}"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.2f} {self.language['common']['mb']}"
        else:
            return f"{size_bytes/(1024*1024*1024):.2f} {self.language['common']['gb']}"
        

    def encrypt_sign(self):
        """
        Gère l'action de chiffrement et de signature.
        """
        # Afficher la barre de progression
        self.toggle_progress(show=True)

        # Désactiver le bouton pendant l'opération
        self.action_button.config(state="disabled")
        self.browse_button.config(state="disabled")
        self.progress_var.set(0)
        self.progress_label.config(text=self.language["encryption"]["progress"]["preparing"])
        self.root.update()  # Forcer la mise à jour de l'interface

        try:
            # Mise à jour initiale
            self.progress_var.set(5)
            self.progress_label.config(text=self.language["encryption"]["progress"]["checking_params"])
            self.root.update()
        
            if not hasattr(self, 'folder_path') or not self.folder_path:
                messagebox.showerror(self.language["encryption"]["dialogs"]["error_title"],
                         self.language["encryption"]["messages"]["no_folder"])
                return

            # Vérifier si un algorithme a été sélectionné
            selected_algorithm = self.algorithm_combobox.get()
            if not selected_algorithm:
                messagebox.showerror("Erreur", "❌ Aucun algorithme sélectionné")
                return

            # Vérifier si une taille de clé a été sélectionnée
            selected_keysize = self.keysize_combobox.get()
            if not selected_keysize:
                messagebox.showerror("Erreur", "❌ Aucune taille de clé sélectionnée")
                return

            # Vérifier si un hachage a été sélectionné
            selected_hash = self.hash_var.get()
            if not selected_hash:
                messagebox.showerror("Erreur", "❌ Aucun algorithme de hachage sélectionné")
                return

            # Nouvelle mise à jour
            self.progress_var.set(10)
            self.progress_label.config(text=self.language["encryption"]["progress"]["processing"])
            self.root.update()

            # Message d'information
            messagebox.showinfo(
                self.language["encryption"]["dialogs"]["processing_title"],
                self.language["encryption"]["messages"]["encryption_started"].format(
                    algo=selected_algorithm, keysize=selected_keysize, storage=storage_manager.base_dir
                )
            )

            try:
                # Générer les clés en utilisant le storage manager
                if selected_algorithm == "RSA":
                    private_key_path, public_key_path, generation_time = generate_rsa_keys(
                        int(selected_keysize), storage_manager
                    )
                elif selected_algorithm == "ECC":
                    curve_name = f"P-{selected_keysize}"  
                    private_key_path, public_key_path, generation_time = generate_ecc_keys(
                        curve_name, storage_manager
                    )
                elif selected_algorithm == "ElGamal":
                    private_key_path, public_key_path, generation_time = generate_elgamal_keys(
                        int(selected_keysize), storage_manager
                    )
                else:
                    raise ValueError("Algorithme non supporté.")

                # Afficher les chemins des clés
                messagebox.showinfo(
                    self.language["encryption"]["dialogs"]["keys_generated_title"],
                    self.language["encryption"]["messages"]["keys_generated"].format(
                        private=private_key_path, public=public_key_path, time=generation_time
                    )
                )

                # Traitement du dossier
                selected_algorithm = self.algorithm_combobox.get()
                selected_keysize = self.keysize_combobox.get()
                selected_hash = self.hash_var.get()

                try:
                    if selected_algorithm != "ECC":
                        selected_keysize = int(selected_keysize)
                    else:
                        selected_keysize = f"P-{selected_keysize}"  
                    
                    result = process_folder(
                        folder_path=self.folder_path,
                        algorithm=selected_algorithm,
                        key_size=selected_keysize,
                        hash_name=selected_hash,
                        storage_manager=storage_manager 
                    )
                    
                    result['asymmetric_gen_time'] = generation_time
                    generate_performance_outputs(result_data=result, algorithm=selected_algorithm, key_size=selected_keysize, operation_type="encryption_and_signature", storage_manager=storage_manager)

                    # Mise à jour finale
                    self.progress_var.set(100)
                    self.progress_label.config(text=self.language["encryption"]["progress"]["completed"])
                    self.update_results_lists(result)

                    messagebox.showinfo(
                        self.language["encryption"]["dialogs"]["success_title"],
                        self.language["encryption"]["messages"]["success"].format(
                            processed=result['processed_files'],
                            failed=result['failed_files'],
                            storage=storage_manager.base_dir
                        )
                    )

                except ValueError as e:
                    messagebox.showerror("Erreur", str(e))

            except Exception as e:
                messagebox.showerror("Erreur", f"❌ Erreur lors de la génération des clés: {e}")

        except Exception as e:
            self.progress_label.config(text=f"Erreur: {str(e)}")
            messagebox.showerror("Erreur", f"❌ Une erreur s'est produite : {e}")

        finally:
            # Réactiver les boutons quoi qu'il arrive
            self.action_button.config(state="normal")
            self.browse_button.config(state="normal")
            self.progress_label.config(text=self.language["encryption"]["progress"]["ready"])
            self.root.update()

            # Petit délai avant de masquer la barre
            self.root.after(2000, lambda: self.toggle_progress(show=False))

    
    def create_storage_menu(self):
        """Crée le menu de configuration du stockage"""
        # Frame pour les boutons de configuration en haut à droite
        config_frame = ttk.Frame(self.root)
        config_frame.pack(side="top", anchor="ne", padx=10, pady=5)
        
        # BOUTON EXPLORATION - AJOUTEZ CE BOUTON
        self.explore_button = ttk.Button(
            config_frame, 
            text="🔍 Explorer", 
            command=self.show_explorer_options,  # ← Menu contextuel
            bootstyle="outline-info", # type: ignore
            width=15
        )
        self.explore_button.pack(side="left")
    
    def show_explorer_options(self):
        """Affiche le menu contextuel intelligent avec feedback"""
        selected_algorithm = self.algorithm_combobox.get()
        selected_keysize = self.keysize_combobox.get()
        
        # Créer le menu
        menu = tk.Menu(self.root, tearoff=0)
        
        if not selected_algorithm or not selected_keysize:
            menu.add_command(label=self.language["encryption"]["explorer"]["select_algorithm_first"], state="disabled")
            menu.add_separator()
            menu.add_command(label=self.language["encryption"]["explorer"]["configuration"], command=self.show_storage_settings)
            menu.post(self.explore_button.winfo_rootx(), 
                    self.explore_button.winfo_rooty() + self.explore_button.winfo_height())
            return
        
        # Vérifier si opération effectuée
        has_operation = self.check_if_operation_done(selected_algorithm, selected_keysize)
        
        if has_operation:
            # Menu complet avec options d'exploration
            menu.add_command(
                label=self.language["encryption"]["explorer"]["open_result_dirs"], 
                command=lambda: self.explorer_manager.open_all_result_dirs(
                    "encrypt_sign", selected_algorithm, selected_keysize
                )
            )
            menu.add_command(
                label=self.language["encryption"]["explorer"]["advanced_explorer"], 
                command=lambda: self.explorer_manager.create_explorer_interface(
                    self.root, "encrypt_sign", selected_algorithm, selected_keysize
                )
            )
            menu.add_separator()
            menu.add_command(
                label=self.language["encryption"]["explorer"]["view_paths"], 
                command=lambda: messagebox.showinfo(
                    "Emplacements des résultats", 
                    self.explorer_manager.get_storage_paths_info("encrypt_sign", selected_algorithm, selected_keysize)
                )
            )
        else:
            # Menu pour opération non effectuée
            menu.add_command(label=self.language["encryption"]["explorer"]["no_operation"], state="disabled")
            menu.add_command(
                label=self.language["encryption"]["explorer"]["launch_encryption"], 
                command=lambda: self.action_button.invoke()
            )
        
        menu.add_separator()
        menu.add_command(label=self.language["encryption"]["explorer"]["storage_config"], command=self.show_storage_settings)
        
        # Afficher le menu
        menu.post(self.explore_button.winfo_rootx(), 
                self.explore_button.winfo_rooty() + self.explore_button.winfo_height())

    
    def check_if_operation_done(self, algorithm: str, key_size: str) -> bool:
        """
        Vérifie de manière robuste si une opération a été effectuée
        """
        if not algorithm or not key_size:
            return False
        
        try:
            algo_id = f"{algorithm}_{key_size}"
            
            # Liste des dossiers à vérifier avec leur contenu attendu
            check_paths = [
                (storage_manager.get_directory("encrypted_files") / algo_id, ["*.enc", "*.crypt"]),
                (storage_manager.get_directory("signed_files") / algo_id, ["*.sig"]),
                (storage_manager.get_directory("metadata") / algo_id, ["*.meta", "*.json"]),
                (storage_manager.get_directory("keys_generated") / algo_id, ["*.pem", "*.key"])
            ]
            
            for directory, patterns in check_paths:
                if directory.exists():
                    # Vérifier s'il y a des fichiers correspondant aux patterns
                    for pattern in patterns:
                        if list(directory.glob(pattern)):
                            return True
                    
                    # Vérifier si le dossier contient au moins un fichier
                    if any(directory.iterdir()):
                        return True
            
            return False
            
        except Exception as e:
            print(f"Erreur vérification opération: {e}")
            return False
    
    def explore_results(self):
        """Ouvre directement l'explorateur"""
        selected_algorithm = self.algorithm_combobox.get()
        selected_keysize = self.keysize_combobox.get()
        
        if selected_algorithm and selected_keysize:
            explorer_manager.open_all_result_dirs(
                "encrypt_sign",
                selected_algorithm, 
                selected_keysize
            )
        else:
            messagebox.showinfo("Information", "Veuillez sélectionner un algorithme et une taille de clé.")