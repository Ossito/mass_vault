import os
import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as ttk
from utils.lang import LANGUAGES
from utils.window_utils import center_window, DOCK_OFFSET
from utils.storage import storage_manager
from utils.explorer_manager import explorer_manager
from handlers.decrypt import perform_decryption


class DecryptWindow:
    def __init__(self, root, change_interface, current_lang, back_button):
        self.root = root
        self.change_interface = change_interface
        self.current_lang = current_lang
        self.language = LANGUAGES[self.current_lang]
        self.last_results = None

        self.back_button = back_button
        self.back_button.config(state="normal")

        # ---- Bouton Explorer en haut à droite ----
        self.create_explorer_menu()

        # ---- Conteneur principal ----
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(expand=True, fill="both")

        # ---- Configuration des colonnes ----
        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=2)
        self.frame.rowconfigure(0, weight=1)

        # ---- Left Frame (Algorithm selection) ----
        self.left_frame = ttk.LabelFrame(
            self.frame,
            text=self.language["decryption"]["decryption_section"],
            padding=10,
            bootstyle="info"  # type: ignore
        )
        self.left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        ttk.Label(self.left_frame, text=self.language["decryption"]["select_algorithm"]).pack(anchor="w", pady=5)
        self.algorithm_combobox = ttk.Combobox(self.left_frame, values=["RSA", "ECC", "ElGamal"], state="readonly")
        self.algorithm_combobox.pack(pady=5, padx=10, fill="x")
        self.algorithm_combobox.bind("<<ComboboxSelected>>", self.update_keysize_options)

        ttk.Label(self.left_frame, text=self.language["decryption"]["select_keysize"]).pack(anchor="w", pady=5)
        self.keysize_combobox = ttk.Combobox(self.left_frame, state="readonly")
        self.keysize_combobox.pack(pady=5, padx=10, fill="x")
        self.keysize_combobox.config(state="disabled")
        self.keysize_combobox.bind("<<ComboboxSelected>>", self.update_encrypted_files_list)

        # Encrypted files list
        self.encrypted_files_label = ttk.Label(
            self.left_frame,
            text=f"{self.language['decryption']['sections']['encrypted_files']} \n Total : 0",
            font=('Arial', 12)
        )
        self.encrypted_files_label.pack(anchor="w", pady=5)

        self.encrypted_frame = ttk.Frame(self.left_frame)
        self.encrypted_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.encrypted_scroll = ttk.Scrollbar(self.encrypted_frame, orient="vertical")
        self.encrypted_listbox = tk.Listbox(
            self.encrypted_frame, height=8, width=40, yscrollcommand=self.encrypted_scroll.set
        )
        self.encrypted_scroll.config(command=self.encrypted_listbox.yview)
        self.encrypted_listbox.pack(side="left", fill="both", expand=True)
        self.encrypted_scroll.pack(side="right", fill="y")

        # ---- Right Frame (Decrypted files) ----
        self.right_frame = ttk.LabelFrame(
            self.frame,
            text=self.language["decryption"]["decryption_operation"],
            padding=10,
            bootstyle="success"  # type: ignore
        )
        self.right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.decrypted_label = ttk.Label(
            self.right_frame,
            text=f"{self.language['decryption']['results']['decrypted_files']}\n Total: 0",
            font=('Arial', 12)
        )
        self.decrypted_label.pack(anchor="w", pady=5)

        self.decrypted_frame = ttk.Frame(self.right_frame)
        self.decrypted_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.decrypted_scroll = ttk.Scrollbar(self.decrypted_frame, orient="vertical")
        self.decrypted_listbox = tk.Listbox(
            self.decrypted_frame, height=8, width=40, yscrollcommand=self.decrypted_scroll.set
        )
        self.decrypted_scroll.config(command=self.decrypted_listbox.yview)
        self.decrypted_listbox.pack(side="left", fill="both", expand=True)
        self.decrypted_scroll.pack(side="right", fill="y")

        # ---- Decrypt button ----
        self.action_button = ttk.Button(
            self.frame,
            text=f"🔑 {self.language['decryption']['decrypt']}",
            command=self.decrypt,
            bootstyle="info"  # type: ignore
        )
        self.action_button.grid(row=1, column=0, columnspan=2, pady=10)

        # ---- Centrage ----
        top = self.root.winfo_toplevel()
        top.update_idletasks()
        required_width = max(top.winfo_reqwidth(), 950)
        required_height = max(top.winfo_reqheight(), 650)
        center_window(top, required_width, required_height, y_offset=DOCK_OFFSET)

    # ----------------------------------------------------------------------
    # Bouton Explorer
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
                menu.add_command(label="⏳ Aucun déchiffrement effectué", state="disabled")
                menu.add_command(
                    label="🚀 Lancer le déchiffrement",
                    command=lambda: self.action_button.invoke()
                )

        menu.add_separator()
        menu.add_command(label="⚙️ Configuration stockage", command=self.show_storage_settings)
        menu.post(self.explore_button.winfo_rootx(),
                  self.explore_button.winfo_rooty() + self.explore_button.winfo_height())

    def open_advanced_explorer(self, algorithm, key_size):
        from utils.explorer_manager import explorer_manager
        if explorer_manager is None:
            messagebox.showerror("Erreur", "L'explorateur n'est pas initialisé.")
            return
        if algorithm == "ECC":
            key_size = f"P-{key_size}"
        explorer_manager.create_explorer_interface(
            self.root, "decryption", algorithm, key_size
        )

    def show_storage_settings(self):
        from utils.storage import show_storage_details
        show_storage_details()

    # ----------------------------------------------------------------------
    # Méthodes de gestion de l'interface
    # ----------------------------------------------------------------------
    def update_keysize_options(self, event=None):
        algorithm = self.algorithm_combobox.get()
        sizes = {
            "RSA": ["1024", "2048", "3072", "4096"],
            "ECC": ["192", "224", "256", "384", "521"],
            "ElGamal": ["1024", "2048", "3072", "4096"]
        }.get(algorithm, [])
        self.keysize_combobox.config(values=sizes, state="readonly" if sizes else "disabled")
        self.keysize_combobox.set('')
        self.encrypted_listbox.delete(0, tk.END)

    def update_encrypted_files_list(self, event=None):
        algorithm = self.algorithm_combobox.get()
        keysize = self.keysize_combobox.get()
        if not algorithm or not keysize:
            return

        algo_id = f"{algorithm}_{keysize}"
        encrypted_dir = storage_manager.get_directory("encrypted_files") / algo_id

        self.encrypted_listbox.delete(0, tk.END)
        file_count = 0
        if encrypted_dir.exists():
            for f in sorted(encrypted_dir.iterdir()):
                if f.is_file() and not f.name.startswith('.'):
                    self.encrypted_listbox.insert(tk.END, f.name)
                    file_count += 1

        self.encrypted_files_label.config(
            text=f"{self.language['decryption']['sections']['encrypted_files']} \n Total: {file_count}",
            font=('Arial', 12, 'bold'), foreground="blue"
        )

    # ----------------------------------------------------------------------
    # Déchiffrement
    # ----------------------------------------------------------------------
    def decrypt(self):
        algorithm = self.algorithm_combobox.get()
        keysize = self.keysize_combobox.get()
        if not algorithm or not keysize:
            messagebox.showwarning(
                self.language["common"]["warning"],
                self.language["decryption"]["messages"]["no_algorithm"]
            )
            return

      
        proc_keysize = keysize

        self.action_button.config(state="disabled", text="Déchiffrement en cours...")
        self.explore_button.config(state="disabled")
        self.root.update_idletasks()

        try:
            algo_id = f"{algorithm}_{proc_keysize}"
            encrypted_dir = storage_manager.get_directory("encrypted_files") / algo_id
            if not encrypted_dir.exists():
                messagebox.showerror(
                    self.language["common"]["error"],
                    self.language["decryption"]["messages"]["no_encrypted_files"]
                )
                return

            result = perform_decryption(str(encrypted_dir), algorithm, proc_keysize, storage_manager)
            self.last_results = result
            self.update_decrypted_files(result)

            if result.get('success'):
                messagebox.showinfo(
                    self.language["decryption"]["dialogs"]["success_title"],
                    self.language["decryption"]["messages"]["success"].format(
                        processed=result['processed_files'],
                        failed=result['failed_files']
                    )
                )
            else:
                messagebox.showwarning(
                    self.language["decryption"]["dialogs"]["warning_title"],
                    self.language["decryption"]["messages"]["warning"].format(
                        processed=result['processed_files'],
                        failed=result['failed_files']
                    )
                )
        except Exception as e:
            messagebox.showerror(
                self.language["common"]["error"],
                f"{self.language['decryption']['messages']['error_processing']}: {str(e)}"
            )
        finally:
            self.action_button.config(state="normal", text=f"🔑 {self.language['decryption']['decrypt']}")
            self.explore_button.config(state="normal")
            self.root.update_idletasks()

    def update_decrypted_files(self, result):
        self.decrypted_listbox.delete(0, tk.END)
        for filepath in result.get('decrypted_files', []):
            filename = os.path.basename(filepath)
            self.decrypted_listbox.insert(tk.END, f"📄 {filename}")
            self.decrypted_listbox.itemconfig(tk.END, {'fg': 'green'})

        count = len(result.get('decrypted_files', []))
        self.decrypted_label.config(
            text=f"{self.language['decryption']['results']['decrypted_files']}\n Total: {count}",
            font=('Arial', 12, 'bold'),
            foreground="green"
        )