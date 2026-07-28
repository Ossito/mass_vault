import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from utils.lang import LANGUAGES
from interfaces.encrypt_sign_window import EncryptSignWindow
from interfaces.decrypt_window import DecryptWindow
from interfaces.verify_window import VerificationSignatureWindow
import ttkbootstrap as ttk
import os
import subprocess
import sys

from utils.window_utils import center_window, DOCK_OFFSET
from utils.storage import storage_manager, choose_storage_location, get_storage_location, get_storage_info

class HomeWindow:
    def __init__(self, root):
        self.root = root
        self.current_lang = "fr"
        self.language = LANGUAGES[self.current_lang]
        self.root.geometry("1000x690")
        center_window(self.root, 1000, 690, y_offset=DOCK_OFFSET)

        # ---- Cadre principal ---- 
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill="both", expand=True)

        # ---- Barre supérieure ----
        self.top_frame = ttk.Frame(self.main_frame)
        self.top_frame.pack(fill="x", pady=5)

        self.language_var = tk.StringVar(value="FR")
        self.language_selector = ttk.Combobox(
            self.top_frame, textvariable=self.language_var,
            values=["FR", "EN"], state="readonly", width=5
        )
        self.language_selector.pack(side="left", padx=10)
        self.language_selector.bind("<<ComboboxSelected>>", self.change_language)

        self.folder_button = ttk.Button(
            self.top_frame,
            text="📁 " + self.language["common"].get("change_folder", "Changer dossier"),
            command=self.change_storage_location,
            bootstyle="outline-info",  # type: ignore
            width=18
        )
        self.folder_button.pack(side="left", padx=10)

        self.location_label = ttk.Label(
            self.top_frame,
            text="",
            font=("Arial", 8),
            foreground="gray"
        )
        self.location_label.pack(side="left", padx=10)

        # --- Bouton Assistant de décision (en haut à droite) ---
        self.assistant_button = ttk.Button(
            self.top_frame,
            text="🧠 Assistant de décision",
            command=self.open_decision_assistant,
            bootstyle="outline-warning",  # type: ignore
            width=22
        )
        self.assistant_button.pack(side="right", padx=8)

        # --- Bouton Retour (placé après pour être le plus à droite) ---
        self.back_button = ttk.Button(
            self.top_frame, text=self.language["common"]["back_button"],
            command=self.go_back, state="disabled"
        )
        self.back_button.pack(side="right", padx=10)

        # ---- Contenu dynamique ----
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(expand=True)

        self.welcome_label = ttk.Label(
            self.content_frame, text=self.language["home"]["welcome_text"],
            font=("Arial", 16, "bold")
        )
        self.welcome_label.pack(pady=10)

        self.call_to_action_label = ttk.Label(
            self.content_frame, text=self.language["home"]["action_text"],
            font=("Arial", 12)
        )
        self.call_to_action_label.pack(pady=5)

        self.buttons_frame = ttk.Frame(self.content_frame)
        self.buttons_frame.pack(pady=20)

        self.row1_frame = ttk.Frame(self.buttons_frame)
        self.row1_frame.pack(pady=5)

        self.encryption_button = ttk.Button(
            self.row1_frame, text=self.language["home"]["encryption_interface"],
            command=self.open_encryption, width=25
        )
        self.encryption_button.pack(side="left", padx=10)

        self.verification_button = ttk.Button(
            self.row1_frame, text=self.language["home"]["verification_interface"],
            command=self.open_verification, width=25
        )
        self.verification_button.pack(side="left", padx=10)

        self.row2_frame = ttk.Frame(self.buttons_frame)
        self.row2_frame.pack(pady=15)

        self.decryption_button = ttk.Button(
            self.row2_frame, text=self.language["home"]["decryption_interface"],
            command=self.open_decryption, width=25
        )
        self.decryption_button.pack()

        self.quit_button = ttk.Button(
            self.content_frame, text=self.language["common"]["quit"],
            command=self.root.quit, width=15
        )
        self.quit_button.pack(pady=10)

        self.copyright_label = ttk.Label(
            self.root, text=self.language["common"]["copyright"],
            font=("Arial", 10)
        )
        self.copyright_label.pack(side="bottom", pady=5)

        self.update_location_display()

    # ----------------------------------------------------------------------
    # Méthodes existantes (change_language, update_ui_texts, go_back, etc.)
    # ----------------------------------------------------------------------
    def change_language(self, event=None):
        selected = self.language_selector.get()
        self.current_lang = "en" if selected == "EN" else "fr"
        self.language = LANGUAGES[self.current_lang]
        self.update_ui_texts()

    def update_ui_texts(self):
        self.root.title(f"MASSS VAULT - {self.language['common']['home']}")
        self.back_button.config(text=self.language["common"]["back_button"])
        self.folder_button.config(text="📁 " + self.language["common"].get("change_folder", "Changer dossier"))
        self.welcome_label.config(text=self.language["home"]["welcome_text"])
        self.call_to_action_label.config(text=self.language["home"]["action_text"])
        self.encryption_button.config(text=self.language["home"]["encryption_interface"])
        self.verification_button.config(text=self.language["home"]["verification_interface"])
        self.decryption_button.config(text=self.language["home"]["decryption_interface"])
        self.quit_button.config(text=self.language["common"]["quit"])
        self.copyright_label.config(text=self.language["common"]["copyright"])
        self.update_location_display()

    def go_back(self):
        self.back_button.config(state="disabled")
        self.show_home_content()
        self.root.title(f"MASSS VAULT - {self.language['home']['home_title']}")

    def open_encryption(self):
        self._switch_to_interface("encryption", EncryptSignWindow)

    def open_verification(self):
        self._switch_to_interface("verification", VerificationSignatureWindow)

    def open_decryption(self):
        self._switch_to_interface("decryption", DecryptWindow)

    def _switch_to_interface(self, key, WindowClass):
        for widget in self.content_frame.winfo_children():
            widget.pack_forget()  # type: ignore
        
        title = self.language.get(key, {}).get(f"{key}_title", key.capitalize())
        self.root.title(f"MASSS VAULT - {title}")
        WindowClass(self.content_frame, self.language, self.current_lang, self.back_button)

        required_height = 600
        current_width = self.root.winfo_width()
        current_height = self.root.winfo_height()
        new_height = max(required_height, current_height)
        center_window(self.root, current_width, new_height, y_offset=DOCK_OFFSET)
        self.back_button.config(state="normal")

    def show_home_content(self):
        for widget in self.content_frame.winfo_children():
            widget.pack_forget()  # type: ignore
        self.welcome_label.pack(pady=10)
        self.call_to_action_label.pack(pady=5)
        self.buttons_frame.pack(pady=20)
        self.quit_button.pack(pady=10)

    def change_storage_location(self):
        try:
            success = choose_storage_location()
            if success:
                self.update_location_display()
                new_location = get_storage_location()
                messagebox.showinfo(
                    "Succès",
                    f"Emplacement de stockage changé avec succès !\n\n"
                    f"Nouvel emplacement :\n{new_location}\n\n"
                    f"Tous les nouveaux fichiers seront sauvegardés ici."
                )
            else:
                current_location = get_storage_location()
                messagebox.showinfo(
                    "Information",
                    f"Emplacement actuel :\n{current_location}\n\n"
                    f"Aucun changement effectué."
                )
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de changer l'emplacement :\n{str(e)}")

    def update_location_display(self):
        try:
            current_location = get_storage_location()
            if len(current_location) > 40:
                display_path = "..." + current_location[-37:]
            else:
                display_path = current_location
            storage_info = get_storage_info()
            total_files = sum(int(info.get('file_count', 0)) for info in storage_info.values())
            total_size_mb = sum(float(info.get('total_size_mb', 0.0)) for info in storage_info.values())
            self.location_label.config(
                text=f"📊 {total_files} fichiers ({total_size_mb:.1f} MB) | 📁 {display_path}"
            )
            self.location_label.bind(
                "<Enter>",
                lambda e: self.show_tooltip(f"Emplacement complet:\n{current_location}")
            )
            self.location_label.bind("<Leave>", lambda e: self.hide_tooltip())
        except Exception as e:
            self.location_label.config(text="❌ Erreur chargement emplacement")

    # ----------------------------------------------------------------------
    # Assistant de décision
    # ----------------------------------------------------------------------
    def open_decision_assistant(self):
        from interfaces.decision_window import DecisionAssistantWindow
        self._switch_to_interface("decision", DecisionAssistantWindow)

    # ----------------------------------------------------------------------
    # Tooltip et autres
    # ----------------------------------------------------------------------
    def show_tooltip(self, text):
        self.tooltip = tk.Toplevel(self.root)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry("+%d+%d" % (self.root.winfo_pointerx()+10, self.root.winfo_pointery()+10))
        label = ttk.Label(self.tooltip, text=text, background="lightyellow",
                          relief="solid", borderwidth=1, padding=5, font=("Arial", 8))
        label.pack()

    def hide_tooltip(self):
        if hasattr(self, 'tooltip'):
            self.tooltip.destroy()

    def show_storage_info(self):
        try:
            from utils.storage import show_storage_details
            show_storage_details()
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'afficher les détails : {str(e)}")