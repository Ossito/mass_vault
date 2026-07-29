import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as ttk
from utils.lang import LANGUAGES
from utils.window_utils import center_window, DOCK_OFFSET
from utils.storage import storage_manager

class DecisionAssistantWindow:
    def __init__(self, root, change_interface, current_lang, back_button):
        self.root = root
        self.change_interface = change_interface
        self.current_lang = current_lang
        self.language = LANGUAGES[self.current_lang]
        self.back_button = back_button
        self.back_button.config(state="normal")

        # ---- Conteneur principal ----
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(expand=True, fill="both")

        # ---- Barre de progression (masquée) ----
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.frame, variable=self.progress_var, maximum=100, mode='indeterminate'
        )
        self.progress_bar.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")
        self.progress_bar.grid_remove()

        # ---- Configuration de la grille ----
        self.frame.columnconfigure(0, weight=0)
        self.frame.columnconfigure(1, weight=1)
        self.frame.rowconfigure(1, weight=1)

        # ---- Bouton d'aide (tout en haut à gauche) ----
        help_btn = ttk.Button(
            self.frame,
            text="ℹ️ Aide",
            bootstyle="outline-secondary",  # type: ignore
            command=self.show_help_dialog,
            width=6
        )
        help_btn.grid(row=0, column=0, padx=10, pady=(5, 0), sticky="w")

        # =====================================================================
        # Panneau gauche : Contraintes
        # =====================================================================
        self.left_frame = ttk.LabelFrame(
            self.frame, text="📋 Contraintes", padding=10, bootstyle="info"  # type: ignore
        )
        self.left_frame.grid(row=1, column=0, padx=(10, 5), pady=10, sticky="ns")

        # Champs de base (sauf conservation)
        fields = [
            ("volume_gb", "Volume (Go)", "3"),
            ("ram_gb", "RAM (Go)", "6"),
            ("cpu_ghz", "CPU (GHz)", "6"),
            ("cores", "Cœurs", "4"),
            ("storage_gb", "Stockage (Go)", "11"),
            ("nb_files", "Fichiers", "10"),
        ]
        self.entries = {}
        row = 0
        for key, label, default in fields:
            ttk.Label(self.left_frame, text=label, font=("Arial", 10)).grid(
                row=row, column=0, sticky="w", pady=2
            )
            var = tk.StringVar(value=default)
            entry = ttk.Entry(self.left_frame, textvariable=var, width=8)
            entry.grid(row=row, column=1, padx=5, pady=2)
            self.entries[key] = var
            row += 1

        # ---- Conservation (valeur + unité) ----
        ttk.Label(self.left_frame, text="Conservation", font=("Arial", 10)).grid(
            row=row, column=0, sticky="w", pady=2
        )
        ret_frame = ttk.Frame(self.left_frame)
        ret_frame.grid(row=row, column=1, padx=5, pady=2, sticky="w")
        self.ret_value = tk.StringVar(value="3")
        ttk.Entry(ret_frame, textvariable=self.ret_value, width=5).pack(side="left")
        self.ret_unit = tk.StringVar(value="ans")
        ttk.Combobox(ret_frame, textvariable=self.ret_unit,
                     values=["jours", "semaines", "ans"], state="readonly", width=8).pack(side="left", padx=2)
        row += 1

        # Fréquence d'accès
        ttk.Label(self.left_frame, text="Fréquence", font=("Arial", 10)).grid(
            row=row, column=0, sticky="w", pady=2
        )
        self.access_var = tk.StringVar(value="rare")
        ttk.Combobox(self.left_frame, textvariable=self.access_var,
                     values=["rare", "régulier", "fréquent"], state="readonly", width=10).grid(
            row=row, column=1, padx=5, pady=2, sticky="w")
        row += 1

        # Priorité
        ttk.Label(self.left_frame, text="Priorité", font=("Arial", 10)).grid(
            row=row, column=0, sticky="w", pady=2
        )
        self.priority_var = tk.StringVar(value="équilibré")
        ttk.Combobox(self.left_frame, textvariable=self.priority_var,
                     values=["sécurité maximale", "performance", "ressources limitées", "équilibré"],
                     state="readonly", width=13).grid(row=row, column=1, padx=5, pady=2, sticky="w")
        row += 1

        # Bouton Analyser
        self.submit_button = ttk.Button(
            self.left_frame, text="🔍 Analyser", command=self.analyze,
            bootstyle="success", width=18  # type: ignore
        )
        self.submit_button.grid(row=row, column=0, columnspan=2, pady=15)

        # =====================================================================
        # Panneau droit : Résultats (visionneuse)
        # =====================================================================
        self.right_frame = ttk.LabelFrame(
            self.frame, text="📊 Résultats et recommandation", padding=10,
            bootstyle="success"  # type: ignore
        )
        self.right_frame.grid(row=1, column=1, padx=(5, 10), pady=10, sticky="nsew")

        self.results_text = tk.Text(
            self.right_frame, wrap="word", font=("Segoe UI", 11),
            state="disabled", bg="#ffffff", fg="#2c3e50",
            padx=15, pady=15, relief="flat", borderwidth=0
        )
        self.results_scroll = ttk.Scrollbar(self.right_frame, orient="vertical", command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=self.results_scroll.set)
        self.results_text.pack(side="left", fill="both", expand=True)
        self.results_scroll.pack(side="right", fill="y")

        # Tags de style (identiques à votre dernière version)
        self.results_text.tag_config("title", font=("Segoe UI", 16, "bold"), foreground="#1a5276", spacing3=10)
        self.results_text.tag_config("subtitle", font=("Segoe UI", 13, "bold"), foreground="#2471a3", spacing3=8)
        self.results_text.tag_config("success", foreground="#27ae60")
        self.results_text.tag_config("warning", foreground="#e67e22")
        self.results_text.tag_config("highlight", background="#fef9e7")
        self.results_text.tag_config("bold", font=("Segoe UI", 11, "bold"))
        self.results_text.tag_config("table_header", font=("Courier New", 11, "bold"), foreground="#ffffff", background="#34495e")
        self.results_text.tag_config("table_row_even", background="#f8f9fa")
        self.results_text.tag_config("table_row_odd", background="#ffffff")
        self.results_text.tag_config("small", font=("Segoe UI", 9), foreground="#7f8c8d")

        self.show_welcome_message()

        top = self.root.winfo_toplevel()
        top.geometry("1000x690")
        top.update_idletasks()
        center_window(top, 1000, 690, y_offset=DOCK_OFFSET)

    # ----------------------------------------------------------------------
    # Aide
    # ----------------------------------------------------------------------
    def show_help_dialog(self):
        messagebox.showinfo("Aide - Assistant de décision",
            "Les prédictions sont extrapolées depuis des données expérimentales.\n"
            "La recommandation respecte les règles métier définies pour votre cryptosystème.\n"
            "AES‑CTR gère le volume, l'asymétrique ne protège que la clé AES.")

    # ----------------------------------------------------------------------
    # Tooltip (?) dans la visionneuse
    # ----------------------------------------------------------------------
    def show_help_tooltip(self, event):
        tooltip = tk.Toplevel(self.root)
        tooltip.wm_overrideredirect(True)
        x = event.x_root + 15
        y = event.y_root + 10
        tooltip.wm_geometry(f"+{x}+{y}")
        tk.Label(tooltip,
            text="Recommandation basée sur vos contraintes\net les performances mesurées.",
            background="lightyellow", relief="solid", borderwidth=1,
            padx=5, pady=3, font=("Arial", 9)).pack()
        self.tooltip_window = tooltip

    def hide_tooltip(self):
        if hasattr(self, 'tooltip_window'):
            self.tooltip_window.destroy()
            self.tooltip_window = None

    # ----------------------------------------------------------------------
    def show_welcome_message(self):
        self.results_text.config(state="normal")
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert("end", "🧠 Assistant de décision\n\n", "title")
        self.results_text.insert("end", "1. Remplissez vos contraintes à gauche\n")
        self.results_text.insert("end", "2. Cliquez sur 'Analyser'\n")
        self.results_text.insert("end", "3. Les résultats détaillés s'afficheront ici\n\n")
        self.results_text.insert("end", "💡 Basé sur vos données expérimentales\n")
        self.results_text.config(state="disabled")

    # ----------------------------------------------------------------------
    def analyze(self):
        # Récupération des contraintes de base
        try:
            vol = float(self.entries['volume_gb'].get())
            ram = float(self.entries['ram_gb'].get())
            cpu = float(self.entries['cpu_ghz'].get())
            cores = int(self.entries['cores'].get())
            storage = float(self.entries['storage_gb'].get())
            nb = int(self.entries['nb_files'].get())
        except ValueError:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs numériques.")
            return

        # Conservation
        try:
            ret_val = float(self.ret_value.get())
        except ValueError:
            messagebox.showerror("Erreur", "Durée de conservation invalide.")
            return
        unit = self.ret_unit.get()
        if unit == "jours":
            ret_days = ret_val
        elif unit == "semaines":
            ret_days = ret_val * 7
        else:  # ans
            ret_days = ret_val * 365

        constraints = {
            'volume_gb': vol,
            'ram_gb': ram,
            'cpu_ghz': cpu,
            'cores': cores,
            'storage_gb': storage,
            'nb_files': nb,
            'access_freq': self.access_var.get(),
            'priority': self.priority_var.get(),
            'retention_days': ret_days,
            # Pour le rapport, on garde aussi la valeur brute et l'unité
            'retention_raw': f"{ret_val} {unit}",
        }

        self.submit_button.config(state="disabled", text="Analyse...")
        self.progress_bar.grid()
        self.progress_bar.start()
        self.root.update_idletasks()

        try:
            from handlers.decision_assistant import (
                load_all_metrics, extract_performance,
                predict_performance, recommend, generate_decision_report
            )
            data = load_all_metrics(storage_manager)
            if not data:
                messagebox.showerror("Erreur", "Aucune métrique disponible.")
                return

            predictions = {}
            for label, metrics_list in data.items():
                perf = extract_performance(metrics_list)
                predictions[label] = predict_performance(perf, vol, nb)

            recommendation, reasons = recommend(constraints, predictions)
            self.display_results(constraints, predictions, recommendation, reasons)

            output_dir = storage_manager.get_directory("decision_reports", create_if_missing=True)
            report_path = generate_decision_report(constraints, predictions, recommendation, reasons, output_dir)
            self.results_text.config(state="normal")
            self.results_text.insert("end", f"\n📄 Rapport : {report_path}\n", "success")
            self.results_text.config(state="disabled")

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur : {str(e)}")
        finally:
            self.submit_button.config(state="normal", text="🔍 Analyser")
            self.progress_bar.stop()
            self.progress_bar.grid_remove()
            self.root.update_idletasks()

    # ----------------------------------------------------------------------
    def display_results(self, constraints, predictions, recommendation, reasons):
        self.results_text.config(state="normal")
        self.results_text.delete(1.0, tk.END)

        self.results_text.insert("end", "🧠  Assistant de décision\n\n", "title")

        # Contraintes
        self.results_text.insert("end", "📋  VOS CONTRAINTES\n\n", "subtitle")
        c = constraints
        self.results_text.insert("end",
            f"    Volume à chiffrer       {c['volume_gb']} Go\n"
            f"    RAM disponible          {c['ram_gb']} Go\n"
            f"    Processeur              {c['cpu_ghz']} GHz  –  {c['cores']} cœur(s)\n"
            f"    Stockage disponible     {c['storage_gb']} Go\n"
            f"    Durée de conservation   {c.get('retention_raw', str(c.get('retention_days', 0)) + ' jours')}\n"
            f"    Fréquence d’accès       {c['access_freq']}\n"
            f"    Priorité                {c['priority']}\n"
            f"    Nombre de fichiers      {c['nb_files']}\n\n"
        )

        self.results_text.insert("end", "─" * 75 + "\n\n")

        # Tableau comparatif
        self.results_text.insert("end", "📈  PRÉDICTIONS COMPARATIVES\n\n", "subtitle")
        self.results_text.insert("end", "    (estimations pour votre volume de données)\n\n", "small")

        algo_list = list(predictions.keys())
        col_data = max(14, max(len(a) for a in algo_list) + 4)
        col_name = 28

        header = f"    {'Critère':<{col_name}}"
        for a in algo_list:
            header += f" {a:>{col_data}}"
        self.results_text.insert("end", header + "\n", "table_header")
        self.results_text.insert("end", "    " + "─" * (col_name + len(algo_list) * col_data + len(algo_list)) + "\n")

        metrics = [
            ("Chiffrement (s)",      'chiffrement'),
            ("Signature (s)",        'signature'),
            ("Vérification (s)",     'verification'),
            ("Déchiffrement (s)",    'dechiffrement'),
            ("RAM max (Mo)",         'ram_max'),
            ("Overhead (%)",         'overhead'),
        ]
        for ri, (label, key) in enumerate(metrics):
            tag = "table_row_even" if ri % 2 == 0 else "table_row_odd"
            line = f"    {label:<{col_name}}"
            for a in algo_list:
                val = predictions[a][key]
                if key in ('ram_max', 'overhead'):
                    line += f" {val:>{col_data}.2f}"
                else:
                    line += f" {val:>{col_data}.1f}"
            self.results_text.insert("end", line + "\n", tag)
        self.results_text.insert("end", "\n")

        # Recommandation
        self.results_text.insert("end", "─" * 75 + "\n\n")
        self.results_text.insert("end", "🏆  RECOMMANDATION\n\n", "subtitle")
        self.results_text.insert("end", f"    ➤  Algorithme recommandé :  ", "bold")
        self.results_text.insert("end", f"{recommendation}\n\n", "success")

        # Justification
        self.results_text.insert("end", "📝  JUSTIFICATION\n\n", "subtitle")
        for i, r in enumerate(reasons, 1):
            self.results_text.insert("end", f"    {i}.  {r}\n")
        self.results_text.insert("end", "\n")

        # Compatibilité
        self.results_text.insert("end", "🔍  COMPATIBILITÉ AVEC VOTRE MATÉRIEL\n\n", "subtitle")
        best = predictions[recommendation]
        ram_ok = best['ram_max'] < constraints['ram_gb'] * 1024
        self.results_text.insert("end",
            f"    {'✅' if ram_ok else '⚠️'}  RAM estimée : {best['ram_max']:.0f} Mo  "
            f"{'(compatible)' if ram_ok else '(risque de dépassement)'}\n",
            "success" if ram_ok else "warning"
        )
        stor_need = constraints['volume_gb'] * (1 + best['overhead'] / 100)
        stor_ok = stor_need < constraints['storage_gb']
        self.results_text.insert("end",
            f"    {'✅' if stor_ok else '⚠️'}  Stockage estimé : {stor_need:.1f} Go  "
            f"{'(compatible)' if stor_ok else '(risque de dépassement)'}\n",
            "success" if stor_ok else "warning"
        )

        self.results_text.insert("end", "\n" + "─" * 75 + "\n")
        self.results_text.insert("end",
            "💡  Prédictions basées sur des données expérimentales.\n"
            "    Un rapport PDF détaillé a été généré.\n\n",
            "highlight"
        )
        # self.results_text.insert("end",
        #     "ℹ️  AES‑CTR gère le volume des fichiers ; l’algorithme asymétrique\n"
        #     "    ne protège que la clé AES (32 octets).\n",
        #     "small"
        # )

        self.results_text.config(state="disabled")
        self.results_text.see(1.0)