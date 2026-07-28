import json
import datetime
import numpy as np
from pathlib import Path
from fpdf import FPDF
from utils.storage import storage_manager

# ----------------------------------------------------------------------
# 1. Chargement des métriques
# ----------------------------------------------------------------------
def load_all_metrics(storage_manager):
    """Charge tous les JSON de metrics_graphs/ et regroupe par algo-taille."""
    metrics_dir = storage_manager.get_metrics_graphs_dir()
    data = {}
    for json_file in metrics_dir.rglob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                content = json.load(f)
            if not content.get('success', False):
                continue
            algo = content['metadata']['algorithm']
            key_size = str(content['metadata']['key_size'])
            if algo == 'ECC':
                key_size = key_size.replace('P-', '')
            label = f"{algo}-{key_size}"
            if label not in data:
                data[label] = []
            data[label].append(content)
        except Exception:
            pass
    return data

# ----------------------------------------------------------------------
# 2. Extraction des performances moyennes par groupe
# ----------------------------------------------------------------------
def extract_performance(metrics_list):
    """
    Calcule les indicateurs moyens et, si disponible, une régression linéaire
    (temps = a * taille + b) à partir des données de calibration.
    """
    nb_files_avg = np.mean([m['files_processed'] for m in metrics_list])
    key_gen = np.mean([m['timings'].get('key_generation', 0) for m in metrics_list])
    signing = np.mean([m['timings'].get('signature', 0) for m in metrics_list])
    verification = np.mean([m['timings'].get('verification', 0) for m in metrics_list])
    decryption = np.mean([m['timings'].get('decapsulation', 0) for m in metrics_list])
    cpu_mean = np.mean([m['resources'].get('cpu_mean', 0) for m in metrics_list])
    ram_max = np.max([m['resources'].get('ram_max', 0) for m in metrics_list])
    overhead = np.mean([m.get('overhead', 0) for m in metrics_list])

    # --- Régression linéaire à partir des données de calibration ---
    all_sizes = []
    all_times = []
    for m in metrics_list:
        cal = m.get('calibration')
        if cal:
            all_sizes.extend(cal['file_sizes_bytes'])
            all_times.extend(cal['encryption_times_sec'])

    if len(all_sizes) >= 3:
        coeffs = np.polyfit(all_sizes, all_times, 1)  # [a, b] : temps = a * taille + b
        slope = coeffs[0]      # secondes par octet
        intercept = coeffs[1]  # secondes (overhead fixe par fichier)
    else:
        # Fallback sur l'ancienne méthode (débit global)
        total_size = np.mean([m.get('total_size', 0) for m in metrics_list])
        encryption = np.mean([m['timings'].get('encapsulation', 0) for m in metrics_list])
        if total_size and encryption and nb_files_avg:
            throughput = total_size / (encryption * nb_files_avg)
            slope = 1.0 / throughput if throughput else 0
            intercept = 0
        else:
            slope = 0
            intercept = encryption / nb_files_avg if nb_files_avg else 0

    return {
        'key_gen': key_gen,
        'signing': signing,
        'verification': verification,
        'decryption': decryption,
        'cpu_mean': cpu_mean,
        'ram_max': ram_max,
        'overhead': overhead,
        'slope': slope,
        'intercept': intercept,
        'avg_file_count': nb_files_avg
    }

# ----------------------------------------------------------------------
# 3. Prédiction pour un scénario donné
# ----------------------------------------------------------------------
def predict_performance(perf, volume_gb, nb_files):
    volume_bytes = volume_gb * 1024**3
    avg_file_size = volume_bytes / nb_files if nb_files else 0

    # Temps de chiffrement AES‑CTR par fichier (inclut l'overhead fixe)
    time_per_file = perf['slope'] * avg_file_size + perf['intercept']
    encrypt_time = nb_files * time_per_file

    total_encrypt = encrypt_time + perf['key_gen'] * nb_files
    total_sign = encrypt_time + perf['signing'] * nb_files
    total_verify = perf['verification'] * nb_files

    # Déchiffrement AES‑CTR (pas d'overhead fixe car c'est la même opération)
    decrypt_aes_time = nb_files * (perf['slope'] * avg_file_size)  # même débit
    total_decrypt = decrypt_aes_time + perf['decryption'] * nb_files

    return {
        'chiffrement': total_encrypt,
        'signature': total_sign,
        'verification': total_verify,
        'dechiffrement': total_decrypt,
        'ram_max': perf['ram_max'],
        'overhead': perf['overhead']
    }  

# ----------------------------------------------------------------------
# 4. Logique de recommandation
# ----------------------------------------------------------------------
def recommend(constraints, predictions):
    """
    constraints : dict avec ram_gb, cpu_ghz, storage_gb, retention_years, access_freq
    predictions : dict { algo_label: prediction_dict }
    Retourne le label recommandé et une justification.
    """
    # Règles
    best_label = None
    reasons = []
    # Si RAM très limitée (<4 Go) et CPU modeste, ECC
    if constraints['ram_gb'] < 4 and constraints['cpu_ghz'] < 4:
        for label in predictions:
            if 'ECC' in label:
                best_label = label
                reasons.append("RAM et CPU limités → ECC recommandé")
                break
    # Si durée de conservation > 5 ans, RSA
    if constraints['retention_years'] > 5:
        for label in predictions:
            if 'RSA' in label:
                best_label = label
                reasons.append("Conservation longue durée → RSA recommandé")
                break
    # Si accès fréquent, ECC (déchiffrement plus rapide)
    if constraints['access_freq'] == 'frequent':
        for label in predictions:
            if 'ECC' in label:
                best_label = label
                reasons.append("Accès fréquent → ECC (déchiffrement rapide)")
                break
    # Si stockage limité, ECC (overhead faible)
    if constraints['storage_gb'] < 2 * constraints['volume_gb']:
        for label in predictions:
            if 'ECC' in label:
                best_label = label
                reasons.append("Stockage très limité → ECC (overhead minimal)")
                break
    # Par défaut, prendre le meilleur compromis (ECC)
    if not best_label:
        for label in predictions:
            if 'ECC' in label:
                best_label = label
                reasons.append("Compromis général → ECC recommandé")
                break
    # Si aucun ECC, prendre le premier
    if not best_label:
        best_label = list(predictions.keys())[0]
        reasons.append("Aucun ECC disponible, choix par défaut")
    return best_label, reasons

# ----------------------------------------------------------------------
# 5. Génération du rapport PDF
# ----------------------------------------------------------------------
def generate_decision_report(constraints, predictions, recommendation, reasons, output_dir):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path(output_dir) / f"decision_{timestamp}"
    report_dir.mkdir(parents=True, exist_ok=True)

    # ---------- Classe PDF avec support Unicode ----------
    class PDF(FPDF):
        def __init__(self):
            super().__init__()
            self.font_dir = Path(__file__).parent.parent / "fonts"  # dossier fonts à la racine
            self.unicode_font = None
            self.setup_fonts()

        def setup_fonts(self):
            # Essaie d’ajouter une police Unicode
            for font_name, file_name in [('DejaVu', 'DejaVuSans.ttf'),
                                         ('DejaVu', 'DejaVuSansCondensed.ttf')]:
                font_path = self.font_dir / file_name
                if font_path.exists():
                    try:
                        self.add_font(font_name, '', str(font_path), uni=True)
                        self.unicode_font = font_name
                        return
                    except:
                        pass
            # Fallback : on utilisera helvetica et on remplacera les caractères Unicode

        def write_text(self, txt):
            if self.unicode_font:
                self.set_font(self.unicode_font, '', 12)
                self.cell(0, 6, txt, ln=1)
            else:
                self.set_font("helvetica", '', 12)
                safe = txt.replace('→', '->').replace('•', '-')
                self.cell(0, 6, safe, ln=1)

        def write_title(self, txt, size=16):
            if self.unicode_font:
                self.set_font(self.unicode_font, 'B', size)
            else:
                self.set_font("helvetica", 'B', size)
            self.cell(0, 10, txt, ln=1, align="C")

    # ----------------------------------------------------------------
    pdf = PDF()
    pdf.add_page()
    pdf.write_title("RAPPORT DE DÉCISION CRYPTOGRAPHIQUE", 16)
    pdf.ln(10)
    pdf.set_font("helvetica", '', 12)
    pdf.cell(0, 6, f"Généré le {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}", ln=1, align="C")
    pdf.ln(10)

    # Contraintes
    pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 8, "CONTRAINTES UTILISATEUR", ln=1)
    pdf.set_font("helvetica", '', 12)
    for k, v in constraints.items():
        pdf.cell(0, 6, f"- {k} : {v}", ln=1)
    pdf.ln(10)

    # Tableau des prédictions
    pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 8, "PRÉDICTIONS", ln=1)
    pdf.ln(5)
    # En-têtes
    pdf.set_font("helvetica", 'B', 10)
    cols = ["Critère"] + list(predictions.keys())
    col_widths = [40] + [30] * len(predictions)
    for i, col in enumerate(cols):
        pdf.cell(col_widths[i], 7, col, border=1, align='C')
    pdf.ln()
    # Lignes
    metrics = [
        ("Chiffrement (s)", 'chiffrement'),
        ("Signature (s)", 'signature'),
        ("Vérification (s)", 'verification'),
        ("Déchiffrement (s)", 'dechiffrement'),
        ("RAM max (Mo)", 'ram_max'),
        ("Overhead (%)", 'overhead'),
    ]
    pdf.set_font("helvetica", '', 10)
    for label, key in metrics:
        pdf.cell(col_widths[0], 7, label, border=1)
        for algo in predictions:
            val = predictions[algo][key]
            if key in ('ram_max', 'overhead'):
                pdf.cell(col_widths[1], 7, f"{val:.2f}", border=1, align='C')
            else:
                pdf.cell(col_widths[1], 7, f"{val:.1f}", border=1, align='C')
        pdf.ln()
    pdf.ln(10)

    # Recommandation
    pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 8, "RECOMMANDATION", ln=1)
    pdf.set_font("helvetica", '', 12)
    pdf.cell(0, 6, f"Algorithme recommandé : {recommendation}", ln=1)
    pdf.ln(5)
    pdf.set_font("helvetica", 'B', 12)
    pdf.cell(0, 6, "Justification :", ln=1)
    pdf.set_font("helvetica", '', 12)
    for r in reasons:
        # Remplacer les flèches si la police Unicode n'est pas disponible
        safe_r = r if pdf.unicode_font else r.replace('→', '->')
        pdf.cell(0, 6, f"- {safe_r}", ln=1)

    pdf.output(str(report_dir / "rapport_decision.pdf"))
    return str(report_dir)