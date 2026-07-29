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
    nb_files_avg = np.mean([m['files_processed'] for m in metrics_list])
    key_gen = np.mean([m['timings'].get('key_generation', 0) for m in metrics_list])
    signing = np.mean([m['timings'].get('signature', 0) for m in metrics_list])
    verification = np.mean([m['timings'].get('verification', 0) for m in metrics_list])
    decryption = np.mean([m['timings'].get('decapsulation', 0) for m in metrics_list])
    cpu_mean = np.mean([m['resources'].get('cpu_mean', 0) for m in metrics_list])
    ram_max = np.max([m['resources'].get('ram_max', 0) for m in metrics_list])
    overhead = np.mean([m.get('overhead', 0) for m in metrics_list])

    # Données de calibration pour régression
    all_sizes = []
    all_times = []
    for m in metrics_list:
        cal = m.get('calibration')
        if cal:
            all_sizes.extend(cal['file_sizes_bytes'])
            all_times.extend(cal['encryption_times_sec'])

    if len(all_sizes) >= 3:
        coeffs = np.polyfit(all_sizes, all_times, 1)   # [pente, intercept]
        slope = coeffs[0]
        intercept = coeffs[1]
    else:
        # Fallback débit global
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
    volume_bytes = volume_gb * 1024 ** 3
    avg_file_size = volume_bytes / nb_files if nb_files else 0

    # Temps de chiffrement AES‑CTR par fichier (inclut l'overhead fixe)
    time_per_file = perf['slope'] * avg_file_size + perf['intercept']
    encrypt_time = nb_files * time_per_file

    total_encrypt = encrypt_time + perf['key_gen'] * nb_files
    total_sign = encrypt_time + perf['signing'] * nb_files
    total_verify = perf['verification'] * nb_files

    # Déchiffrement AES‑CTR – même modèle (overhead fixe existe aussi)
    decrypt_time_per_file = perf['slope'] * avg_file_size + perf['intercept']
    decrypt_aes_time = nb_files * decrypt_time_per_file
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
# 4. Logique de recommandation (complète et dynamique)
# ----------------------------------------------------------------------
def recommend(constraints, predictions):
    """
    Règles métier strictes :
    - ECC si RAM < 6 Go OU accès régulier/fréquent.
    - RSA si RAM >= 6 Go ET accès rare.
    - Si aucun ECC ou RSA n'est disponible, prendre le premier algorithme.
    """
    ram_gb = constraints.get('ram_gb', 8)
    access_freq = constraints.get('access_freq', 'rare')

    # Identifier les meilleurs candidats ECC et RSA (par performance brute)
    ecc_labels = [lbl for lbl in predictions if lbl.startswith('ECC')]
    rsa_labels = [lbl for lbl in predictions if lbl.startswith('RSA')]

    def best_of(labels):
        if not labels:
            return None
        return min(labels, key=lambda l: predictions[l]['chiffrement'] + predictions[l]['dechiffrement'])

    best_ecc = best_of(ecc_labels)
    best_rsa = best_of(rsa_labels)

    # Appliquer les règles
    if ram_gb < 6 or access_freq in ('régulier', 'frequent'):
        # ECC prioritaire
        if best_ecc:
            label = best_ecc
            reasons = [
                "ECC est recommandé pour les environnements avec ressources limitées (RAM < 6 Go) ou accès régulier/fréquent.",
                "ECC offre de meilleures performances et une empreinte mémoire réduite."
            ]
        elif best_rsa:
            label = best_rsa
            reasons = ["ECC non disponible, RSA est le seul choix."]
        else:
            label = list(predictions.keys())[0]
            reasons = ["Aucun algorithme ECC ou RSA trouvé, choix par défaut."]
    else:
        # RAM >= 6 Go et accès rare → RSA
        if best_rsa:
            label = best_rsa
            reasons = [
                "Avec une RAM suffisante (>= 6 Go) et un accès rare, RSA est recommandé.",
                "RSA offre une sécurité éprouvée et une bonne stabilité."
            ]
        elif best_ecc:
            label = best_ecc
            reasons = ["RSA non disponible, ECC est le seul choix."]
        else:
            label = list(predictions.keys())[0]
            reasons = ["Aucun algorithme RSA ou ECC trouvé, choix par défaut."]

    # Ajouter des informations sur le candidat retenu
    pred = predictions[label]
    reasons += [
        f"Chiffrement estimé : {pred['chiffrement']:.1f} s",
        f"Déchiffrement estimé : {pred['dechiffrement']:.1f} s",
        f"RAM maximale estimée : {pred['ram_max']:.0f} Mo",
        f"Overhead de stockage : {pred['overhead']:.2f} %"
    ]

    return label, reasons


# ----------------------------------------------------------------------
# 5. Génération du rapport PDF (sans erreurs de police)
# ----------------------------------------------------------------------
def generate_decision_report(constraints, predictions, recommendation, reasons, output_dir):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path(output_dir) / f"decision_{timestamp}"
    report_dir.mkdir(parents=True, exist_ok=True)

    class PDF(FPDF):
        def __init__(self):
            super().__init__()
            self.font_dir = Path(__file__).parent.parent / "fonts"
            self.unicode_font = None
            self.setup_fonts()

        def setup_fonts(self):
            for font_name, file_name in [('DejaVu', 'DejaVuSans.ttf'),
                                         ('DejaVu', 'DejaVuSansCondensed.ttf')]:
                font_path = self.font_dir / file_name
                if font_path.exists():
                    try:
                        self.add_font(font_name, '', str(font_path), uni=True) # type: ignore
                        self.unicode_font = font_name
                        return
                    except:
                        pass

        def safe_text(self, txt):
            """Remplace tous les caractères Unicode problématiques par des équivalents ASCII."""
            if self.unicode_font:
                return txt
            replacements = {
                '–': '-', '—': '-', '’': "'", '‘': "'",
                '“': '"', '”': '"', '…': '...', '•': '-', '→': '->',
                '≤': '<=', '≥': '>=', '±': '+/-'
            }
            for orig, repl in replacements.items():
                txt = txt.replace(orig, repl)
            return txt

    pdf = PDF()
    pdf.add_page()

    # Titre
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, 'B', 16)
    else:
        pdf.set_font("helvetica", 'B', 16)
    pdf.cell(0, 10, pdf.safe_text("RAPPORT DE DÉCISION CRYPTOGRAPHIQUE"), ln=1, align="C") # type: ignore
    pdf.ln(10)

    # Date
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, '', 12)
    else:
        pdf.set_font("helvetica", '', 12)
    pdf.cell(0, 6, pdf.safe_text(f"Généré le {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}"), ln=1, align="C") # type: ignore
    pdf.ln(10)

    # Contraintes
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, 'B', 14)
    else:
        pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 8, "CONTRAINTES UTILISATEUR", ln=1) # type: ignore
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, '', 12)
    else:
        pdf.set_font("helvetica", '', 12)
    for k, v in constraints.items():
        pdf.cell(0, 6, pdf.safe_text(f"- {k} : {v}"), ln=1) # type: ignore
    pdf.ln(10)

    # Tableau des prédictions
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, 'B', 14)
    else:
        pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 8, "PRÉDICTIONS", ln=1) # type: ignore
    pdf.ln(5)

    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, 'B', 10)
    else:
        pdf.set_font("helvetica", 'B', 10)
    cols = ["Critère"] + list(predictions.keys())
    col_widths = [40] + [30] * len(predictions)
    for i, col in enumerate(cols):
        pdf.cell(col_widths[i], 7, col, border=1, align='C')
    pdf.ln()

    metrics = [
        ("Chiffrement (s)", 'chiffrement'),
        ("Signature (s)", 'signature'),
        ("Vérification (s)", 'verification'),
        ("Déchiffrement (s)", 'dechiffrement'),
        ("RAM max (Mo)", 'ram_max'),
        ("Overhead (%)", 'overhead'),
    ]
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, '', 10)
    else:
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
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, 'B', 14)
    else:
        pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 8, "RECOMMANDATION", ln=1) # type: ignore
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, '', 12)
    else:
        pdf.set_font("helvetica", '', 12)
    pdf.cell(0, 6, pdf.safe_text(f"Algorithme recommandé : {recommendation}"), ln=1) # type: ignore
    pdf.ln(5)

    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, 'B', 12)
    else:
        pdf.set_font("helvetica", 'B', 12)
    pdf.cell(0, 6, "Justification :", ln=1) # type: ignore
    if pdf.unicode_font:
        pdf.set_font(pdf.unicode_font, '', 12)
    else:
        pdf.set_font("helvetica", '', 12)
    for r in reasons:
        safe_r = r if pdf.unicode_font else r.replace('→', '->').replace('–', '-')
        pdf.cell(0, 6, f"- {safe_r}", ln=1) # type: ignore

    pdf.output(str(report_dir / "rapport_decision.pdf"))
    return str(report_dir)