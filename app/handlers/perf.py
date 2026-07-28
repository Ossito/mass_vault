from threading import Thread
import time
from pathlib import Path
from typing import Optional, Union
import matplotlib.pyplot as plt
from datetime import datetime
from fpdf import FPDF
import psutil
from concurrent.futures import ThreadPoolExecutor
import os
import csv
from functools import wraps

def measure_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        process = psutil.Process(os.getpid())
        cpu_start = process.cpu_percent(interval=None)
        mem_start = process.memory_info().rss / (1024 * 1024)
        time_start = time.perf_counter()
        
        result = func(*args, **kwargs)
        
        time_end = time.perf_counter()
        mem_end = process.memory_info().rss / (1024 * 1024)
        cpu_end = process.cpu_percent(interval=None)
        
        metrics = {
            'time': time_end - time_start,
            'cpu': cpu_end - cpu_start,
            'ram': mem_end - mem_start
        }
        
        if isinstance(result, dict):
            result['_metrics'] = metrics
        # Parfois la fonction retourne un tuple, il faut propager
        elif isinstance(result, tuple) and len(result) > 0 and isinstance(result[-1], dict):
            result[-1]['_metrics'] = metrics
        else:
            # Si le resultat n'est pas un dictionnaire, on crée un attribut s'il peut en avoir, 
            # mais souvent on va retourner le résultat dans un dictionnaire enveloppant 
            # dans les fonctions cibles (encrypt_file, etc.)
            pass
            
        return result
    return wrapper

def save_metrics_to_csv(metrics, filename="metrics_results.csv"):
    file_exists = os.path.isfile(filename)
    fields = ['timestamp', 'operation', 'algorithm', 'key_size', 'file_size', 'time', 'cpu', 'ram', 'hash_algorithm']
    
    with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        if not file_exists:
            writer.writeheader()
        writer.writerow(metrics)

class PerformanceTracker:
    def __init__(self, base_output_dir: str = "../performance_results"):
        self.operations = {}
        self.base_output_dir = Path(base_output_dir)

    def start_operation(self, operation_type: str, algorithm: str, key_size: Union[int, str], op_id: str = None, **metadata): # type: ignore
        if op_id is None:
            op_id = f"{operation_type}_{time.time_ns()}"
        self.operations[op_id] = {
            'type': operation_type,
            'start': time.perf_counter(),
            'metadata': {
                'algorithm': algorithm,
                'key_size': key_size,
                **metadata
            },
            'monitoring_active': True,
            'system_metrics': {
                'cpu_samples': [],
                'ram_samples': [],
                'timestamps': []
            },
            'steps': {},  # Initialisation du dictionnaire steps
            'file_operations': []  # Initialisation des opérations sur fichiers
        }
        
        # Démarrer le monitoring
        Thread(target=self._monitor_system, args=(op_id,), name=f"monitor_{op_id}", daemon=True).start()
        return op_id
    

    def _monitor_system(self, op_id: str, interval: float = 0.1):
        """Version améliorée avec gestion d'erreur et limite mémoire"""
        MAX_SAMPLES = 1000
        
        op_data = self.operations.get(op_id)
        if not isinstance(op_data, dict):
            return

        process = psutil.Process()
        
        while op_data.get('monitoring_active', True):
            try:
                # Mesures
                cpu = process.cpu_percent(interval=interval)
                ram = process.memory_info().rss / (1024 * 1024)  # MB
                
                # Stockage avec rotation
                metrics = op_data['system_metrics']
                for metric, value in zip(['cpu_samples', 'ram_samples', 'timestamps'],
                                        [cpu, ram, time.time()]):
                    metrics[metric].append(value)
                    if len(metrics[metric]) > MAX_SAMPLES:
                        metrics[metric].pop(0)
                        
            except (psutil.NoSuchProcess, KeyError) as e:
                print(f"Erreur de monitoring: {e}")
                break


    def stop_operation(self, op_id: str):
        if op_id in self.operations:
            self.operations[op_id]['monitoring_active'] = False
            self.operations[op_id]['duration'] = time.perf_counter() - self.operations[op_id]['start']

    def add_step(self, op_id: str, step_name: str):
        """Ajoute une étape à suivre"""
        if op_id not in self.operations:
            raise ValueError(f"Opération {op_id} non trouvée")
            
        self.operations[op_id]['steps'][step_name] = {
            'start': time.perf_counter(),
            'end': None,
            'duration': None
        }

    def end_step(self, op_id: str, step_name: str):
        """Termine une étape et calcule sa durée"""
        if op_id not in self.operations or step_name not in self.operations[op_id]['steps']:
            raise ValueError("Opération ou étape invalide")
            
        step_data = self.operations[op_id]['steps'][step_name]
        step_data['end'] = time.perf_counter()
        step_data['duration'] = step_data['end'] - step_data['start']

    def add_file_operation(self, op_id: str, filename: str, operation_type: str, duration: float):
        """Ajoute une opération sur fichier"""
        if op_id not in self.operations:
            raise ValueError(f"Opération {op_id} non trouvée")
            
        self.operations[op_id]['file_operations'].append({
            'filename': filename,
            'type': operation_type,
            'duration': duration
        })


    @staticmethod
    def process_files_parallel(files, process_func, max_workers=4):
        """Traite les fichiers en parallèle"""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(process_func, files))
        return results

    def _generate_system_graphs(self, op_data: dict, output_dir: Path):
        """Génère les graphiques système"""
        metrics = op_data['system_metrics']
        algorithm = op_data['metadata']['algorithm']
        key_size = op_data['metadata']['key_size']
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Assurer que toutes les listes ont la même taille
        min_len = min(len(metrics['timestamps']), len(metrics['cpu_samples']), len(metrics['ram_samples']))
        if min_len == 0:
            print("⚠️ Pas assez de données pour générer le graphique système")
            return None
            
        timestamps = metrics['timestamps'][:min_len]
        cpu_samples = metrics['cpu_samples'][:min_len]
        ram_samples = metrics['ram_samples'][:min_len]

        # Normalisation du temps
        time_elapsed = [t - timestamps[0] for t in timestamps]

        # Graphique combiné
        plt.figure(figsize=(15, 8))
        
        # CPU
        plt.subplot(2, 1, 1)
        plt.plot(time_elapsed, cpu_samples, 'r-', label='CPU %')
        plt.ylabel('CPU Usage (%)')
        plt.title(f"{algorithm} {key_size} - Resource Usage")
        plt.legend()

        # RAM
        plt.subplot(2, 1, 2)
        plt.plot(time_elapsed, ram_samples, 'b-', label='RAM (MB)')
        plt.ylabel('RAM Usage (MB)')
        plt.xlabel('Time (seconds)')
        plt.legend()

        # Sauvegarde
        graph_path = output_dir / f"system_metrics_{timestamp}.png"
        plt.savefig(graph_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        return graph_path


    def _generate_steps_graph(self, op_data: dict, output_dir: Path, timestamp: str) -> Path:
        """Génère le graphique des étapes"""
        steps = list(op_data['steps'].keys())
        durations = [s['duration'] for s in op_data['steps'].values()]
        
        plt.figure(figsize=(12, 6))
        bars = plt.bar(steps, durations, color=['#3498db', '#2ecc71', '#f1c40f'])
        
        plt.title("Temps par étape")
        plt.ylabel("Secondes")
        
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, height,
                    f'{height:.3f}s', ha='center', va='bottom')
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        graph_path = output_dir / f"steps_{timestamp}.png"
        plt.savefig(graph_path, dpi=150)
        plt.close()
        
        return graph_path

    def _generate_encryption_graph(self, op_data: dict, output_dir: Path, timestamp: str) -> Optional[Path]:
        """Génère le graphique de chiffrement"""
        enc_ops = [f for f in op_data['file_operations'] if f['type'] == 'encryption']
        
        if not enc_ops:
            return None
            
        filenames = [f['filename'] for f in enc_ops]
        durations = [f['duration'] for f in enc_ops]
        
        plt.figure(figsize=(12, 6))
        plt.bar(filenames, durations, color='#3498db')
        plt.title("Temps de chiffrement par fichier")
        plt.ylabel("Secondes")
        plt.xticks(rotation=90)
        plt.tight_layout()
        
        graph_path = output_dir / f"encryption_{timestamp}.png"
        plt.savefig(graph_path, dpi=150)
        plt.close()
        
        return graph_path

    def _generate_signing_graph(self, op_data: dict, output_dir: Path, timestamp: str) -> Optional[Path]:
        """Génère le graphique de signature"""
        sig_ops = [f for f in op_data['file_operations'] if f['type'] == 'signing']
        
        if not sig_ops:
            return None
            
        filenames = [f['filename'] for f in sig_ops]
        durations = [f['duration'] for f in sig_ops]
        
        plt.figure(figsize=(12, 6))
        plt.bar(filenames, durations, color='#9b59b6')
        plt.title("Temps de signature par fichier")
        plt.ylabel("Secondes")
        plt.xticks(rotation=90)
        plt.tight_layout()
        
        graph_path = output_dir / f"signing_{timestamp}.png"
        plt.savefig(graph_path, dpi=150)
        plt.close()
        
        return graph_path

    def generate_report(self, op_id: str):
        """Version finale avec séparation claire des dossiers"""
        if op_id not in self.operations:
            raise ValueError(f"Opération {op_id} non trouvée")
        
        op_data = self.operations[op_id]
        algo = op_data['metadata']['algorithm']
        key_size = op_data['metadata']['key_size']
        algo_folder = f"{algo}_{key_size}"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Création des dossiers séparés
        graphs_dir = self.base_output_dir / "graphs" / algo_folder
        reports_dir = self.base_output_dir / "reports" / algo_folder
        graphs_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Génération des graphiques (dans graphs_dir)
        graphs = []
        for graph_func in [
            lambda: self._generate_system_graphs(op_data, graphs_dir),
            lambda: self._generate_steps_graph(op_data, graphs_dir, timestamp),
            lambda: self._generate_encryption_graph(op_data, graphs_dir, timestamp),
            lambda: self._generate_signing_graph(op_data, graphs_dir, timestamp)
        ]:
            try:
                if graph := graph_func():
                    graphs.append(graph)
            except Exception as e:
                print(f"⚠️ Erreur génération graphique: {e}")

        # Génération PDF (dans reports_dir)
        self._generate_pdf_report(
            op_data=op_data,
            algo_id=f"{algo} {key_size}",
            timestamp=timestamp,
            output_dir=reports_dir,
            graph_paths=graphs
        )

    def _generate_pdf_report(self, op_data: dict, algo_id: str, timestamp: str, output_dir: Path, graph_paths: list):
        """Génère le rapport PDF"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # En-tête
        pdf.set_font_size(16)
        pdf.cell(200, 10, text=f"Rapport de performance - {algo_id}", new_x="LMARGIN", new_y="next", align='C')
        pdf.set_font_size(12)
        pdf.cell(200, 8, text=f"Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="next", align='C')
        pdf.ln(20)
        
        # Graphique des étapes
        if graph_paths[0]:
            pdf.set_font('', 'B', 14)
            pdf.cell(200, 10, text="Temps par étape", new_x="LMARGIN", new_y="next")
            pdf.image(str(graph_paths[0]), x=10, w=190)
            pdf.ln(5)
        
        # Graphique des chiffrements
        if graph_paths[1]:
            pdf.add_page()
            pdf.set_font('', 'B', 14)
            pdf.cell(200, 10, text="Temps de chiffrement par fichier", new_x="LMARGIN", new_y="next")
            pdf.image(str(graph_paths[1]), x=10, w=190)
            pdf.ln(5)
        
        # Graphique des signatures
        if graph_paths[2]:
            pdf.add_page()
            pdf.set_font('', 'B', 14)
            pdf.cell(200, 10, text="Temps de signature par fichier", new_x="LMARGIN", new_y="next")
            pdf.image(str(graph_paths[2]), x=10, w=190)
        
        # Sauvegarde
        report_path = output_dir / f"report_{timestamp}.pdf"
        pdf.output(str(report_path))
        print(f"📊 Rapport généré: {report_path}")

# Instance globale
perf_tracker = PerformanceTracker()