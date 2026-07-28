#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path

# Ajouter le répertoire 'app' au chemin de recherche
root_dir = Path(__file__).resolve().parent
sys.path.append(str(root_dir / "app"))

from utils.storage import StorageManager

def load_all_metrics(metrics_graphs_dir):
    """
    Parcourt tous les fichiers JSON du dossier metrics_graphs/ et les charge.
    """
    all_data = []
    if not metrics_graphs_dir.exists():
        print(f"❌ Le dossier des métriques n'existe pas : {metrics_graphs_dir}")
        return all_data

    print(f"🔍 Scan du dossier centralisé : {metrics_graphs_dir}")
    for json_file in sorted(metrics_graphs_dir.glob("*.json")):
        # Ignorer les anciens backups
        if "_old_" in json_file.name:
            continue
            
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Validation de la structure cible
            if not isinstance(data, dict) or 'metadata' not in data or 'timings' not in data or 'resources' not in data:
                print(f"⚠️ Fichier JSON non conforme ignoré : {json_file.name}")
                continue
                
            all_data.append(data)
            print(f"✅ Métrique chargée : {json_file.name} (Répétition #{data['metadata'].get('repetition_index', 1)})")
            
        except Exception as e:
            print(f"❌ Erreur de chargement {json_file.name} : {e}")
            
    return all_data

def compile_comparison_data(all_data):
    """
    Regroupe et compile les données par configuration {algorithm}_{key_size}.
    """
    compiled = {}
    for data in all_data:
        meta = data['metadata']
        algo = meta['algorithm']
        key_size = meta['key_size']
        config_name = f"{algo}_{key_size}"
        
        if config_name not in compiled:
            compiled[config_name] = {
                'keygen': [],
                'encap': [],
                'sign': [],
                'verif': [],
                'dec': [],
                'cpu_mean': [],
                'ram_max': [],
                'ram_mean': [],
                'overhead': []
            }
            
        # Charger les métriques réelles depuis le schéma JSON précis
        timings = data.get('timings', {})
        compiled[config_name]['keygen'].append(timings.get('key_generation', 0.0))
        compiled[config_name]['encap'].append(timings.get('encapsulation', 0.0))
        compiled[config_name]['sign'].append(timings.get('signature', 0.0))
        compiled[config_name]['verif'].append(timings.get('verification', 0.0))
        compiled[config_name]['dec'].append(timings.get('decapsulation', 0.0))
        
        resources = data.get('resources', {})
        compiled[config_name]['cpu_mean'].append(resources.get('cpu_mean', 0.0))
        compiled[config_name]['ram_max'].append(resources.get('ram_max', 0.0))
        compiled[config_name]['ram_mean'].append(resources.get('ram_mean', 0.0))
        
        compiled[config_name]['overhead'].append(data.get('overhead', 0.0))
        
    # Calculer moyennes et écarts-types
    summary = {}
    for config, lists in compiled.items():
        reps = len(lists['keygen'])
        if reps < 2:
            print(f"⚠️ Avertissement : Seulement {reps} répétition(s) pour la configuration {config}.")
            print("Les calculs d'écarts-types ne seront pas statistiquement significatifs.")
            
        summary[config] = {
            'reps': reps,
            
            # Keygen
            'keygen_mean': np.mean(lists['keygen']) if lists['keygen'] else 0.0,
            'keygen_std': np.std(lists['keygen']) if len(lists['keygen']) > 1 else 0.0,
            
            # Phases
            'encap_mean': np.mean(lists['encap']) if lists['encap'] else 0.0,
            'encap_std': np.std(lists['encap']) if len(lists['encap']) > 1 else 0.0,
            'sign_mean': np.mean(lists['sign']) if lists['sign'] else 0.0,
            'sign_std': np.std(lists['sign']) if len(lists['sign']) > 1 else 0.0,
            'verif_mean': np.mean(lists['verif']) if lists['verif'] else 0.0,
            'verif_std': np.std(lists['verif']) if len(lists['verif']) > 1 else 0.0,
            'dec_mean': np.mean(lists['dec']) if lists['dec'] else 0.0,
            'dec_std': np.std(lists['dec']) if len(lists['dec']) > 1 else 0.0,
            
            # CPU
            'cpu_mean_mean': np.mean(lists['cpu_mean']) if lists['cpu_mean'] else 0.0,
            'cpu_mean_std': np.std(lists['cpu_mean']) if len(lists['cpu_mean']) > 1 else 0.0,
            
            # RAM
            'ram_max_mean': np.mean(lists['ram_max']) if lists['ram_max'] else 0.0,
            'ram_max_std': np.std(lists['ram_max']) if len(lists['ram_max']) > 1 else 0.0,
            'ram_mean_mean': np.mean(lists['ram_mean']) if lists['ram_mean'] else 0.0,
            'ram_mean_std': np.std(lists['ram_mean']) if len(lists['ram_mean']) > 1 else 0.0,
            
            # Overhead
            'overhead_mean': np.mean(lists['overhead']) if lists['overhead'] else 0.0,
            'overhead_std': np.std(lists['overhead']) if len(lists['overhead']) > 1 else 0.0
        }
    return summary

def generate_comparison_graphs(summary, output_dir):
    """
    Génère les 4 graphiques de comparaison demandés dans comparison_graphs/.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    configs = sorted(list(summary.keys()))
    
    if not configs:
        print("❌ Aucune donnée pour générer les graphiques comparatifs globaux.")
        return

    # --- 1. keygen_time.png (Temps de génération des clés) ---
    plt.figure(figsize=(10, 6))
    means = [summary[cfg]['keygen_mean'] for cfg in configs]
    stds = [summary[cfg]['keygen_std'] for cfg in configs]
    
    bars = plt.bar(configs, means, yerr=stds, capsize=6, color='#ff7f0e', alpha=0.8, edgecolor='grey')
    plt.ylabel('Temps de génération moyen (s)')
    plt.title('Temps moyen de génération des clés asymétriques (RSA / ECC / ElGamal)')
    plt.xticks(rotation=45, ha='right')
    plt.grid(True, linestyle=':', alpha=0.5)
    
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, height + (height*0.02) + 0.01, f"{height:.4f}s", ha='center', va='bottom', fontsize=8)
        
    plt.tight_layout()
    plt.savefig(output_dir / "comparaison_keygen.png", dpi=150)
    plt.close()
    print("  ✓ comparaison_keygen.png généré.")

    # --- 2. comparaison_time.png (Temps des 4 phases cryptographiques) ---
    plt.figure(figsize=(12, 7))
    x = np.arange(len(configs))
    width = 0.18
    
    encap_means = [summary[cfg]['encap_mean'] for cfg in configs]
    encap_stds = [summary[cfg]['encap_std'] for cfg in configs]
    sign_means = [summary[cfg]['sign_mean'] for cfg in configs]
    sign_stds = [summary[cfg]['sign_std'] for cfg in configs]
    dec_means = [summary[cfg]['dec_mean'] for cfg in configs]
    dec_stds = [summary[cfg]['dec_std'] for cfg in configs]
    verif_means = [summary[cfg]['verif_mean'] for cfg in configs]
    verif_stds = [summary[cfg]['verif_std'] for cfg in configs]
    
    plt.bar(x - 1.5*width, encap_means, width, yerr=encap_stds, capsize=3, label='Encapsulation (Chiff.)', color='#1f77b4', alpha=0.8)
    plt.bar(x - 0.5*width, sign_means, width, yerr=sign_stds, capsize=3, label='Signature', color='#2ca02c', alpha=0.8)
    plt.bar(x + 0.5*width, dec_means, width, yerr=dec_stds, capsize=3, label='Déchiffrement (Décaps.)', color='#9467bd', alpha=0.8)
    plt.bar(x + 1.5*width, verif_means, width, yerr=verif_stds, capsize=3, label='Vérification de signature', color='#bcbd22', alpha=0.8)
    
    plt.ylabel('Temps de traitement moyen (s)')
    plt.title('Comparaison globale des temps par phase cryptographique (Moyenne ± Écart-type)')
    plt.xticks(x, configs, rotation=45, ha='right')
    plt.legend()
    plt.grid(True, linestyle=':', alpha=0.5)
    
    plt.tight_layout()
    plt.savefig(output_dir / "comparaison_time.png", dpi=150)
    plt.close()
    print("  ✓ comparaison_time.png généré.")

    # --- 3. comparaison_resources.png (CPU et RAM) ---
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7))
    
    # CPU moyenne
    cpu_means = [summary[cfg]['cpu_mean_mean'] for cfg in configs]
    cpu_stds = [summary[cfg]['cpu_mean_std'] for cfg in configs]
    ax1.bar(configs, cpu_means, yerr=cpu_stds, capsize=5, color='#d62728', alpha=0.8, edgecolor='grey')
    ax1.set_ylabel('Utilisation CPU Moyenne (%)')
    ax1.set_title('Charge CPU moyenne globale')
    ax1.set_xticklabels(configs, rotation=45, ha='right')
    ax1.grid(True, linestyle=':', alpha=0.5)
    
    # RAM max et moyenne
    x_ram = np.arange(len(configs))
    w_ram = 0.35
    ram_max_means = [summary[cfg]['ram_max_mean'] for cfg in configs]
    ram_max_stds = [summary[cfg]['ram_max_std'] for cfg in configs]
    ram_mean_means = [summary[cfg]['ram_mean_mean'] for cfg in configs]
    ram_mean_stds = [summary[cfg]['ram_mean_std'] for cfg in configs]
    
    ax2.bar(x_ram - w_ram/2, ram_mean_means, w_ram, yerr=ram_mean_stds, capsize=4, label='RAM Moyenne', color='#aec7e8', alpha=0.8)
    ax2.bar(x_ram + w_ram/2, ram_max_means, w_ram, yerr=ram_max_stds, capsize=4, label='RAM Max (Pic)', color='#1f77b4', alpha=0.8)
    ax2.set_ylabel('Utilisation RAM moyenne (Mo)')
    ax2.set_title('Consommation RAM (Moyenne vs Pic)')
    ax2.set_xticks(x_ram)
    ax2.set_xticklabels(configs, rotation=45, ha='right')
    ax2.legend()
    ax2.grid(True, linestyle=':', alpha=0.5)
    
    plt.tight_layout()
    plt.savefig(output_dir / "comparaison_resources.png", dpi=150)
    plt.close()
    print("  ✓ comparaison_resources.png généré.")

    # --- 4. comparaison_overhead.png (Overhead) ---
    plt.figure(figsize=(10, 6))
    oh_means = [summary[cfg]['overhead_mean'] for cfg in configs]
    oh_stds = [summary[cfg]['overhead_std'] for cfg in configs]
    
    bars = plt.bar(configs, oh_means, yerr=oh_stds, capsize=6, color='#9467bd', alpha=0.8, edgecolor='grey')
    plt.ylabel("Overhead moyen d'expansion de taille (%)")
    plt.title("Expansion moyenne de taille (overhead) par rapport au fichier d'origine")
    plt.xticks(rotation=45, ha='right')
    plt.grid(True, linestyle=':', alpha=0.5)
    
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, height + (height*0.02) + 0.05, f"{height:.4f}%", ha='center', va='bottom', fontsize=8)
        
    plt.tight_layout()
    plt.savefig(output_dir / "comparaison_overhead.png", dpi=150)
    plt.close()
    print("  ✓ comparaison_overhead.png généré.")
    
    print(f"\n🎉 Graphiques de comparaison globale enregistrés dans : {output_dir}")

def main():
    print("==================================================")
    print("📊 MASSS VAULT - Outil de Comparaison Globale")
    print("==================================================")
    
    sm = StorageManager()
    metrics_graphs_dir = sm.get_metrics_graphs_dir()
    comparison_dir = sm.get_directory("comparison_graphs")
    
    all_data = load_all_metrics(metrics_graphs_dir)
    if not all_data:
        print("❌ Aucune donnée de métrique valide n'a pu être chargée.")
        print("Veuillez lancer des chiffrements/signatures dans l'application pour générer des données.")
        return
        
    summary = compile_comparison_data(all_data)
    generate_comparison_graphs(summary, comparison_dir)
    print("==================================================")

if __name__ == "__main__":
    main()
