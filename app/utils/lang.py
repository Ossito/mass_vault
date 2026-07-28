LANGUAGES = {
    "fr": {
        # --- Textes communs à toutes les interfaces ---
        "common": {
            "home": "Accueil",
            "quit": "Quitter",
            "back_button": "Retour",
            "copyright": "© 2026 Cryptosystem 0geek. Tous droits réservés.",
            "warning": "Attention",
            "information": "Information",
            "error": "Erreur",
            "change_folder": "Changer dossier",
            "storage_location": "Emplacement de stockage",
            "current_location": "Emplacement actuel",
            "files_count": "fichiers",
            "storage_size": "taille",
            "close": "Fermer",                         # "Close" en anglais
            "view_details": "Voir les détails",       # "View details"
            "storage_configuration": "Configuration du Stockage",  # "Storage Configuration"
            "storage_details": "DÉTAILS DU STOCKAGE", # "STORAGE DETAILS"
            "base_location": "Emplacement de base:",  # "Base location:"
            "path": "Chemin",                         # "Path"
            "files": "Fichiers",                      # "Files"
            "yes": "Oui",                             # "Yes"
            "no": "Non",                              # "No"
            "bytes": "octets",   # "bytes"
            "kb": "Ko",          # "KB"
            "mb": "Mo",          # "MB"
            "gb": "Go",          # "GB"
            "tb": "To",          # "TB"
            "assistant_button": "Assistant de décision",
            "decision": {
                "decision_title": "Assistant de décision"
            },
        },
        
        # --- Interface d'accueil ---
        "home": {
            "home_title": "Accueil",
            "welcome_text": "Bienvenue sur MASSS VAULT !",
            "action_text": "Choisissez une action ci-dessous :",
            "encryption_interface": "Chiffrement & Signature",
            "decryption_interface": "Déchiffrement",
            "verification_interface": "Vérification de Signature"
        },
        
        # --- Interface de chiffrement ---
        "encryption": {
            "encryption_title": "Chiffrement et Signature",
            "select_folder": "Sélectionner un dossier",
            "browse": "Sélectionner",
            "folder_size": "Taille total dossier: 0.00 MB",
            "select_algorithm": "Sélectionner un algorithme",
            "select_keysize": "Sélectionner une taille de clé",
            "encrypt_sign": "🔐 Chiffrer et Signer",
            "hash_algorithm": "Algorithme de hachage",
            
            "explorer": {
                "select_algorithm_first": "⏳ Sélectionnez un algorithme et une taille",
                "configuration": "⚙️ Configuration",
                "open_result_dirs": "📂 Ouvrir les dossiers de résultats",
                "advanced_explorer": "🔍 Explorateur avancé",
                "view_paths": "📋 Voir les chemins",
                "no_operation": "⏳ Aucune opération effectuée",
                "launch_encryption": "🚀 Lancer le chiffrement/signature",
                "storage_config": "⚙️ Configuration stockage"
            },
            
            "sections": {
                "selection": "Sélection de dossier",
                "algorithm": "Paramètres algorithmes",
                "results": "Résultat(s) Opération(s)"
            },
            
            "results": {
                "encrypted_files": "Fichier(s) chiffré(s)",
                "signed_files": "Fichier(s) signé(s)"
            },
            
            "progress": {
                "preparing": "Préparation...",
                "checking_params": "Vérification des paramètres...",
                "processing": "Préparation du traitement...",
                "completed": "Opération terminée avec succès!",
                "ready": "Prêt"
            },
            
            "messages": {
                "no_folder": "Veuillez d'abord sélectionner un dossier valide.",
                "no_algorithm": "Aucun algorithme sélectionné.",
                "no_keysize": "Aucune taille de clé sélectionnée.",
                "no_hash": "Aucun algorithme de hachage sélectionné.",
                "encryption_started": "⏳ Chiffrement et Signature en cours...\nAlgorithme : {algo}\nTaille de clé : {keysize} bits\nStockage : {storage}",
                "keys_generated": "✅ Clés générées avec succès.\nClé privée : {private}\nClé publique : {public}\nTemps de génération : {time:.2f} secondes",
                "success": "✅ Opération terminée avec succès !\n\nFichiers traités : {processed}\nÉchecs : {failed}\n📁 Stocké dans : {storage}",
                "error_generating_keys": "❌ Erreur lors de la génération des clés: {error}",
                "error_processing": "❌ Une erreur s'est produite : {error}"
            },
            
            "dialogs": {
                "no_folder_title": "Aucun dossier",
                "no_folder_msg": "Aucun fichier trouvé.\nTaille : {size} Mo",
                "folder_selected_title": "Dossier sélectionné",
                "folder_selected_msg": "Dossier chargé.\nTaille : {size} Mo",
                "keys_generated_title": "Clés générées",
                "success_title": "Terminé",
                "error_title": "Erreur",
                "processing_title": "Succès"
            }
        },
        
        # --- Interface de déchiffrement ---
        "decryption": {
            "decryption_title": "Déchiffrement",
            "decrypt": "Déchiffrer",
            "decryption_section": "Déchiffrement",
            "select_algorithm": "Choisissez un algorithme",
            "select_keysize": "Choisissez une taille de clé",
            "decryption_operation": "Résultat(s) du Déchiffrement",
            "progress": {
                "preparing": "Préparation...",
                "decrypting": "Déchiffrement en cours...",
                "completed": "Déchiffrement terminé.",
                "ready": "Prêt"
            },
            "messages": {
                "no_algorithm": "Veuillez sélectionner un algorithme et une taille de clé.",
                "no_encrypted_files": "Aucun fichier chiffré trouvé.",
                "success": "✅ Déchiffrement terminé.\nFichiers traités : {processed}\nÉchecs : {failed}",
                "warning": "⚠️ Déchiffrement terminé avec des erreurs.\nFichiers traités : {processed}\nÉchecs : {failed}",
                "error_processing": "Erreur lors du déchiffrement",
                "information": "Information",
                "encrypted_files_found": "fichier(s) chiffré(s) trouvé(s)"
            },
            "dialogs": {
                "success_title": "Succès",
                "warning_title": "Avertissement",
                "error_title": "Erreur"
            },
            "sections": {
                "encrypted_files": "Fichier(s) Chiffré(s)",
                "decrypted_files": "Fichier(s) Déchiffré(s)",
                "results": "Résultats"
            },
            "results": {
                "decrypted_files": "Fichier(s) déchiffré(s)"
            },
            "explorer": {
                "select_algorithm_first": "⏳ Sélectionnez un algorithme et une taille",
                "configuration": "⚙️ Configuration",
                "open_result_dirs": "📂 Ouvrir les dossiers de résultats",
                "advanced_explorer": "🔍 Explorateur avancé",
                "view_paths": "📋 Voir les chemins",
                "no_operation": "⏳ Aucun déchiffrement effectué",
                "launch_decryption": "🚀 Lancer le déchiffrement",
                "storage_config": "⚙️ Configuration stockage"
            }
        },
        
        # --- Interface de vérification ---
        "verification": {
            "verification_title": "Vérification de Signature",
            "verify_signatures": "Vérifier les signatures",
            "select_algorithm": "Choisissez un algorithme",
            "select_keysize": "Choisissez une taille de clé",
            "signature_verification": "Vérification de Signature",
            "show_graphs": "Afficher les graphiques",
            "graphs": {
                "title": "Graphiques de Vérification",
                "performance": "Performance par Fichier",
                "results": "Répartition des Résultats",
                "open_folder": "Ouvrir le dossier des graphiques"
            },
            "progress": {
                "preparing": "Préparation...",
                "checking_params": "Vérification des paramètres...",
                "verifying": "Vérification en cours...",
                "completed": "Vérification terminée.",
                "ready": "Prêt"
            },
            "messages": {
                "no_algorithm": "Veuillez sélectionner un algorithme et une taille de clé.",
                "success": "✅ Vérification terminée.\n{valid} signature(s) valide(s)\nTemps moyen : {avg_time:.3f}s",
                "warning": "⚠️ Vérification terminée avec des anomalies.\n✅ {valid} valide(s)\n❌ {invalid} invalide(s)\n⚠️ {missing} manquante(s)",
                "error_processing": "Erreur lors de la vérification"
            },
            "sections": {
                "verification": "Vérification",
                "results": "Résultats",
                "signed_files": "Fichier(s) Signé(s)",
                "encrypted_files": "Fichier(s) Chiffré(s)"
            },
            "dialogs": {
                "success_title": "Succès",
                "warning_title": "Avertissement",
                "error_title": "Erreur"
            },
            "results": {
                "status": "État de la Vérification"
            }
        }
    },
    
    "en": {
        "common": {
            "home": "Home",
            "quit": "Quit",
            "back_button": "Back",
            "copyright": "© 2026 Cryptosystem 0geek. All rights reserved.",
            "warning": "Warning",
            "information": "Information",
            "error": "Error",
            "change_folder": "Change folder",
            "storage_location": "Storage location",
            "current_location": "Current location",
            "files_count": "files",
            "storage_size": "size",
            "close": "Close",
            "view_details": "View details",
            "storage_configuration": "Storage Configuration",
            "storage_details": "STORAGE DETAILS",
            "base_location": "Base location:",
            "path": "Path",
            "files": "Files",
            "yes": "Yes",
            "no": "No",
            "bytes": "bytes",
            "kb": "KB",
            "mb": "MB",
            "gb": "GB",
            "tb": "TB",
            "assistant_button": "Decision Assistant",
            "decision": {
                "decision_title": "Decision Assistant"
            } 
        },

        "home": {
            "home_title": "Home",
            "welcome_text": "Welcome to MASSS VAULT!",
            "action_text": "Select an action below:",
            "encryption_interface": "Encryption & Signature",
            "decryption_interface": "Decryption",
            "verification_interface": "Signature Verification"
        },

        "encryption": {
            "encryption_title": "Encryption & Signature",
            "select_folder": "Select a folder",
            "browse": "Browse",
            "folder_size": "Total folder size: 0.00 MB",
            "select_algorithm": "Select algorithm",
            "select_keysize": "Select key size",
            "encrypt_sign": "🔐 Encrypt & Sign",
            "hash_algorithm": "Hash algorithm (required)",
            
            "explorer": {
                "select_algorithm_first": "⏳ Select an algorithm and a key size",
                "configuration": "⚙️ Configuration",
                "open_result_dirs": "📂 Open result folders",
                "advanced_explorer": "🔍 Advanced explorer",
                "view_paths": "📋 View paths",
                "no_operation": "⏳ No operation performed",
                "launch_encryption": "🚀 Launch encryption/signing",
                "storage_config": "⚙️ Storage configuration"
            },

            "sections": {
                "selection": "Folder selection",
                "algorithm": "Algorithm settings",
                "results": "Operation results"
            },

            "results": {
                "encrypted_files": "Encrypted file(s)",
                "signed_files": "Signed file(s)"
            },

            "progress": {
                "preparing": "Preparing...",
                "checking_params": "Checking parameters...",
                "processing": "Processing...",
                "completed": "Operation completed successfully!",
                "ready": "Ready"
            },

            "messages": {
                "no_folder": "Please select a folder first.",
                "no_algorithm": "No algorithm selected.",
                "no_keysize": "No key size selected.",
                "no_hash": "No hash algorithm selected.",
                "encryption_started": "⏳ Encryption and signing in progress...\nAlgorithm: {algo}\nKey size: {keysize} bits\nStorage: {storage}",
                "keys_generated": "✅ Keys generated successfully.\nPrivate key: {private}\nPublic key: {public}\nGeneration time: {time:.2f} seconds",
                "success": "✅ Operation completed successfully!\n\nFiles processed: {processed}\nFailures: {failed}\n📁 Stored in: {storage}",
                "error_generating_keys": "❌ Error generating keys: {error}",
                "error_processing": "❌ An error occurred: {error}"
            },

            "dialogs": {
                "no_folder_title": "No folder",
                "no_folder_msg": "No file found.\nSize: {size} MB",
                "folder_selected_title": "Folder selected",
                "folder_selected_msg": "Folder loaded.\nSize: {size} MB",
                "keys_generated_title": "Keys generated",
                "success_title": "Done",
                "error_title": "Error",
                "processing_title": "Success"
            }
        },

        "decryption": {
            "decryption_title": "Decryption",
            "decrypt": "Decrypt",
            "decryption_section": "Decryption",
            "select_algorithm": "Select algorithm",
            "select_keysize": "Select key size",
            "decryption_operation": "Decryption Results",
            "progress": {
                "preparing": "Preparing...",
                "decrypting": "Decrypting...",
                "completed": "Decryption completed.",
                "ready": "Ready"
            },
            "messages": {
                "no_algorithm": "Please select an algorithm and a key size.",
                "no_encrypted_files": "No encrypted files found.",
                "success": "✅ Decryption completed.\nProcessed: {processed}\nFailed: {failed}",
                "warning": "⚠️ Decryption finished with errors.\nProcessed: {processed}\nFailed: {failed}",
                "error_processing": "Error during decryption",
                "information": "Information",
                "encrypted_files_found": "encrypted file(s) found"
            },
            "dialogs": {
                "success_title": "Success",
                "warning_title": "Warning",
                "error_title": "Error"
            },
            "sections": {
                "encrypted_files": "Encrypted File(s)",
                "decrypted_files": "Decrypted File(s)",
                "results": "Results"
            },
            "results": {
                "decrypted_files": "Decrypted file(s)"
            },
            "explorer": {
                "select_algorithm_first": "⏳ Select an algorithm and a key size",
                "configuration": "⚙️ Configuration",
                "open_result_dirs": "📂 Open result folders",
                "advanced_explorer": "🔍 Advanced explorer",
                "view_paths": "📋 View paths",
                "no_operation": "⏳ No decryption performed",
                "launch_decryption": "🚀 Launch decryption",
                "storage_config": "⚙️ Storage configuration"
            }
        },

        "verification": {
            "verification_title": "Signature Verification",
            "verify_signatures": "Verify Signatures",
            "select_algorithm": "Select algorithm",
            "select_keysize": "Select key size",
            "signature_verification": "Signature Verification",
            "show_graphs": "Show Graphs",
            "graphs": {
                "title": "Verification Graphs",
                "performance": "Performance by File",
                "results": "Results Distribution",
                "open_folder": "Open Graphs Folder"
            },
            "progress": {
                "preparing": "Preparing...",
                "checking_params": "Checking parameters...",
                "verifying": "Verifying...",
                "completed": "Verification completed.",
                "ready": "Ready"
            },
            "messages": {
                "no_algorithm": "Please select an algorithm and a key size.",
                "success": "✅ Verification completed.\n{valid} valid signature(s)\nAverage time: {avg_time:.3f}s",
                "warning": "⚠️ Verification completed with anomalies.\n✅ {valid} valid\n❌ {invalid} invalid\n⚠️ {missing} missing",
                "error_processing": "Error during verification"
            },
            "sections": {
                "verification": "Verification",
                "results": "Results",
                "signed_files": "Signed File(s)",
                "encrypted_files": "Encrypted File(s)"
            },
            "dialogs": {
                "success_title": "Success",
                "warning_title": "Warning",
                "error_title": "Error"
            },
            "results": {
                "status": "Verification Status"
            }
        }
    }
}