import tkinter as tk
import ttkbootstrap as ttk
from interfaces.home_window import HomeWindow

# Variables globales pour le centrage automatique
_last_width = None
_last_height = None

# Décalage pour compenser le Dock (à ajuster selon votre écran, 60–80 pixels généralement)
DOCK_OFFSET = 70

def center_window(window, width=None, height=None, y_offset=DOCK_OFFSET):
    """
    Centre la fenêtre en tenant compte d'un décalage vertical (pour le Dock).
    Si width/height sont fournis, redimensionne d'abord.
    """
    if width is not None and height is not None:
        window.geometry(f"{width}x{height}")
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    win_width = window.winfo_width()
    win_height = window.winfo_height()

    # Position horizontale centrée
    x = (screen_width - win_width) // 2
    # Position verticale centrée, remontée de y_offset pixels
    y = (screen_height - win_height) // 2 - y_offset
    # Sécurité : ne pas sortir de l'écran par le haut
    if y < 0:
        y = 0

    window.geometry(f"+{x}+{y}")

def on_configure(event):
    """Recentrer automatiquement si la taille change (pas lors d'un simple déplacement)."""
    global _last_width, _last_height
    if event.widget == root:
        if _last_width != event.width or _last_height != event.height:
            _last_width = event.width
            _last_height = event.height
            root.after(10, lambda: center_window(root, y_offset=DOCK_OFFSET))

def main():
    global root
    root = tk.Tk()
    try:
        root.tk.call('tk', 'scaling', 1.2)
    except:
        pass
    root.title("MASSS VAULT - Main Interface")

    # Dimensions initiales
    init_width, init_height = 900, 690
    center_window(root, init_width, init_height, y_offset=DOCK_OFFSET)

    root.resizable(True, True)
    root.minsize(800, 690)

    # Événement de redimensionnement
    root.bind('<Configure>', on_configure)

    # Thème Bootstrap
    style = ttk.Style()
    available_themes = style.theme_names()
    default_theme = "flatly" if "flatly" in available_themes else available_themes[0]
    style.theme_use(default_theme)

    from config import ensure_vault_directories
    ensure_vault_directories()

    # --- Initialisation de l'explorateur de fichiers ---
    from utils.storage import storage_manager
    from utils.explorer_manager import init_explorer_manager
    init_explorer_manager(storage_manager)

    HomeWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()