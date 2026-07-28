import tkinter as tk

# Offset pour le Dock Mac (ajustable)
DOCK_OFFSET = 70

def center_window(window, width=None, height=None, y_offset=DOCK_OFFSET):
    """
    Centre la fenêtre sur l'écran en tenant compte d'un décalage vertical (Dock).
    Si width/height sont fournis, redimensionne d'abord.
    """
    if width is not None and height is not None:
        window.geometry(f"{width}x{height}")
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    win_width = window.winfo_width()
    win_height = window.winfo_height()
    x = (screen_width - win_width) // 2
    y = (screen_height - win_height) // 2 - y_offset
    if y < 0:
        y = 0
    window.geometry(f"+{x}+{y}")