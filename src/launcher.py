"""
launcher.py - small desktop launcher for the scanner and web UI.

Run with: python launcher.py
"""

import subprocess
import sys
import webbrowser
from pathlib import Path

import customtkinter as ctk

BASE_DIR = Path(__file__).parent.resolve()
SCRIPT_1 = BASE_DIR / "scanner.py"
SCRIPT_2 = BASE_DIR / "web_ui.py"
UI_URL = "http://127.0.0.1:5000"  # change this to your UI URL


def run_all():
    status_label.configure(text="Running Script 1...", text_color="orange")
    app.update()

    subprocess.run([sys.executable, str(SCRIPT_1)])

    status_label.configure(text="Running Script 2...", text_color="orange")
    app.update()

    subprocess.run([sys.executable, str(SCRIPT_2)])

    status_label.configure(text="Done! Opening UI...", text_color="green")
    app.update()

    webbrowser.open(UI_URL)


# ---------- UI ----------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Automation Launcher")
app.geometry("400x250")

title = ctk.CTkLabel(app, text="Run Scripts", font=("Arial", 24))
title.pack(pady=20)

run_button = ctk.CTkButton(app, text="Start Automation", command=run_all, width=200, height=40)
run_button.pack(pady=10)

status_label = ctk.CTkLabel(app, text="", font=("Arial", 14))
status_label.pack(pady=10)

app.mainloop()
