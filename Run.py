# import tkinter as tk
# import subprocess

# def run_script1():
#     subprocess.run(["python", "juice_scan1.py"])

# def run_script2():
#     subprocess.run(["python", "web_ui_bootstrap1.py"])

# app = tk.Tk()
# app.title("Run Python Scripts")

# button1 = tk.Button(app, text="Run Script 1", command=run_script1)
# button1.pack(pady=10)

# button2 = tk.Button(app, text="Run Script 2", command=run_script2)
# button2.pack(pady=10)

# app.mainloop()

import customtkinter as ctk
import subprocess
import webbrowser

# Your scripts and UI URL
SCRIPT_1 = "juice_scan1.py"
SCRIPT_2 = "web_ui_bootstrap1.py"
UI_URL = "http://127.0.0.1:5000"    # change this to your UI URL

def run_all():
    status_label.configure(text="Running Script 1...", text_color="orange")
    app.update()

    subprocess.run(["python", SCRIPT_1])

    status_label.configure(text="Running Script 2...", text_color="orange")
    app.update()

    subprocess.run(["python", SCRIPT_2])

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
breakpoint
run_button = ctk.CTkButton(app, text="Start Automation", command=run_all, width=200, height=40)
run_button.pack(pady=10)

status_label = ctk.CTkLabel(app, text="", font=("Arial", 14))
status_label.pack(pady=10)

app.mainloop()

