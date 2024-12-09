import os
import shutil
import socket
import ipaddress
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from datetime import datetime
import string
import winreg
import customtkinter
from customtkinter import *
from PIL import Image

# Malware signatures for simulation
MALWARE_SIGNATURES = ["malicious_code", "virus123", "trojan_horse"]
QUARANTINE_FOLDER = "quarantine"

# Ensure quarantine folder exists
if not os.path.exists(QUARANTINE_FOLDER):
    os.makedirs(QUARANTINE_FOLDER)

# Global variable to track active tooltip windows
active_tooltip = None

# Function to scan a file for malware
def scan_file(file_path):
    try:
        with open(file_path, "r", errors="ignore") as file:
            content = file.read()
            for signature in MALWARE_SIGNATURES:
                if signature in content:
                    return f"Malware detected in {file_path}!\nSignature: {signature}"
            return f"{file_path} is clean."
    except Exception as e:
        return f"Error reading {file_path}: {e}"

# Function to scan a folder and check all files
def scan_folder(folder_path):
    if not os.path.isdir(folder_path):
        return "Invalid folder path."
    results = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_file(file_path)
            results.append(result)
    return "\n".join(results)

# Function to quarantine infected files
def quarantine_file(file_path):
    try:
        shutil.copy(file_path, QUARANTINE_FOLDER)
        os.remove(file_path)
        return f"{file_path} has been moved to quarantine."
    except Exception as e:
        return f"Error quarantining {file_path}: {e}"


# # Function to log results into a file
# def log_result(result):
#     with open("scan_log.txt", "a") as log_file:
#         log_file.write(f"{datetime.now()}:\n{result}\n{'-'*40}\n")

# # Function to toggle real-time protection
# def toggle_real_time_protection():
#     if real_time_var.get():  
#         messagebox.showinfo("Real-Time Protection", "Real-time protection enabled.")
#     else:
#         messagebox.showinfo("Real-Time Protection", "Real-time protection disabled.")

# Network scanning function
def scan_network(network_range):
    results = []
    try:
        network = ipaddress.IPv4Network(network_range, strict=False)
        for ip in network:
            ip_str = str(ip)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    result = s.connect_ex((ip_str, 80))  # Check port 80
                    if result == 0:
                        results.append(f"{ip_str} is active (port 80 open).")
                    else:
                        results.append(f"{ip_str} is inactive.")
            except Exception as e:
                results.append(f"Error scanning {ip_str}: {e}")
    except ValueError as e:
        return f"Invalid network range: {e}"

    return "\n".join(results)

# Function to evaluate password strength
def evaluate_password(password):
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return "Weak: Password must include at least one uppercase letter."
    if not any(char.islower() for char in password):
        return "Weak: Password must include at least one lowercase letter."
    if not any(char.isdigit() for char in password):
        return "Weak: Password must include at least one number."
    if not any(char in string.punctuation for char in password):
        return "Weak: Password must include at least one special character (!@#$%^&*)."
    if password.lower() in ["password", "123456", "qwerty", "abc123", "letmein"]:
        return "Weak: Password is too common."
    return "Strong: Your password meets all criteria!"

# Function to browse and select a file
def browse_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        result = scan_file(file_path)  
        if "Malware detected" in result:
            quarantine = messagebox.askyesno("Malware Found", "Malware detected! Quarantine the file?")
            if quarantine:
                quarantine_msg = quarantine_file(file_path)
                result += f"\n{quarantine_msg}"
        log_result(result)
        messagebox.showinfo("Scan Result", result)

# Function to browse and select a folder
def browse_folder():
    folder_path = filedialog.askdirectory(title="Select a Folder")
    if folder_path:
        results = scan_folder(folder_path) 
        log_result(results)
        messagebox.showinfo("Scan Results", results)

# Function to detect if the system is in dark mode (works on Windows)
def is_dark_mode():
    try:
        # Using winreg to access Windows registry for Dark Mode check
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
        value, _ = winreg.QueryValueEx(reg_key, "AppsUseLightTheme")
        
        # Dark Mode is enabled when the registry value is 0 (Light Mode = 1, Dark Mode = 0)
        return value == 0
    except Exception as e:
        print(f"Error detecting Dark Mode: {e}")
        return False  
        
# Function to apply Dark or Light mode
def apply_theme(root):
    # We check whether the system is in Dark Mode and apply the appropriate colors
    if is_dark_mode():
        root.config(bg="black")
        # Set other components to dark mode
        for widget in root.winfo_children():
            if isinstance(widget, tk.Button):
                widget.config(bg="gray", fg="white")
            elif isinstance(widget, tk.Checkbutton):
                widget.config(bg="black", fg="white")
            elif isinstance(widget, tk.Label):
                widget.config(bg="black", fg="white")
    else:
        root.config(bg="white")
        # Set other components to light mode
        for widget in root.winfo_children():
            if isinstance(widget, tk.Button):
                widget.config(bg="lightgray", fg="black")
            elif isinstance(widget, tk.Checkbutton):
                widget.config(bg="white", fg="black")
            elif isinstance(widget, tk.Label):
                widget.config(bg="white", fg="black")

# Function to show tooltip (text appears when hovering over an element)
def show_tooltip(event, widget, text):
    global active_tooltip

    # If there's an existing tooltip, destroy it
    if active_tooltip:
        active_tooltip.destroy()

    # Only create a tooltip if there's a valid text
    if text:
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)  
        tooltip.wm_geometry(f"+{widget.winfo_rootx() + 20}+{widget.winfo_rooty() + 20}")  
        tooltip_label = tk.Label(tooltip, text=text, background="lightyellow", relief="solid", borderwidth=1)
        tooltip_label.pack()
        active_tooltip = tooltip  

        def close_tooltip(event):
            tooltip.destroy()  

        widget.bind("<Leave>", close_tooltip)

# Function to open help window
def open_help():
    messagebox.showinfo("Help", "This tool helps you scan files and folders for malware.\n\n"
                                "1. Scan File: Scan individual files for malware.\n"
                                "2. Scan Folder: Scan all files within a folder.\n"
                                "3. Real-Time Protection: Enable/Disable real-time protection.\n"
                                "4. Quarantine: Infected files will be moved to quarantine.")


# GUI functions
def browse_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        result = scan_file(file_path)
        if "Malware detected" in result:
            quarantine = messagebox.askyesno("Malware Found", "Malware detected! Quarantine the file?")
            if quarantine:
                quarantine_msg = quarantine_file(file_path)
                result += f"\n{quarantine_msg}"
        log_result(result)
        messagebox.showinfo("Scan Result", result)

def browse_folder():
    folder_path = filedialog.askdirectory(title="Select a Folder")
    if folder_path:
        results = scan_folder(folder_path)
        log_result(results)
        messagebox.showinfo("Scan Results", results)

def toggle_real_time_protection():
    if real_time_var.get():  
        messagebox.showinfo("Real-Time Protection", "Real-time protection enabled.")
    else:
        messagebox.showinfo("Real-Time Protection", "Real-time protection disabled.")

def scan_network_gui():
    try:
        network_range = simpledialog.askstring("Network Scan", "Enter network range (e.g., 192.168.1.0/24):")
        if network_range:
            results = scan_network(network_range)
            log_result(results)
            messagebox.showinfo("Network Scan Results", results)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during the scan: {e}")

def password_checker_gui():
    password = simpledialog.askstring("Password Checker", "Enter a password to check its strength:", show="*")
    if password:
        result = evaluate_password(password)
        messagebox.showinfo("Password Strength", result)

def log_result(result):
    with open("scan_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()}:\n{result}\n{'-'*40}\n")

def create_gui():
    app = CTk()
    app.title("M.A.T")
    app.geometry("500x400")

    # logo
    app.iconbitmap("C:/Users/Administrator/Pictures/Logo.ico")


    # Tittle
    label = CTkLabel(master = app, text = " Antivirus Tool",font = ("Arial Black", 20), text_color = "darkblue")
    label.place(relx = 0.5, rely = 0.09, anchor = "center")

    #scan file button
    scan_file_btn = CTkButton(master = app, text = "Scan File", command=browse_file, corner_radius = 32, fg_color = "darkblue",
                    hover_color = "#4158D0", border_color = "",
                    border_width = 2)
    scan_file_btn.place(relx = 0.2, rely = 0.3, anchor = "center")
    scan_file_btn.bind("<Enter>", lambda e: show_tooltip(e, scan_file_btn, "Scan a file for malware"))

    #scan folder button
    scan_folder_btn = CTkButton(master = app, text = "Scan Folder", command=browse_folder, corner_radius = 32, fg_color = "darkblue",
                hover_color = "#4158D0")
    scan_folder_btn.place(relx = 0.8, rely = 0.3, anchor = "center")
    scan_folder_btn.bind("<Enter>", lambda e: show_tooltip(e, scan_folder_btn, "Scan a folder for malware"))

    # # Real-time-protection switcher
    # real_time_var = tk.BooleanVar()  
    # real_time_check = CTkCheckBox(master = app, text = "Real_time_protection", fg_color = "darkblue", checkbox_height = 30,
    #                    checkbox_width = 30, corner_radius = 36)
    # real_time_check.place(relx = 0.5, rely = 0.5, anchor = "center")
    # real_time_check.bind("<Enter>", lambda e: show_tooltip(e, real_time_check, "Enable or Disable real-time protection"))

    #scan Password button
    check_password_btn = CTkButton(master = app, text = "Check Password", command=password_checker_gui, corner_radius = 32, fg_color = "darkblue",
                hover_color = "#4158D0")
    check_password_btn.place(relx = 0.8, rely = 0.8, anchor = "center")
    check_password_btn.bind("<Enter>", lambda e: show_tooltip(e, check_password_btn, "Check if the password is strong"))

    # Network scan
    check_Network_btn = CTkButton(master = app, text="Scan Network", command=scan_network_gui,  corner_radius = 32, fg_color = "darkblue",
                hover_color = "#4158D0")
    check_Network_btn.place(relx = 0.5, rely = 0.5, anchor = "center")
    check_Network_btn.bind("<Enter>", lambda e: show_tooltip(e, check_Network_btn, "Check if the Network is strong"))

    # Help button
    help_btn = CTkButton(master = app, text = "Help", command=open_help, corner_radius = 32, fg_color = "darkblue",
                hover_color = "#4158D0")
    help_btn.place(relx = 0.2, rely = 0.8, anchor = "center")
    help_btn.bind("<Enter>", lambda e: show_tooltip(e, help_btn, "Get help and instructions"))

    # Exit button
    exit_btn = CTkButton(master = app, text = "Exit", command=app.quit, corner_radius = 32, fg_color = "red",
                hover_color = "#4158D0")
    exit_btn.place(relx = 0.5, rely = 0.91, anchor = "center")
    exit_btn.bind("<Enter>", lambda e: show_tooltip(e, exit_btn, "Exit from the App"))

    app.mainloop()

# Run the GUI application
create_gui()





















