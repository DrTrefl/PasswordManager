import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import secrets
import string
import hashlib
import base64
import threading
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self):
        self.master_password = None
        self.fernet = None
        self.data_file = "passwords.dat"
        self.config_file = "config.dat"
        self.passwords = {}
        self.root = None
        self.main_window = None
        self.password_visible_timer = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def hash_password(self, password: str) -> str:
        salt = os.urandom(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return base64.b64encode(salt + pwdhash).decode('ascii')
    
    def verify_password(self, stored_password: str, provided_password: str) -> bool:
        try:
            salt_and_hash = base64.b64decode(stored_password.encode('ascii'))
            salt = salt_and_hash[:32]
            stored_hash = salt_and_hash[32:]
            pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
            return pwdhash == stored_hash
        except:
            return False
    
    def save_master_password(self, password: str):
        hashed = self.hash_password(password)
        salt = os.urandom(16)
        with open(self.config_file, 'wb') as f:
            f.write(salt + hashed.encode('utf-8'))
    
    def load_master_password(self) -> tuple:
        if not os.path.exists(self.config_file):
            return None, None
        with open(self.config_file, 'rb') as f:
            data = f.read()
            salt = data[:16]
            hashed_password = data[16:].decode('utf-8')
            return hashed_password, salt
    
    def encrypt_data(self, data: dict) -> bytes:
        json_data = json.dumps(data).encode('utf-8')
        return self.fernet.encrypt(json_data)
    
    def decrypt_data(self, encrypted_data: bytes) -> dict:
        decrypted_data = self.fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    
    def save_data(self):
        if self.fernet is None:
            return
        encrypted_data = self.encrypt_data(self.passwords)
        with open(self.data_file, 'wb') as f:
            f.write(encrypted_data)
    
    def load_data(self):
        if not os.path.exists(self.data_file) or self.fernet is None:
            self.passwords = {}
            return
        try:
            with open(self.data_file, 'rb') as f:
                encrypted_data = f.read()
            self.passwords = self.decrypt_data(encrypted_data)
        except:
            self.passwords = {}
    
    def generate_password(self, length=16, use_uppercase=True, use_lowercase=True, 
                         use_digits=True, use_symbols=True):
        characters = ""
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            characters = string.ascii_letters + string.digits
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password
    
    def start_login_window(self):
        self.root = tk.Tk()
        self.root.iconbitmap('../assets/icon.ico')
        self.root.title("Password Manager - Login")
        self.root.geometry("400x250")
        self.root.resizable(False, False)
        
        self.center_window(self.root, 400, 250)
        
        stored_password, salt = self.load_master_password()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Password Manager", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        if stored_password is None:
            ttk.Label(main_frame, text="Create a master password:").grid(row=1, column=0, sticky=tk.W, pady=5)
            self.master_password_entry = ttk.Entry(main_frame, show="*", width=30)
            self.master_password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
            
            ttk.Label(main_frame, text="Confirm password:").grid(row=2, column=0, sticky=tk.W, pady=5)
            self.confirm_password_entry = ttk.Entry(main_frame, show="*", width=30)
            self.confirm_password_entry.grid(row=2, column=1, pady=5, padx=(10, 0))
            
            create_button = ttk.Button(main_frame, text="Create", command=self.create_master_password)
            create_button.grid(row=3, column=0, columnspan=2, pady=20)
            
        else:
            ttk.Label(main_frame, text="Enter master password:").grid(row=1, column=0, sticky=tk.W, pady=5)
            self.master_password_entry = ttk.Entry(main_frame, show="*", width=30)
            self.master_password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
            
            login_button = ttk.Button(main_frame, text="Log in", command=self.login)
            login_button.grid(row=2, column=0, columnspan=2, pady=20)
            
            change_password_button = ttk.Button(main_frame, text="Change master password", 
                                              command=self.change_master_password)
            change_password_button.grid(row=3, column=0, columnspan=2, pady=5)
        
        self.root.bind('<Return>', lambda e: self.login() if stored_password else self.create_master_password())
        self.master_password_entry.focus()
        
        self.root.mainloop()
    
    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_master_password(self):
        password = self.master_password_entry.get()
        confirm = self.confirm_password_entry.get()
        
        if len(password) < 6:
            messagebox.showerror("Error", "The master password must be at least 6 characters long")
            return
            
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        self.save_master_password(password)
        self.master_password = password
        
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        self.fernet = Fernet(key)
        
        self.root.destroy()
        self.start_main_window()
    
    def login(self):
        password = self.master_password_entry.get()
        stored_password, salt = self.load_master_password()
        
        if stored_password and self.verify_password(stored_password, password):
            self.master_password = password
            key = self.derive_key(password, salt)
            self.fernet = Fernet(key)
            self.load_data()
            self.root.destroy()
            self.start_main_window()
        else:
            messagebox.showerror("Error", "Incorrect master password")
            self.master_password_entry.delete(0, tk.END)
    
    def change_master_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.iconbitmap('../assets/icon.ico')
        dialog.title("Master password change")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        self.center_window(dialog, 400, 200)
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Current password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        old_password_entry = ttk.Entry(main_frame, show="*", width=25)
        old_password_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        
        ttk.Label(main_frame, text="New password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        new_password_entry = ttk.Entry(main_frame, show="*", width=25)
        new_password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        
        ttk.Label(main_frame, text="Confirm:").grid(row=2, column=0, sticky=tk.W, pady=5)
        confirm_password_entry = ttk.Entry(main_frame, show="*", width=25)
        confirm_password_entry.grid(row=2, column=1, pady=5, padx=(10, 0))
        
        def change_password():
            old_password = old_password_entry.get()
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            
            stored_password, _ = self.load_master_password()
            if not self.verify_password(stored_password, old_password):
                messagebox.showerror("Error", "Incorrect current password")
                return
            
            if len(new_password) < 6:
                messagebox.showerror("Error", "The new password must be at least 6 characters long")
                return
                
            if new_password != confirm_password:
                messagebox.showerror("Error", "The new passwords do not match")
                return
            
            self.save_master_password(new_password)
            messagebox.showinfo("Success", "The master password has been changed")
            dialog.destroy()
        
        change_button = ttk.Button(main_frame, text="Change password", command=change_password)
        change_button.grid(row=3, column=0, columnspan=2, pady=20)
        
        old_password_entry.focus()
    
    def start_main_window(self):
        self.main_window = tk.Tk()
        self.main_window.iconbitmap('../assets/icon.ico')
        self.main_window.title("Password Manager")
        self.main_window.geometry("800x600")
        self.center_window(self.main_window, 800, 600)
        
        menubar = tk.Menu(self.main_window)
        self.main_window.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save", command=self.save_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        main_frame = ttk.Frame(self.main_window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.main_window.columnconfigure(0, weight=1)
        self.main_window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        left_frame = ttk.LabelFrame(main_frame, text="Platforms", padding="10")
        left_frame.grid(row=0, column=0, rowspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        ttk.Label(left_frame, text="Search:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.search_entry = ttk.Entry(left_frame, width=25)
        self.search_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        self.search_entry.bind('<KeyRelease>', self.filter_passwords)
        
        self.password_listbox = tk.Listbox(left_frame, width=25, height=20)
        self.password_listbox.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        self.password_listbox.bind('<<ListboxSelect>>', self.on_password_select)
        
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(2, weight=1)
        
        buttons_frame = ttk.Frame(left_frame)
        buttons_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(buttons_frame, text="Add", command=self.add_password).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_frame, text="Edit", command=self.edit_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Delete", command=self.delete_password).pack(side=tk.LEFT, padx=5)
        
        right_frame = ttk.LabelFrame(main_frame, text="Details", padding="10")
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(right_frame, text="Platform:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.platform_label = ttk.Label(right_frame, text="", font=('Arial', 10))
        self.platform_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        ttk.Label(right_frame, text="Email/Login:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.email_label = ttk.Label(right_frame, text="", font=('Arial', 10))
        self.email_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        ttk.Label(right_frame, text="Password:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=5)
        
        password_frame = ttk.Frame(right_frame)
        password_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        self.password_label = ttk.Label(password_frame, text="", font=('Arial', 10))
        self.password_label.grid(row=0, column=0, sticky=tk.W)
        
        self.show_password_button = ttk.Button(password_frame, text="Show", command=self.toggle_password_visibility)
        self.show_password_button.grid(row=0, column=1, padx=(10, 0))
        
        self.copy_password_button = ttk.Button(password_frame, text="Copy", command=self.copy_password)
        self.copy_password_button.grid(row=0, column=2, padx=(5, 0))
        
        right_frame.columnconfigure(1, weight=1)
        
        generator_frame = ttk.LabelFrame(main_frame, text="Password generator", padding="10")
        generator_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(10, 0))
        
        length_frame = ttk.Frame(generator_frame)
        length_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(length_frame, text="Length:").pack(side=tk.LEFT)
        self.length_var = tk.IntVar(value=16)
        length_spinbox = ttk.Spinbox(length_frame, from_=4, to=128, width=10, textvariable=self.length_var)
        length_spinbox.pack(side=tk.LEFT, padx=(5, 0))
        
        options_frame = ttk.Frame(generator_frame)
        options_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Uppercase letters", variable=self.uppercase_var).pack(side=tk.LEFT)
        ttk.Checkbutton(options_frame, text="Lowercase letters", variable=self.lowercase_var).pack(side=tk.LEFT)
        ttk.Checkbutton(options_frame, text="Numbers", variable=self.digits_var).pack(side=tk.LEFT)
        ttk.Checkbutton(options_frame, text="Symbols", variable=self.symbols_var).pack(side=tk.LEFT)
        
        generate_button = ttk.Button(generator_frame, text="Generate password", command=self.generate_and_show_password)
        generate_button.grid(row=2, column=0, pady=10)
        
        self.generated_password_var = tk.StringVar()
        generated_entry = ttk.Entry(generator_frame, textvariable=self.generated_password_var, width=40, state='readonly')
        generated_entry.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        
        copy_generated_button = ttk.Button(generator_frame, text="Copy generated", 
                                         command=self.copy_generated_password)
        copy_generated_button.grid(row=4, column=0, pady=5)
        
        generator_frame.columnconfigure(0, weight=1)
        
        self.status_bar = ttk.Label(main_frame, text="Done", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.refresh_password_list()
        
        self.main_window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.main_window.mainloop()
    
    def filter_passwords(self, event):
        search_text = self.search_entry.get().lower()
        self.password_listbox.delete(0, tk.END)
        
        for platform in sorted(self.passwords.keys()):
            if search_text in platform.lower():
                self.password_listbox.insert(tk.END, platform)
    
    def refresh_password_list(self):
        self.password_listbox.delete(0, tk.END)
        for platform in sorted(self.passwords.keys()):
            self.password_listbox.insert(tk.END, platform)
    
    def on_password_select(self, event):
        selection = self.password_listbox.curselection()
        if selection:
            platform = self.password_listbox.get(selection[0])
            data = self.passwords[platform]
            
            self.platform_label.config(text=platform)
            self.email_label.config(text=data['email'])
            self.password_label.config(text="••••••••••")
            self.current_password = data['password']
            self.password_visible = False
            self.show_password_button.config(text="Show")
            
            if self.password_visible_timer:
                self.password_visible_timer.cancel()
    
    def toggle_password_visibility(self):
        if hasattr(self, 'current_password'):
            if self.password_visible:
                self.password_label.config(text="••••••••••")
                self.show_password_button.config(text="Show")
                self.password_visible = False
                if self.password_visible_timer:
                    self.password_visible_timer.cancel()
            else:
                self.password_label.config(text=self.current_password)
                self.show_password_button.config(text="Hide")
                self.password_visible = True
                
                self.password_visible_timer = threading.Timer(60.0, self.hide_password_after_timeout)
                self.password_visible_timer.start()
    
    def hide_password_after_timeout(self):
        self.password_label.config(text="••••••••••")
        self.show_password_button.config(text="Show")
        self.password_visible = False
    
    def copy_password(self):
        if hasattr(self, 'current_password'):
            pyperclip.copy(self.current_password)
            self.status_bar.config(text="Password copied to clipboard")
            self.main_window.after(3000, lambda: self.status_bar.config(text="Done"))
    
    def add_password(self):
        self.password_dialog()
    
    def edit_password(self):
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select an entry to edit")
            return
        
        platform = self.password_listbox.get(selection[0])
        self.password_dialog(platform)
    
    def delete_password(self):
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select an entry to delete")
            return
        
        platform = self.password_listbox.get(selection[0])
        
        if messagebox.askyesno("Confirmation", f"Are you sure you want to delete the entry for '{platform}'?"):
            del self.passwords[platform]
            self.refresh_password_list()
            self.clear_details()
            self.save_data()
            self.status_bar.config(text=f"Entry deleted: {platform}")
    
    def clear_details(self):
        self.platform_label.config(text="")
        self.email_label.config(text="")
        self.password_label.config(text="")
        if hasattr(self, 'current_password'):
            del self.current_password
    
    def password_dialog(self, edit_platform=None):
        dialog = tk.Toplevel(self.main_window)
        dialog.iconbitmap('../assets/icon.ico')
        dialog.title("Edit entry" if edit_platform else "Add new entry")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        self.center_window(dialog, 400, 250)
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Platform/Service:").grid(row=0, column=0, sticky=tk.W, pady=5)
        platform_entry = ttk.Entry(main_frame, width=30)
        platform_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        
        ttk.Label(main_frame, text="Email/Login:").grid(row=1, column=0, sticky=tk.W, pady=5)
        email_entry = ttk.Entry(main_frame, width=30)
        email_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(main_frame, width=30, show="*")
        password_entry.grid(row=2, column=1, pady=5, padx=(10, 0))
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        show_var = tk.BooleanVar()
        def toggle_password_show():
            password_entry.config(show="" if show_var.get() else "*")
        
        show_check = ttk.Checkbutton(button_frame, text="Show password", variable=show_var, command=toggle_password_show)
        show_check.pack(side=tk.LEFT)
        
        def use_generated_password():
            if self.generated_password_var.get():
                password_entry.delete(0, tk.END)
                password_entry.insert(0, self.generated_password_var.get())
        
        use_generated_button = ttk.Button(button_frame, text="Use generated", command=use_generated_password)
        use_generated_button.pack(side=tk.LEFT, padx=(10, 0))
        
        if edit_platform:
            data = self.passwords[edit_platform]
            platform_entry.insert(0, edit_platform)
            email_entry.insert(0, data['email'])
            password_entry.insert(0, data['password'])
        
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        def save_password():
            platform = platform_entry.get().strip()
            email = email_entry.get().strip()
            password = password_entry.get()
            
            if not platform or not email or not password:
                messagebox.showerror("Error", "All fields must be filled out")
                return
            
            if not edit_platform and platform in self.passwords:
                if not messagebox.askyesno("Confirmation", 
                                         f"Entry for '{platform}' already exists. Replace?"):
                    return
            
            if edit_platform and edit_platform != platform:
                del self.passwords[edit_platform]
            
            self.passwords[platform] = {
                'email': email,
                'password': password
            }
            
            self.refresh_password_list()
            self.save_data()
            self.status_bar.config(text=f"Entry saved: {platform}")
            dialog.destroy()
        
        save_button = ttk.Button(action_frame, text="Save", command=save_password)
        save_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = ttk.Button(action_frame, text="Cancel", command=dialog.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        platform_entry.focus()
    
    def generate_and_show_password(self):
        length = self.length_var.get()
        uppercase = self.uppercase_var.get()
        lowercase = self.lowercase_var.get()
        digits = self.digits_var.get()
        symbols = self.symbols_var.get()
        
        if not any([uppercase, lowercase, digits, symbols]):
            messagebox.showwarning("Warning", "Select at least one character type")
            return
        
        password = self.generate_password(length, uppercase, lowercase, digits, symbols)
        self.generated_password_var.set(password)
        self.status_bar.config(text="A new password has been generated")
    
    def copy_generated_password(self):
        password = self.generated_password_var.get()
        if password:
            pyperclip.copy(password)
            self.status_bar.config(text="Generated password copied to clipboard")
            self.main_window.after(3000, lambda: self.status_bar.config(text="Done"))
        else:
            messagebox.showwarning("Warning", "Generate the password first")
    
    def on_closing(self):
        if self.password_visible_timer:
            self.password_visible_timer.cancel()
        
        self.save_data()
        
        if self.main_window:
            self.main_window.destroy()
        else:
            self.root.destroy()

def main():
    try:
        import cryptography
        import pyperclip
    except ImportError as e:
        print(f"Error: Missing required library: {e}")
        print("Install the required libraries:")
        print("pip install cryptography pyperclip")
        return
    
    password_manager = PasswordManager()
    password_manager.start_login_window()

if __name__ == "__main__":
    main()