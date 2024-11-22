import re  # Library for validation patterns
import pyodbc
from sqlalchemy import create_engine, text
import customtkinter as ctk
from tkinter import filedialog, messagebox  # For browsing files and pop-up messages
from PIL import Image  # Import Pillow for image handling
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Creating the connection to the database
engine = create_engine('mssql+pyodbc://IIZEEX/ImageEncrytion?driver=ODBC+Driver+17+for+SQL+Server')
connection = engine.connect()

ctk.set_appearance_mode("Dark")  # Appearance options
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Login/Register")
        self.geometry("600x500")
        self.resizable(True, True)

        # Initialize Login Page
        self.login_page()

    def clear_frame(self):
        for widget in self.winfo_children():
            widget.destroy()

    def login_page(self):
        self.clear_frame()

        # Login Frame
        login_frame = ctk.CTkFrame(self)
        login_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(login_frame, text="Login", font=("Arial", 24)).pack(pady=10)

        # Email and Password fields
        self.email_entry = ctk.CTkEntry(login_frame, placeholder_text="Email")
        self.email_entry.pack(pady=10)

        self.password_entry = ctk.CTkEntry(login_frame, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=10)

        # Buttons
        ctk.CTkButton(login_frame, text="Login", command=self.login_action).pack(pady=10)
        ctk.CTkButton(login_frame, text="Register", command=self.register_page).pack(pady=10)

    def encrypt_password(self, password):
        # إعداد AES للتشفير
        Pkey = os.urandom(32)  # مفتاح عشوائي 256 بت
        Piv = os.urandom(16)  # قيمة ابتدائية عشوائية
        cipher = Cipher(algorithms.AES(Pkey), modes.CBC(Piv), backend=default_backend())
        Pencryptor = cipher.encryptor()

        # تأكد من أن حجم البيانات يكون مضاعفاً لحجم البلوك
        Ppadded_data = password + b"\0" * (16 - len(password) % 16)

        Pencrypted_data = Pencryptor.update(Ppadded_data) + Pencryptor.finalize()

        return (Pencrypted_data, Pkey, Piv)

    def register_page(self):
        self.clear_frame()

        # Register Frame
        register_frame = ctk.CTkFrame(self)
        register_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(register_frame, text="Register", font=("Arial", 24)).pack(pady=10)

        # Input Fields for Registration
        self.first_name_entry = ctk.CTkEntry(register_frame, placeholder_text="First Name")
        self.first_name_entry.pack(pady=5)

        self.last_name_entry = ctk.CTkEntry(register_frame, placeholder_text="Last Name")
        self.last_name_entry.pack(pady=5)

        self.username_entry = ctk.CTkEntry(register_frame, placeholder_text="Username")
        self.username_entry.pack(pady=5)

        self.email_register_entry = ctk.CTkEntry(register_frame, placeholder_text="Email")
        self.email_register_entry.pack(pady=5)

        self.phone_entry = ctk.CTkEntry(register_frame, placeholder_text="Phone Number")
        self.phone_entry.pack(pady=5)

        self.password_register_entry = ctk.CTkEntry(register_frame, placeholder_text="Password", show="*")
        self.password_register_entry.pack(pady=5)

        self.confirm_password_entry = ctk.CTkEntry(register_frame, placeholder_text="Confirm Password", show="*")
        self.confirm_password_entry.pack(pady=5)

        # Gender OptionMenu for Male/Female selection
        self.gender_entry = ctk.CTkOptionMenu(register_frame, values=["Male", "Female"])
        self.gender_entry.pack(pady=5)

        # Buttons
        ctk.CTkButton(register_frame, text="Register", command=self.register_action).pack(pady=10)
        ctk.CTkButton(register_frame, text="Back", command=self.login_page).pack(pady=10)

    def validate_password(self, password):
        # Ensure the password meets the required pattern
        pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%?&])[A-Za-z\d@$!%?&]{8,}$"
        return bool(re.match(pattern, password))

    def validate_phone_number(self, phone):
        # Check if the phone number contains exactly 11 digits and starts with '01'
        return phone.isdigit() and len(phone) == 11 and phone.startswith("01")

    def validate_email(self, email):
        # Ensure email contains '@' and ends with '.com'
        return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com)$", email))

    # Remaining functions...
    def register_action(self):
        first_name = self.first_name_entry.get().strip()
        last_name = self.last_name_entry.get().strip()
        username = self.username_entry.get().strip()
        email = self.email_register_entry.get().strip()
        phone = self.phone_entry.get().strip()
        password = self.password_register_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()
        gender = self.gender_entry.get()  # Get the selected gender

        # Collect errors
        errors = []

        # Check required fields
        if not email:
            errors.append("Email is required.")
        elif not self.validate_email(email):
            errors.append("- Invalid email format (must contain '@' and end with '.com').")

        if not phone:
            errors.append("Phone number is required.")
        elif not self.validate_phone_number(phone):
            errors.append("- Phone number must be exactly 11 digits and start with '01'.")

        if not username:
            errors.append("Username is required.")

        if not password:
            errors.append("Password is required.")
        elif not self.validate_password(password):
            errors.append("- Password must contain at least 8 characters, including uppercase, lowercase, digit, and special character.")

        if not confirm_password:
            errors.append("Confirm Password is required.")
        elif password != confirm_password:
            errors.append("- Passwords do not match.")

        # Display all errors, if any
        if errors:
            error_message = "\n".join(errors)
            messagebox.showerror("Registration Error", error_message)
            return

        # If no errors, proceed with registration
        try:
            encrypted_password, Pkey, PIV = self.encrypt_password(password.encode())

            query = text(''' 
                INSERT INTO Users (FName, LName, username, Email, PhoneNum, Password, Gender)
                OUTPUT INSERTED.user_id
                VALUES (:first_name, :last_name, :username, :email, :phone, :password, :gender)
            ''')

            with engine.begin() as connection:
                result = connection.execute(query, {
                    "first_name": first_name,
                    "last_name": last_name,
                    "username": username,
                    "email": email,
                    "phone": phone,
                    "password": encrypted_password,
                    "gender": gender
                }).fetchone()

                self.user_id = result[0] if result else None

            if self.user_id:
                # Insert encryption details for the password
                query = text(''' 
                    INSERT INTO PasswordEncryption (user_id, Pkey, PIV)
                    VALUES (:user_id, :Pkey, :PIV)
                ''')

                with engine.begin() as connection:
                    connection.execute(query, {
                        "user_id": self.user_id,
                        "Pkey": Pkey,
                        "PIV": PIV
                    })

                messagebox.showinfo("Registration Successful", "You have been registered successfully!")
                self.after(1500, self.login_page)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def login_action(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        query = text(''' 
            SELECT user_id, Password 
            FROM Users
            WHERE Email = :email
        ''')

        try:
            result = connection.execute(query, {"email": email}).fetchone()
            if result:
                stored_password = result[1]
                user_id = result[0]
#                print(f"Stored Password (Debugging): {stored_password}")  # remooove

                if stored_password == password:  # Simplified for demonstration
                    self.user_id = user_id
                    self.dashboard_page()
                else:
                    messagebox.showerror("Login Error", "Invalid Password.")
            else:
                messagebox.showerror("Login Error", "Email not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def dashboard_page(self):
        self.clear_frame()

        dashboard_frame = ctk.CTkFrame(self)
        dashboard_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(dashboard_frame, text="Dashboard", font=("Arial", 24)).pack(pady=10)

        ctk.CTkButton(dashboard_frame, text="Upload Photo", command=self.upload_photo).pack(pady=10)
        ctk.CTkButton(dashboard_frame, text="Show Photos", command=self.show_photos_page).pack(pady=10)
        ctk.CTkButton(dashboard_frame, text="Sign Out", command=self.login_page).pack(side="bottom", anchor="se", pady=10)

    def upload_photo(self):
        file_path = filedialog.askopenfilename(
            title="Select a Photo",
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if file_path:
            encrypted_image_data = self.encrypt_image(file_path)
            self.insert_encrypted_image_to_db(encrypted_image_data, file_path)
            messagebox.showinfo("Upload Successful", "Photo Uploaded and Encrypted Successfully!")

    def encrypt_image(self, image_path):
        img = Image.open(image_path)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        image_data = buffered.getvalue()

        Ekey = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(Ekey), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padded_image_data = image_data + b" " * (16 - len(image_data) % 16)
        encrypted_data = encryptor.update(padded_image_data) + encryptor.finalize()
        return encrypted_data

    def insert_encrypted_image_to_db(self, encrypted_data, image_path):
        encoded_image_data = base64.b64encode(encrypted_data).decode("utf-8")
        image_name = os.path.basename(image_path)

        query = text('''
            INSERT INTO Images (ImageData, ImageName, UserID) 
            VALUES (:image_data, :image_name, :user_id)
        ''')

        with engine.begin() as connection:
            connection.execute(query, {
                "image_data": encoded_image_data,
                "image_name": image_name,
                "user_id": self.user_id  # Use the logged-in user's ID
            })

    def show_photos_page(self):
        self.clear_frame()

        photos_frame = ctk.CTkFrame(self)
        photos_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(photos_frame, text="Show Photos Page (Empty)", font=("Arial", 24)).pack(pady=10)
        ctk.CTkButton(photos_frame, text="Back", command=self.dashboard_page).pack(pady=10)


if __name__ == "__main__":
    app = App()
    app.mainloop()
