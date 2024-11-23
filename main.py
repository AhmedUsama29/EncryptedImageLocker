import os
import base64
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog, messagebox
import customtkinter as ctk
from sqlalchemy import create_engine, text
import pyodbc
from PIL import Image
from io import BytesIO

# Database connection setup
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
        # AES encryption setup
        Pkey = os.urandom(32)  # Random 256-bit key
        Piv = os.urandom(16)  # Random initialization vector
        cipher = Cipher(algorithms.AES(Pkey), modes.CBC(Piv), backend=default_backend())
        Pencryptor = cipher.encryptor()

        # Ensure data is padded to a multiple of block size
        Ppadded_data = password.encode('utf-8') + b"\0" * (16 - len(password.encode('utf-8')) % 16)
        Pencrypted_data = Pencryptor.update(Ppadded_data) + Pencryptor.finalize()

        # Convert Pkey and Piv to base64 strings for storing in the database
        Pkey_str = base64.b64encode(Pkey).decode('utf-8')
        Piv_str = base64.b64encode(Piv).decode('utf-8')

        return (Pencrypted_data, Pkey_str, Piv_str)

    def decrypt_password(self, encrypted_password, Pkey_str, PIV_str):
        # Convert Pkey and PIV from base64 string back to bytes
        Pkey = base64.b64decode(Pkey_str)
        PIV = base64.b64decode(PIV_str)

        cipher = Cipher(algorithms.AES(Pkey), modes.CBC(PIV), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_password) + decryptor.finalize()
        return decrypted_data.rstrip(b"\0").decode('utf-8')  # Remove padding and decode to string

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
        # Password validation pattern
        pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%?&])[A-Za-z\d@$!%?&]{8,}$"
        return bool(re.match(pattern, password))

    def validate_phone_number(self, phone):
        # Phone validation
        return phone.isdigit() and len(phone) == 11 and phone.startswith("01")

    def validate_email(self, email):
        # Email validation
        return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com)$", email))

    def register_action(self):
        first_name = self.first_name_entry.get().strip()
        last_name = self.last_name_entry.get().strip()
        username = self.username_entry.get().strip()
        email = self.email_register_entry.get().strip()
        phone = self.phone_entry.get().strip()
        password = self.password_register_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()
        gender = self.gender_entry.get()  # Get the selected gender

        # Validation checks
        errors = []

        # Email validation
        if not email:
            errors.append("Email is required.")
        elif not self.validate_email(email):
            errors.append("- Invalid email format (must contain '@' and end with '.com').")

        # Phone validation
        if not phone:
            errors.append("Phone number is required.")
        elif not self.validate_phone_number(phone):
            errors.append("- Phone number must be exactly 11 digits and start with '01'.")

        # Username validation
        if not username:
            errors.append("Username is required.")

        # Password validation
        if not password:
            errors.append("Password is required.")
        elif not self.validate_password(password):
            errors.append("- Password must contain at least 8 characters, including uppercase, lowercase, digit, and special character.")

        # Confirm password validation
        if not confirm_password:
            errors.append("Confirm Password is required.")
        elif password != confirm_password:
            errors.append("- Passwords do not match.")

        # Show errors if any
        if errors:
            error_message = "\n".join(errors)
            messagebox.showerror("Registration Error", error_message)
            return

        # Proceed with registration if no errors
        try:
            encrypted_password, Pkey, PIV = self.encrypt_password(password)

            # Insert into Users table
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
        SELECT Users.User_ID, Users.Password, PasswordEncryption.Pkey, PasswordEncryption.PIV
        FROM Users 
        INNER JOIN PasswordEncryption ON Users.User_ID = PasswordEncryption.user_id
        WHERE Email = :email
        ''')

        result = connection.execute(query, {"email": email}).fetchone()

        if result:
            encrypted_password, Pkey_str, Piv_str = result[1], result[2], result[3]
            decrypted_password = self.decrypt_password(encrypted_password, Pkey_str, Piv_str)

            if decrypted_password == password:
                self.user_id = result[0]  # استخدام الفهرس للوصول إلى الـ user_id
                self.dashboard_page()  # الانتقال إلى صفحة التحكم (Dashboard)
            else:
                messagebox.showerror("Login Failed", "Invalid email or password!")
        else:
            messagebox.showerror("Login Failed", "Email not found!")

    def dashboard_page(self):
        self.clear_frame()

        # Dashboard Frame
        dashboard_frame = ctk.CTkFrame(self)
        dashboard_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(dashboard_frame, text="Dashboard", font=("Arial", 24)).pack(pady=10)

        # Upload Photo Button
        ctk.CTkButton(dashboard_frame, text="Upload Photo", command=self.upload_photo).pack(pady=10)

        # Show Photos Button
        ctk.CTkButton(dashboard_frame, text="Show Photos", command=self.show_photos_page).pack(pady=10)

        # Sign Out Button (added at the bottom right)
        ctk.CTkButton(dashboard_frame, text="Sign Out", command=self.login_page).pack(side="bottom", anchor="se", pady=10)

    def upload_photo(self):
        file_path = filedialog.askopenfilename(
            title="Select a Photo",
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if file_path:
            # تشفير الصورة باستخدام AES
            encrypted_image_data = self.encrypt_image(file_path)

            # إدخال الصورة المشفرة إلى قاعدة البيانات
            self.insert_encrypted_image_to_db(encrypted_image_data, file_path)

            ctk.CTkLabel(self, text="Photo Uploaded and Encrypted Successfully!", font=("Arial", 18), text_color="green").pack(pady=20)

    def encrypt_image(self, image_path):
        # فتح الصورة باستخدام PIL
        img = Image.open(image_path)

        # تحويل الصورة إلى بايتات
        buffered = BytesIO()
        img.save(buffered, format="PNG")

        # تحويل البايتات إلى نص Base64 (اختياري لكن سأتركه فقط لإظهار كيفية تحويل الصورة)
        image_data = buffered.getvalue()

        # إعداد AES للتشفير
        Ekey = os.urandom(32)  # مفتاح عشوائي 256 بت
        iv = os.urandom(16)  # قيمة ابتدائية عشوائية
        cipher = Cipher(algorithms.AES(Ekey), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # تأكد من أن حجم البيانات يكون مضاعفاً لحجم البلوك
        padded_data = image_data + b"\0" * (16 - len(image_data) % 16)

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return (encrypted_data, Ekey, iv)

    def insert_encrypted_image_to_db(self, encrypted_image_data, image_path):
        encrypted_data, Ekey, iv = encrypted_image_data

        # خصائص الصورة
        file_size = os.path.getsize(image_path)
        file_extension = os.path.splitext(image_path)[1].lower()
        image_name = os.path.basename(image_path)
        category = "General"
        #
        try:
            query = text('''
                INSERT INTO Images (Size, Extention, Name, Category, EncryptedText, User_Id)
                VALUES (:size, :ext, :name, :category, :encrypted_text, :user_id)
            ''')

            with engine.begin() as connection:
                connection.execute(query, {
                    "size": file_size,
                    "ext": file_extension,
                    "name": image_name,
                    "category": category,
                    "encrypted_text": encrypted_data,
                    "user_id": self.user_id
                })

                imgid_query = text('SELECT @@IDENTITY AS imgid')
                result = connection.execute(imgid_query).fetchone()
                imgid = result[0] if result else None

                if imgid:
                    # إدخال imgid و Ekey و iv في جدول EncryptionDetails
                    insert_encryption_details_query = text('''
                        INSERT INTO EncryptionDetails (ImgID, Ekey, iv)
                        VALUES (:imgid, :ekey, :iv)
                    ''')
                    connection.execute(insert_encryption_details_query, {
                        "imgid": imgid,
                        "ekey": Ekey,
                        "iv": iv
                    })
                else:
                    raise Exception("Failed to retrieve imgid after inserting image")

            ctk.CTkLabel(self, text="Image Encrypted and Uploaded Successfully!", font=("Arial", 18), text_color="green").pack(pady=20)
        except Exception as e:
            ctk.CTkLabel(self, text=f"Error: {e}", font=("Arial", 20), text_color="red").pack(pady=20)

    def show_photos_page(self):
        self.clear_frame()

        # Frame لعرض الصور
        photos_frame = ctk.CTkFrame(self)
        photos_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(photos_frame, text="Show Photos Page (Empty)", font=("Arial", 24)).pack(pady=10)
        ctk.CTkButton(photos_frame, text="Back", command=self.dashboard_page).pack(pady=10)


if __name__ == "__main__":
    app = App()
    app.mainloop()
