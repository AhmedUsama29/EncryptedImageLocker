import pyodbc
from sqlalchemy import create_engine, text
import customtkinter as ctk
from tkinter import filedialog  # For browsing files
from PIL import Image  # Import Pillow for image handling
import base64
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# إنشاء الاتصال بقاعدة البيانات
engine = create_engine('mssql+pyodbc://IIZEEX/ImageEncrytion?driver=ODBC+Driver+17+for+SQL+Server')
connection = engine.connect()

ctk.set_appearance_mode("Dark")  # خيارات المظهر
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

        self.gender_entry = ctk.CTkEntry(register_frame, placeholder_text="Gender (M/F)")
        self.gender_entry.pack(pady=5)

        # Buttons
        ctk.CTkButton(register_frame, text="Register", command=self.register_action).pack(pady=10)
        ctk.CTkButton(register_frame, text="Back", command=self.login_page).pack(pady=10)

    def login_action(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        query = text(''' 
            SELECT * 
            FROM Users
            WHERE Email = :email 
            AND Password = :password
        ''')

        result = connection.execute(query, {"email": email, "password": password}).fetchone()

        if result:
            self.user_id = result[0]  # استخدام الفهرس للوصول إلى الـ user_id
            self.dashboard_page()  # الانتقال إلى صفحة التحكم (Dashboard)
        else:
            ctk.CTkLabel(self, text="Invalid Email or Password", font=("Arial", 20), text_color="red").pack(pady=20)

    def register_action(self):
        first_name = self.first_name_entry.get().strip()
        last_name = self.last_name_entry.get().strip()
        username = self.username_entry.get().strip()
        email = self.email_register_entry.get().strip()
        phone = self.phone_entry.get().strip()
        password = self.password_register_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()
        gender = self.gender_entry.get().strip()

        # Check for required fields
        if not email or not password or not confirm_password or not username:
            ctk.CTkLabel(self, text="Required fields cannot be empty!", font=("Arial", 20), text_color="red").pack(pady=20)
            return

        # Check if passwords match
        if password != confirm_password:
            ctk.CTkLabel(self, text="Passwords do not match!", font=("Arial", 20), text_color="red").pack(pady=20)
            return

        # Insert user into the database
        try:
            query = text(''' 
                INSERT INTO Users (FName, LName, username, Email, PhoneNum, Password, Gender)
                VALUES (:first_name, :last_name, :username, :email, :phone, :password, :gender)
            ''')

            # Using a transaction with commit
            with engine.begin() as connection:  # Use a transactional connection
                connection.execute(query, {
                    "first_name": first_name,
                    "last_name": last_name,
                    "username": username,
                    "email": email,
                    "phone": phone,
                    "password": password,
                    "gender": gender
                })

            # Show success message briefly and return to login page
            ctk.CTkLabel(self, text="Registration Successful!", font=("Arial", 20), text_color="green").pack(pady=20)
            self.after(1500, self.login_page)  # Navigate to login page after 1.5 seconds

        except Exception as e:
            ctk.CTkLabel(self, text=f"Error: {e}", font=("Arial", 20), text_color="red").pack(pady=20)

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
        key = os.urandom(32)  # مفتاح عشوائي 256 بت
        iv = os.urandom(16)  # قيمة ابتدائية عشوائية
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # تأكد من أن حجم البيانات يكون مضاعفاً لحجم البلوك
        padded_data = image_data + b"\0" * (16 - len(image_data) % 16)

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return (encrypted_data, key, iv)

    def insert_encrypted_image_to_db(self, encrypted_image_data, image_path):
        encrypted_data, key, iv = encrypted_image_data

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
