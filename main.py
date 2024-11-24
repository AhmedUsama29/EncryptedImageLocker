import os
import base64
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk
from sqlalchemy import create_engine, text
import pyodbc
from PIL import Image , ImageTk
from io import BytesIO

# Database connection setup
engine = create_engine('mssql+pyodbc://IIZEEX/ImageEncrytion?driver=ODBC+Driver+17+for+SQL+Server')
connection = engine.connect()

ctk.set_appearance_mode("Light")  # Appearance options
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Image Locker")
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

        # Username/Email and Password fields
        self.email_or_username_entry = ctk.CTkEntry(login_frame, placeholder_text="Email or Username")
        self.email_or_username_entry.pack(pady=10)

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
        email_or_username = self.email_or_username_entry.get().strip()
        password = self.password_entry.get().strip()

        query = text('''
        SELECT Users.User_ID, Users.Password, PasswordEncryption.Pkey, PasswordEncryption.PIV
        FROM Users
        INNER JOIN PasswordEncryption ON Users.User_ID = PasswordEncryption.user_id
        WHERE Email = :email_or_username OR username = :email_or_username
        ''')
        
        result = connection.execute(query, {"email_or_username": email_or_username}).fetchone()

        if result:
            encrypted_password, Pkey_str, Piv_str = result[1], result[2], result[3]
            decrypted_password = self.decrypt_password(encrypted_password, Pkey_str, Piv_str)

            if decrypted_password == password:
                self.user_id = result[0]  # Get user_id
                self.dashboard_page()  # Navigate to Dashboard
            else:
                messagebox.showerror("Login Failed", "Invalid email/username or password!")
        else:
            messagebox.showerror("Login Failed", "Email/Username not found!")

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

        # عرض رسالة النجاح كـ pop-up
            messagebox.showinfo("Success", "Image Uploaded Successfully!")
        except Exception as e:
        # عرض رسالة الخطأ كـ pop-up
            messagebox.showerror("Error", f"Error: {e}")

    def decrypt_image(self, encrypted_data, ekey, iv):
    # إعداد التشفير لفك البيانات
        cipher = Cipher(algorithms.AES(ekey), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

    # فك التشفير
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # إزالة البادئة إذا كانت مضافة
        decrypted_data = decrypted_data.rstrip(b"\0")

        return decrypted_data
    
    def delete_image(self, img_id, img_frame):
        try:
            delete_image_query = text('''
                DELETE FROM Images WHERE ImgID = :img_id
            ''')

            with engine.connect() as connection:
                with connection.begin() as transaction:
                    result = connection.execute(delete_image_query, {"img_id": img_id})

                # تحقق من عدد الصفوف المتأثرة
                    if result.rowcount == 0:
                        messagebox.showerror("Error", "Image not found")
                    else:
                    # إزالة الصورة من الواجهة وإعادة تحميل البيانات
                        img_frame.destroy()
                    # ... (أضف هنا الكود الخاص بك لإعادة تحميل البيانات)
                        messagebox.showinfo("Success", "Image deleted successfully!")

                    transaction.commit()
        except Exception as e:
            print(f"Error occurred: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")



    def show_photos_page(self):
        self.clear_frame()

    # إعداد إطار رئيسي يشمل الصور وزر Back والعنوان
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=20)  # توسيع الإطار لملء النافذة

    # Canvas لإضافة التمرير
        canvas = ctk.CTkCanvas(container, highlightthickness=0)
        canvas.pack(side="left", fill='both', expand=True, padx=20, pady=20)  # توسيع canvas لملء الإطار

    # Scrollbar عمودي
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")

        photos_frame = ctk.CTkFrame(canvas)
        photos_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=photos_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

    # عنوان الصفحة
        title = ctk.CTkLabel(photos_frame, text="Photo Gallery", font=("Arial", 24))
        title.grid(row=0, column=0, padx=20, pady=10)

        try:
        # جلب الصور من قاعدة البيانات
            query = text('''
            SELECT i.ImgID, i.EncryptedText, i.Name, i.Size, i.Extention, ed.Ekey, ed.iv
            FROM Images i
            JOIN EncryptionDetails ed ON i.imgid = ed.ImgID
            WHERE i.User_Id = :user_id
            ''')

            with engine.connect() as connection:
                results = connection.execute(query, {"user_id": self.user_id}).fetchall()

            if not results:
                ctk.CTkLabel(photos_frame, text="No Photos Available", font=("Arial", 18), text_color="red").grid(row=1, column=0, pady=20)
                ctk.CTkButton(photos_frame, text="Back", command=self.dashboard_page).grid(row=2, column=0, pady=10)
                return

        # تحديد عدد الأعمدة بناءً على عرض النافذة
            container_width = container.winfo_width()
            image_width = 210  # عرض الصورة مع الهامش
            columns = max(7, container_width // image_width)  # تحديد عدد الأعمدة بناءً على عرض الإطار

            row = 1
            col = 0

            for result in results:
                img_id, encrypted_text, img_name, img_size, img_extension, ekey, iv = result

            # فك تشفير الصورة
                decrypted_image = self.decrypt_image(encrypted_text, ekey, iv)

            # تحويل البيانات إلى صورة
                image = Image.open(BytesIO(decrypted_image))
                image.thumbnail((200, 200))  # ضبط حجم الصور
                photo = ImageTk.PhotoImage(image)

            # إطار خاص لكل صورة
                img_frame = ctk.CTkFrame(photos_frame, width=200, height=250, corner_radius=10)
                img_frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")  # التأكد من توزيع المساحة بشكل صحيح

            # عرض الصورة
                label = ctk.CTkLabel(img_frame, image=photo, text="")
                label.photo = photo  # الاحتفاظ بالمراجع
                label.pack(pady=5)

            # زر التنزيل
                download_btn = ctk.CTkButton(
                    img_frame, text="⬇", width=50, 
                    command=lambda i=img_id: self.download_image(i)
                )
                download_btn.pack(side="left", padx=5)

            # زر المعلومات
                info_btn = ctk.CTkButton(
                    img_frame, text="ℹ", width=50, 
                    command=lambda n=img_name, s=img_size, e=img_extension: self.show_image_info(n, s, e)
                )
                info_btn.pack(side="right", padx=5)

            # زر الحذف
                delete_btn = ctk.CTkButton(
                    img_frame, text="❌", width=50, 
                    command=lambda i=img_id, f=img_frame: self.delete_image(i, f)
                )
                delete_btn.pack(side="bottom", padx=5)


            # تحديث الصفوف والأعمدة
                col += 1
                if col >= columns:
                    col = 0  # عندما نصل إلى 8 أعمدة، نبدأ صفًا جديدًا
                    row += 1  # الانتقال إلى الصف التالي

        # تحديد توزيع المساحة
            for i in range(columns):
                photos_frame.grid_columnconfigure(i, weight=1)  # التأكد من توزيع الأعمدة بشكل متساوي

        except Exception as e:
            ctk.CTkLabel(photos_frame, text=f"Error: {e}", font=("Arial", 20), text_color="red").grid(row=1, column=0, pady=20)

    # زر العودة إلى الصفحة الرئيسية
        back_button = ctk.CTkButton(photos_frame, text="Back", command=self.dashboard_page)
        back_button.grid(row=row + 1, column=0, pady=10)

    # التأكد من أن كل شيء متناسق مع التمرير
        container.update()


    def download_image(self, img_id):
        try:
            query = text('''
            SELECT i.EncryptedText, ed.Ekey, ed.iv
            FROM Images i
            JOIN EncryptionDetails ed ON i.imgid = ed.ImgID
            WHERE i.ImgID = :img_id
            ''')

            with engine.connect() as connection:
                result = connection.execute(query, {"img_id": img_id}).fetchone()

            if result:
                encrypted_text, ekey, iv = result
                decrypted_image = self.decrypt_image(encrypted_text, ekey, iv)

                # Save the image to a file
                save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
                if save_path:
                    with open(save_path, "wb") as file:
                        file.write(decrypted_image)
                    messagebox.showinfo("Download Successful", "Image downloaded successfully!")
            else:
                messagebox.showerror("Error", "Image not found!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def show_image_info(self, name, size, extension):
        info_message = f"Name: {name}\nSize: {size} bytes\nExtension: {extension}"
        messagebox.showinfo("Image Information", info_message)

    


if __name__ == "__main__":
    app = App()
    app.mainloop()
