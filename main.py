#pip install customtkinter
import customtkinter as ctk

ctk.set_appearance_mode("Dark")  # Options: "Light", "Dark", "System"
ctk.set_default_color_theme("blue")  # Other themes: "green", "dark-blue"

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

        ctk.CTkEntry(login_frame, placeholder_text="Username").pack(pady=10)
        ctk.CTkEntry(login_frame, placeholder_text="Password", show="*").pack(pady=10)

        ctk.CTkButton(login_frame, text="Login", command=self.login_action).pack(pady=10)
        ctk.CTkButton(login_frame, text="Register", command=self.register_page).pack(pady=10)

    def register_page(self):
        self.clear_frame()

        # Register Frame
        register_frame = ctk.CTkFrame(self)
        register_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(register_frame, text="Register", font=("Arial", 24)).pack(pady=10)

        # Input Fields
        fields = ["First Name", "Last Name", "Username", "Email", "Phone Number"]
        for field in fields:
            ctk.CTkEntry(register_frame, placeholder_text=field).pack(pady=5)

        # Password Fields
        ctk.CTkEntry(register_frame, placeholder_text="Password", show="*").pack(pady=5)
        ctk.CTkEntry(register_frame, placeholder_text="Confirm Password", show="*").pack(pady=5)

        # Gender Selection
        gender_label = ctk.CTkLabel(register_frame, text="Gender:")
        gender_label.pack(pady=(10, 0))

        gender_frame = ctk.CTkFrame(register_frame)
        gender_frame.pack(pady=5)
        gender_var = ctk.StringVar(value="Male")
        ctk.CTkRadioButton(gender_frame, text="Male", variable=gender_var, value="Male").pack(side="left", padx=5)
        ctk.CTkRadioButton(gender_frame, text="Female", variable=gender_var, value="Female").pack(side="left", padx=5)

        # Buttons
        ctk.CTkButton(register_frame, text="Register", command=self.register_action).pack(pady=10)
        ctk.CTkButton(register_frame, text="Back", command=self.login_page).pack(pady=10)

    def login_action(self):
        print("Logging in...")

    def register_action(self):
        print("Registering new user...")

if __name__ == "__main__":
    app = App()
    app.mainloop()
