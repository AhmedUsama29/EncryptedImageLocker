#pip install customtkinter
import customtkinter as ctk

ctk.set_appearance_mode("Dark")  # Options: "Light", "Dark", "System"
ctk.set_default_color_theme("blue")  # Other themes: "green", "dark-blue"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Login/Register")
        self.geometry("600x400")
        self.resizable(True, True)
        
        # Login Frame
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(self.login_frame, text="Login", font=("Arial", 24)).pack(pady=10)
        
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Username")
        self.username_entry.pack(pady=10)

        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=10)

        self.login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.login_action)
        self.login_button.pack(pady=10)

        self.register_button = ctk.CTkButton(self.login_frame, text="Register", command=self.show_register_page)
        self.register_button.pack(pady=10)
    
    def login_action(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        print(f"Logging in with {username}:{password}")

    def show_register_page(self):
        # Add transition/animation here for modern effects
        print("Switching to register page...")

if __name__ == "__main__":
    app = App()
    app.mainloop()
