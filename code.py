
from kivy.app import App 
from kivy.uix.boxlayout import BoxLayout 
from kivy.uix.textinput import TextInput 
from kivy.uix.label import Label
from kivy.uix.button import Button
from Crypto.Cipher import AES 
from Crypto.Hash import SHA256 
import base64
import json
import os

# --- Helper Functions ---
def encrypt(message, password):
    key = SHA256.new(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt(ciphertext, password):
    try:
        key = SHA256.new(password.encode()).digest()
        raw = base64.b64decode(ciphertext)
        nonce = raw[:16]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt(raw[16:])
        return decrypted.decode()
    except:
        return "ERROR"

# --- GUI Layout ---
class PasswordManager(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.master_pass = ""
        self.file_path = "passwords.json"

        self.label = Label(text="Enter Master Password")
        self.add_widget(self.label)

        self.pass_input = TextInput(password=True, multiline=False)
        self.add_widget(self.pass_input)

        self.submit_btn = Button(text="Unlock")
        self.submit_btn.bind(on_press=self.unlock)
        self.add_widget(self.submit_btn)

    def unlock(self, instance):
        self.master_pass = self.pass_input.text
        self.clear_widgets()
        self.build_main_ui()

    def build_main_ui(self):
        self.add_widget(Label(text="Site Name"))
        self.site_input = TextInput()
        self.add_widget(self.site_input)

        self.add_widget(Label(text="Password"))
        self.password_input = TextInput()
        self.add_widget(self.password_input)

        save_btn = Button(text="Save Password")
        save_btn.bind(on_press=self.save_password)
        self.add_widget(save_btn)

        view_btn = Button(text="View All")
        view_btn.bind(on_press=self.view_passwords)
        self.add_widget(view_btn)

        self.result = Label(text="")
        self.add_widget(self.result)

    def save_password(self, instance):
        site = self.site_input.text
        pwd = self.password_input.text
        if not site or not pwd:
            self.result.text = "Fields cannot be empty."
            return
        enc_pwd = encrypt(pwd, self.master_pass)
        data = self.load_data()
        data[site] = enc_pwd
        with open(self.file_path, 'w') as f:
            json.dump(data, f)
        self.result.text = f"Saved password for {site}."

    def view_passwords(self, instance):
        data = self.load_data()
        output = ""
        for site, enc_pwd in data.items():
            dec_pwd = decrypt(enc_pwd, self.master_pass)
            output += f"{site}: {dec_pwd}\n"
        self.result.text = output or "No passwords stored."

    def load_data(self):
        if not os.path.exists(self.file_path):
            return {}
        with open(self.file_path, 'r') as f:
            return json.load(f)

class PasswordApp(App):
    def build(self):
        return PasswordManager()

if __name__ == "__main__":
    PasswordApp().run()
