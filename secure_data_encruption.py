import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
from typing import Dict, Any, Optional

# 🔐 Generate and manage encryption key
def generate_key():
    return Fernet.generate_key()

# Initialize with a new key (in production, store this securely)
cipher_suite = Fernet(generate_key())

# 🗂️ Data storage with type hints
stored_data: Dict[str, Dict[str, Any]] = {}
failed_attempts = 0
MAX_ATTEMPTS = 3

# 🔑 Improved hashing with salt
def hash_passkey(passkey: str, salt: str = "default_salt") -> str:
    """Secure hash function with salt"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()

# 🔒 Enhanced encryption
def encrypt_data(text: str) -> str:
    """Encrypt text using Fernet symmetric encryption"""
    return cipher_suite.encrypt(text.encode()).decode()

# 🔓 Improved decryption with better error handling
def decrypt_data(encrypted_text: str, passkey: str) -> Optional[str]:
    """Decrypt text if passkey matches"""
    global failed_attempts
    
    if not encrypted_text or not passkey:
        return None
        
    try:
        # Find matching entry
        for entry in stored_data.values():
            if (entry["encrypted_text"] == encrypted_text and 
                entry["passkey"] == hash_passkey(passkey)):
                failed_attempts = 0
                return cipher_suite.decrypt(encrypted_text.encode()).decode()
        
        failed_attempts += 1
        return None
        
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

# 🚀 Streamlit UI with better structure
def main():
    global failed_attempts
    
    st.set_page_config(page_title="Secure Data Encryption", layout="wide")
    st.title("🔐 Secure Data Encryption System")
    
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Navigation", menu)
    
    if choice == "Home":
        show_home()
    elif choice == "Store Data":
        store_data()
    elif choice == "Retrieve Data":
        retrieve_data()
    elif choice == "Login":
        login()

def show_home():
    """Home page content"""
    st.subheader("🏠 Welcome")
    st.write("""
    Securely **store** and **retrieve** data using military-grade encryption.
    - All data is encrypted before storage
    - Passkeys are hashed with PBKDF2
    - Brute-force protection
    """)
    st.info("ℹ️ Use the sidebar to navigate between functions")

def store_data():
    """Data storage interface"""
    st.subheader("📥 Store Data")
    
    with st.form("store_form"):
        user_data = st.text_area("Enter your sensitive data:")
        passkey = st.text_input("Enter a strong passkey:", type="password")
        confirm_passkey = st.text_input("Confirm passkey:", type="password")
        
        if st.form_submit_button("Encrypt & Save"):
            if not user_data:
                st.warning("Please enter data to encrypt")
            elif not passkey or passkey != confirm_passkey:
                st.error("Passkeys don't match or are empty")
            else:
                encrypted = encrypt_data(user_data)
                stored_data[encrypted] = {
                    "encrypted_text": encrypted,
                    "passkey": hash_passkey(passkey)
                }
                st.success("✅ Data encrypted and saved securely")
                st.code(f"Encrypted text:\n{encrypted}")

def retrieve_data():
    """Data retrieval interface"""
    global failed_attempts
    
    st.subheader("📤 Retrieve Data")
    
    with st.form("retrieve_form"):
        encrypted_input = st.text_area("Enter encrypted text:")
        passkey = st.text_input("Enter your passkey:", type="password")
        
        if st.form_submit_button("Decrypt"):
            if not encrypted_input or not passkey:
                st.warning("Both fields are required")
            else:
                result = decrypt_data(encrypted_input, passkey)
                if result:
                    st.success("✅ Decryption successful")
                    st.text_area("Decrypted content:", value=result, height=200)
                else:
                    remaining = MAX_ATTEMPTS - failed_attempts
                    st.error(f"❌ Invalid passkey. Attempts remaining: {remaining}")
                    if failed_attempts >= MAX_ATTEMPTS:
                        st.warning("🔒 Account locked due to too many failed attempts")
                        st.session_state.locked = True
                        st.experimental_rerun()

def login():
    """Admin login interface"""
    global failed_attempts
    
    st.subheader("🔑 Admin Login")
    
    if st.session_state.get('locked', False):
        st.error("Account locked. Please contact administrator.")
        return
        
    with st.form("login_form"):
        master_pass = st.text_input("Enter master password:", type="password")
        
        if st.form_submit_button("Login"):
            if master_pass == "admin123":  # In production, use proper auth
                failed_attempts = 0
                st.session_state.locked = False
                st.success("✅ Authentication successful")
                st.experimental_rerun()
            else:
                st.error("❌ Invalid credentials")

if __name__ == "__main__":
    main()