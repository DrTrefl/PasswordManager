import pytest
import os
import tempfile
import shutil
import json
from unittest.mock import Mock, patch, MagicMock
import tkinter as tk
from cryptography.fernet import Fernet

try:
    from Password_ManagerTest import PasswordManager
except ImportError:
    pass

class TestPasswordManager:
    
    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def password_manager(self, temp_dir):
        pm = PasswordManager()
        pm.data_file = os.path.join(temp_dir, "test_passwords.dat")
        pm.config_file = os.path.join(temp_dir, "test_config.dat")
        return pm
    
    @pytest.fixture
    def initialized_password_manager(self, password_manager):

        master_password = "test_master_password_123"
        password_manager.save_master_password(master_password)
        password_manager.master_password = master_password
        
        salt = os.urandom(16)
        key = password_manager.derive_key(master_password, salt)
        password_manager.fernet = Fernet(key)
        
        password_manager.passwords = {
            "Gmail": {"email": "test@gmail.com", "password": "gmail_pass_123"},
            "Facebook": {"email": "user@facebook.com", "password": "fb_secure_456"},
            "GitHub": {"email": "dev@github.com", "password": "git_strong_789"}
        }
        return password_manager
    
    def test_hash_password(self, password_manager):
        password = "test_password_123"
        hashed = password_manager.hash_password(password)
        
        assert isinstance(hashed, str)
        assert len(hashed) > 0
        assert hashed != password
    
    def test_verify_password_correct(self, password_manager):
        password = "correct_password_123"
        hashed = password_manager.hash_password(password)
        
        assert password_manager.verify_password(hashed, password) is True
    
    def test_verify_password_incorrect(self, password_manager):
        password = "correct_password_123"
        wrong_password = "wrong_password_456"
        hashed = password_manager.hash_password(password)
        
        assert password_manager.verify_password(hashed, wrong_password) is False
    
    def test_derive_key(self, password_manager):
        password = "test_password"
        salt = os.urandom(16)
        
        key1 = password_manager.derive_key(password, salt)
        key2 = password_manager.derive_key(password, salt)
        
        assert key1 == key2
        assert len(key1) == 44
    
    def test_derive_key_different_salt(self, password_manager):
        password = "test_password"
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        
        key1 = password_manager.derive_key(password, salt1)
        key2 = password_manager.derive_key(password, salt2)
        
        assert key1 != key2
    
    def test_save_and_load_master_password(self, password_manager):
        password = "master_password_test_123"
        password_manager.save_master_password(password)
        
        stored_password, salt = password_manager.load_master_password()
        
        assert stored_password is not None
        assert salt is not None
        assert password_manager.verify_password(stored_password, password) is True
    
    def test_load_master_password_nonexistent(self, password_manager):
        stored_password, salt = password_manager.load_master_password()
        
        assert stored_password is None
        assert salt is None
    
    def test_encrypt_decrypt_data(self, password_manager):
        key = Fernet.generate_key()
        password_manager.fernet = Fernet(key)
        
        test_data = {
            "Gmail": {"email": "test@gmail.com", "password": "secret123"},
            "Facebook": {"email": "user@fb.com", "password": "fb_pass456"}
        }
        
        encrypted = password_manager.encrypt_data(test_data)
        decrypted = password_manager.decrypt_data(encrypted)
        
        assert decrypted == test_data
        assert isinstance(encrypted, bytes)
    
    def test_save_and_load_data(self, initialized_password_manager):
        pm = initialized_password_manager
        original_data = pm.passwords.copy()
        
        pm.save_data()
        pm.passwords = {}
        pm.load_data()
        
        assert pm.passwords == original_data
    
    def test_load_data_nonexistent_file(self, password_manager):
        key = Fernet.generate_key()
        password_manager.fernet = Fernet(key)
        
        password_manager.load_data()
        
        assert password_manager.passwords == {}
    
    def test_generate_password_default(self, password_manager):
        password = password_manager.generate_password()
        
        assert len(password) == 16
        assert isinstance(password, str)
        assert len(password) > 0
    
    def test_generate_password_custom_length(self, password_manager):
        lengths = [8, 12, 20, 32]
        
        for length in lengths:
            password = password_manager.generate_password(length=length)
            assert len(password) == length
    
    def test_generate_password_only_lowercase(self, password_manager):
        password = password_manager.generate_password(
            length=20,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False
        )
        
        assert password.islower()
        assert password.isalpha()
    
    def test_generate_password_only_digits(self, password_manager):
        password = password_manager.generate_password(
            length=10,
            use_uppercase=False,
            use_lowercase=False,
            use_symbols=False
        )
        
        assert password.isdigit()
    
    def test_generate_password_no_options_fallback(self, password_manager):
        password = password_manager.generate_password(
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            use_symbols=False
        )
        
        assert len(password) == 16
        assert any(c.isalpha() or c.isdigit() for c in password)
    
    def test_generate_password_uniqueness(self, password_manager):
        passwords = []
        for _ in range(10):
            password = password_manager.generate_password(length=16)
            passwords.append(password)
        
        assert len(set(passwords)) == len(passwords)


class TestPasswordManagerIntegration:
    
    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_full_workflow(self, temp_dir):
        pm = PasswordManager()
        pm.data_file = os.path.join(temp_dir, "test_passwords.dat")
        pm.config_file = os.path.join(temp_dir, "test_config.dat")
        
        master_password = "secure_master_123"
        pm.save_master_password(master_password)
        
        stored_password, salt = pm.load_master_password()
        assert pm.verify_password(stored_password, master_password)
        
        key = pm.derive_key(master_password, salt)
        pm.fernet = Fernet(key)
        pm.master_password = master_password
        
        pm.passwords = {
            "Gmail": {"email": "user@gmail.com", "password": "gmail_pass"},
            "Twitter": {"email": "user@twitter.com", "password": "twitter_pass"}
        }
        
        pm.save_data()
        
        pm2 = PasswordManager()
        pm2.data_file = pm.data_file
        pm2.config_file = pm.config_file
        
        stored_password2, salt2 = pm2.load_master_password()
        assert pm2.verify_password(stored_password2, master_password)
        
        key2 = pm2.derive_key(master_password, salt2)
        pm2.fernet = Fernet(key2)
        pm2.load_data()
        
        assert pm2.passwords == pm.passwords
    
    def test_wrong_master_password(self, temp_dir):
        pm = PasswordManager()
        pm.data_file = os.path.join(temp_dir, "test_passwords.dat")
        pm.config_file = os.path.join(temp_dir, "test_config.dat")
        
        master_password = "correct_password_123"
        pm.save_master_password(master_password)
        
        stored_password, salt = pm.load_master_password()
        wrong_password = "wrong_password_456"
        
        assert not pm.verify_password(stored_password, wrong_password)
    
    def test_change_master_password_workflow(self, temp_dir):
        pm = PasswordManager()
        pm.data_file = os.path.join(temp_dir, "test_passwords.dat")
        pm.config_file = os.path.join(temp_dir, "test_config.dat")
        
        old_password = "old_master_password_123"
        pm.save_master_password(old_password)
        
        stored_password, salt = pm.load_master_password()
        assert pm.verify_password(stored_password, old_password)
        
        new_password = "new_master_password_456"
        pm.save_master_password(new_password)
        
        stored_password_new, salt_new = pm.load_master_password()
        assert pm.verify_password(stored_password_new, new_password)
        assert not pm.verify_password(stored_password_new, old_password)


class TestPasswordManagerMocked:
    
    @pytest.fixture
    def password_manager(self):
        pm = PasswordManager()
        pm.data_file = "test_passwords.dat"
        pm.config_file = "test_config.dat"
        return pm
    
    @patch('tkinter.messagebox.showerror')
    @patch('tkinter.messagebox.showinfo')
    def test_gui_error_handling(self, mock_showinfo, mock_showerror, password_manager):
        pass
    
    def test_password_validation(self, password_manager):
        assert not self._validate_password_entry("", "test@email.com", "password123")
        assert not self._validate_password_entry("Platform", "", "password123")
        assert not self._validate_password_entry("Platform", "test@email.com", "")
        
        assert self._validate_password_entry("Gmail", "test@gmail.com", "secure123")
    
    def _validate_password_entry(self, platform, email, password):
        return bool(platform.strip() and email.strip() and password.strip())

class TestPasswordManagerPerformance:
    
    @pytest.fixture
    def password_manager(self):
        pm = PasswordManager()
        key = Fernet.generate_key()
        pm.fernet = Fernet(key)
        return pm
    
    def test_large_dataset_encryption(self, password_manager):
        import time
        
        large_dataset = {}
        for i in range(1000):
            large_dataset[f"Platform_{i}"] = {
                "email": f"user_{i}@example.com",
                "password": f"password_{i}_secure_123456"
            }
        
        start_time = time.time()
        encrypted = password_manager.encrypt_data(large_dataset)
        encryption_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = password_manager.decrypt_data(encrypted)
        decryption_time = time.time() - start_time
        
        assert encryption_time < 1.0
        assert decryption_time < 1.0
        assert decrypted == large_dataset
    
    def test_password_generation_performance(self, password_manager):
        import time
        
        start_time = time.time()
        passwords = []
        for _ in range(100):
            password = password_manager.generate_password(length=32)
            passwords.append(password)
        generation_time = time.time() - start_time
        
        assert generation_time < 1.0
        assert len(passwords) == 100
        assert len(set(passwords)) == 100

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    test_files = ["test_passwords.dat", "test_config.dat"]
    for file in test_files:
        if os.path.exists(file):
            os.remove(file)
    
    yield
    
    for file in test_files:
        if os.path.exists(file):
            os.remove(file)

@pytest.mark.parametrize("password_length", [8, 16, 24, 32, 64, 128])
def test_password_generation_lengths(password_length):
    pm = PasswordManager()
    password = pm.generate_password(length=password_length)
    assert len(password) == password_length


@pytest.mark.parametrize("master_password", [
    "short",
    "medium_length_password",
    "very_long_master_password_with_special_chars_123!@#",
    "🔒🔑🛡️",  # Unicode
    "password with spaces",
])
def test_master_password_variations(master_password):
    pm = PasswordManager()
    hashed = pm.hash_password(master_password)
    assert pm.verify_password(hashed, master_password)


if __name__ == "__main__":
    pytest.main(["-v", "--tb=short", __file__])