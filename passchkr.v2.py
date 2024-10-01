import re
import sys
import pyfiglet
import time  # Used to track the timestamp of the password
from collections import deque  # Used to store the last X passwords
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout
from PyQt5.QtGui import QColor, QPainter

# Constants for password expiration and password history
PASSWORD_EXPIRATION_DAYS = 90  # Example: 90 days expiration threshold
PASSWORD_HISTORY_LIMIT = 3  # Last 3 passwords should not be reused

# Store password data: last change timestamp and password history
user_password_data = {
    'last_password_change': None,
    'password_history': deque(maxlen=PASSWORD_HISTORY_LIMIT)  # Store the last 3 passwords
}

def create_banner(text):
    ascii_banner = pyfiglet.figlet_format(text)
    print(ascii_banner)

# NIST Password Guidelines
def check_nist_password_guidelines(password):
    nist_len = r'^.{8,}$'  
    nist_complexity = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$'  
    if re.match(nist_len, password) and re.match(nist_complexity, password):
        return True
    else:
        return False

# OWASP Password Guidelines
def check_owasp_password_guidelines(password):
    owasp_len = r'^.{12,}$'  
    owasp_complexity = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]*[^A-Za-z0-9][A-Za-z\d]*$'  
    if re.match(owasp_len, password) and re.match(owasp_complexity, password):
        return True
    else:
        return False

# Password Strength Check
def check_password_strength(password):
    length_strength = min(len(password) // 4, 3)  # Strength increases every 4 characters, capped at 4
    complexity_strength = 0

    if any(char.isupper() for char in password) and any(char.islower() for char in password):
        complexity_strength += 2
    if any(char.isdigit() for char in password):
        complexity_strength += 2
    if any(char in '@$!%*?&' for char in password):
        complexity_strength += 2
    
    total_strength = length_strength + complexity_strength
    return total_strength

# Check if password is expired
def is_password_expired():
    if user_password_data['last_password_change'] is None:
        return False
    # Calculate the number of days since the last password change
    current_time = time.time()
    days_since_change = (current_time - user_password_data['last_password_change']) / (60 * 60 * 24)
    return days_since_change > PASSWORD_EXPIRATION_DAYS

# Check if the password has been reused from the last X passwords
def is_password_reused(password):
    return password in user_password_data['password_history']

# Get the age of the password in days
def get_password_age():
    if user_password_data['last_password_change'] is None:
        return None
    current_time = time.time()
    days_since_change = (current_time - user_password_data['last_password_change']) / (60 * 60 * 24)
    return round(days_since_change, 2)  # Return age in days (rounded to 2 decimal places)

# Update password data when a new valid password is set
def update_password_data(password):
    # Update the last password change timestamp
    user_password_data['last_password_change'] = time.time()
    # Add the password to the history
    user_password_data['password_history'].append(password)

class PasswordPolicyChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        create_banner("Password Policy Checker")
        
        self.password_label = QLabel("Enter password to check:")
        self.password_entry = QLineEdit()
        self.check_button = QPushButton("Check Password")
        self.result_label = QLabel()
        self.strength_label = QLabel()

        self.check_button.clicked.connect(self.show_password_policy_result)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.check_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.strength_label)

        self.setLayout(layout)

        self.setWindowTitle("Password Policy Checker")
        self.show()

    def show_password_policy_result(self):
        password = self.password_entry.text()

        # Check if password is expired
        if is_password_expired():
            self.result_label.setText("Password expired! Please set a new password.")
            return
        
        # Check if password has been reused
        if is_password_reused(password):
            password_age = get_password_age()
            if password_age is not None:
                self.result_label.setText(f"Password reuse detected! The password has been in use for {password_age} days.")
            else:
                self.result_label.setText(f"Password reuse detected!")
            return

        # Check against password guidelines
        nist_result = check_nist_password_guidelines(password)
        owasp_result = check_owasp_password_guidelines(password)
        password_strength = check_password_strength(password)

        if nist_result and owasp_result:
            self.result_label.setText("Password satisfies both NIST and OWASP guidelines.")
            # Update password history and last change time
            update_password_data(password)
        elif nist_result:
            self.result_label.setText("Password satisfies NIST guidelines but not OWASP guidelines.")
        else:
            self.result_label.setText("Password does not satisfy NIST or OWASP guidelines.")

        self.strength_label.setText(f"Password Strength: {password_strength}")

        # Visualize password strength with colored bars
        self.strength_label.setStyleSheet(f"background-color: {self.get_color(password_strength)}")

    def get_color(self, strength):
        if strength >=0 and strength <=1:
            return "red"
        elif strength >=2 and strength <=3:
            return "orange"
        elif strength >=4 and strength <=5:
            return "yellow"
        elif strength > 5:
            return "green"

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PasswordPolicyChecker()
    sys.exit(app.exec_())
