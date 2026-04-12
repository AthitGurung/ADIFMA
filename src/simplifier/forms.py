from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QGroupBox, QMessageBox, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from src.simplifier.ad_utils import ADUtils
import re

def validate_password(pwd):
    if len(pwd) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", pwd):
        return "Missing uppercase letter."
    if not re.search(r"[a-z]", pwd):
        return "Missing lowercase letter."
    if not re.search(r"[0-9]", pwd):
        return "Missing numeric digit."
    if not re.search(r"[!@#$%^&*()\-_+=~`\[\]{}|;:'\",.<>/?\\]", pwd):
        return "Missing special character."
    return None

def parse_ad_error(err, action=""):
    err_lower = err.lower()
    if action == "create_user":
        if "history" in err_lower or "previously" in err_lower:
            return "Password already used previously (history policy)."
        elif "already exists" in err_lower:
            return "Username already exists."
        elif "identity info provided is not valid" in err_lower or "format" in err_lower:
            return "Invalid username format."
        elif "password" in err_lower and ("requirement" in err_lower or "complexity" in err_lower):
            return "Password does not meet complexity requirements."
    elif action == "reset_pwd":
        if "history" in err_lower or "previously" in err_lower:
            return "Password reuse is not allowed."
        elif "password" in err_lower and ("requirement" in err_lower or "complexity" in err_lower):
            return "Password does not meet complexity requirements."
        elif "restriction" in err_lower or "access denied" in err_lower:
            return "Account restrictions or access denied."
    elif action == "add_group":
        if "cannot find an object with identity" in err_lower:
            if "group" in err_lower:
                return "Group does not exist."
            else:
                return "User not found or Group does not exist."
        elif "already a member" in err_lower:
            return "User already exists in the group."
        elif "access" in err_lower or "permission" in err_lower:
            return "Insufficient permissions."
    elif action == "remove_user":
        if "cannot find an object with identity" in err_lower:
            return "User does not exist."
        elif "access" in err_lower or "permission" in err_lower:
            return "Permission denied."
    
    # Generic fallback
    if err.strip():
        return err.strip().split('\n')[0] # First line of error
    return "Unknown error occurred."

class BaseForm(QFrame):
    action_completed = pyqtSignal(dict)

    def __init__(self, title):
        super().__init__()
        
        # Style as a card
        self.setObjectName("CardFrame")
        self.setStyleSheet("""
            #CardFrame {
                background-color: white;
                border-radius: 10px;
                border: 1px solid #e0e0e0;
            }
        """)
        
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(15, 15, 15, 15)
        self.layout.setSpacing(10)
        self.setLayout(self.layout)
        
        # Title
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.title_label)
        
        # Form Layout
        self.form_layout = QVBoxLayout()
        self.form_layout.setSpacing(8)
        self.layout.addLayout(self.form_layout)
        
        # Status Label
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.hide()
        self.layout.addWidget(self.status_label)

    def show_inline_message(self, success, action_name, target_user, reason=""):
        if success:
            self.status_label.setStyleSheet("color: #155724; background-color: #d4edda; padding: 5px; border-radius: 3px; font-weight: bold; font-size: 12px;")
            self.status_label.setText("Success")
        else:
            self.status_label.setStyleSheet("color: #721c24; background-color: #f8d7da; padding: 5px; border-radius: 3px; font-weight: bold; font-size: 12px;")
            self.status_label.setText(f"Error: {reason}")
            
        self.status_label.show()
        
        # Hide after 5 seconds
        QTimer.singleShot(5000, self.status_label.hide)
        
        # Emit signal to dashboard
        log_entry = {
            "user": target_user,
            "action": action_name,
            "status": "Success" if success else "Failed",
            "reason": reason if not success else ""
        }
        self.action_completed.emit(log_entry)

class AddUserForm(BaseForm):
    def __init__(self):
        super().__init__("Add New User")
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.form_layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.form_layout.addWidget(self.password_input)

        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("Description (Optional)")
        self.form_layout.addWidget(self.desc_input)
        
        self.btn = QPushButton("Create User")
        self.btn.clicked.connect(self.execute)
        self.form_layout.addWidget(self.btn)
        
    def execute(self):
        user = self.username_input.text()
        pwd = self.password_input.text()
        desc = self.desc_input.text()
        
        if not user or not pwd:
            self.show_inline_message(False, "Create User", user, "Username and Password are required.")
            return

        # Pre-validate password criteria
        pwd_error = validate_password(pwd)
        if pwd_error:
            self.show_inline_message(False, "Create User", user, pwd_error)
            return

        success, out, err = ADUtils.create_user(user, pwd, desc)
        if success:
            self.show_inline_message(True, "Create User", user)
            self.username_input.clear()
            self.password_input.clear()
            self.desc_input.clear()
        else:
            reason = parse_ad_error(err, "create_user")
            self.show_inline_message(False, "Create User", user, reason)

class RemoveUserForm(BaseForm):
    def __init__(self):
        super().__init__("Remove User")
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username to Remove")
        self.form_layout.addWidget(self.username_input)
        
        self.btn = QPushButton("Remove User")
        self.btn.setStyleSheet("background-color: #ffcccc; color: #a00000;")
        self.btn.clicked.connect(self.execute)
        self.form_layout.addWidget(self.btn)
        
    def execute(self):
        user = self.username_input.text()
        
        if not user:
            self.show_inline_message(False, "Remove User", user, "Username is required.")
            return

        success, out, err = ADUtils.remove_user(user)
        if success:
            self.show_inline_message(True, "Remove User", user)
            self.username_input.clear()
        else:
            reason = parse_ad_error(err, "remove_user")
            self.show_inline_message(False, "Remove User", user, reason)

class PrivilegeForm(BaseForm):
    def __init__(self):
        super().__init__("Escalate Privilege / Group")
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Target Username")
        self.form_layout.addWidget(self.username_input)
        
        self.group_input = QLineEdit()
        self.group_input.setPlaceholderText("Target Group (e.g. Administrators)")
        self.form_layout.addWidget(self.group_input)
        
        self.btn = QPushButton("Add to Group")
        self.btn.clicked.connect(self.execute)
        self.form_layout.addWidget(self.btn)
        
    def execute(self):
        user = self.username_input.text()
        group = self.group_input.text()
        
        if not user or not group:
            self.show_inline_message(False, "Add to Group", user, "Username and Group are required.")
            return

        success, out, err = ADUtils.add_to_group(user, group)
        if success:
            self.show_inline_message(True, "Add to Group", user)
            self.username_input.clear()
        else:
            reason = parse_ad_error(err, "add_group")
            self.show_inline_message(False, "Add to Group", user, reason)

class PasswordResetForm(BaseForm):
    def __init__(self):
        super().__init__("Reset User Password")
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Target Username")
        self.form_layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("New Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.form_layout.addWidget(self.password_input)
        
        self.btn = QPushButton("Reset Password")
        self.btn.clicked.connect(self.execute)
        self.form_layout.addWidget(self.btn)
        
    def execute(self):
        user = self.username_input.text()
        pwd = self.password_input.text()
        
        if not user or not pwd:
            self.show_inline_message(False, "Reset Password", user, "Username and New Password are required.")
            return

        # Pre-validate password criteria
        pwd_error = validate_password(pwd)
        if pwd_error:
            self.show_inline_message(False, "Reset Password", user, pwd_error)
            return

        success, out, err = ADUtils.reset_password(user, pwd)
        if success:
            self.show_inline_message(True, "Reset Password", user)
            self.username_input.clear()
            self.password_input.clear()
        else:
            reason = parse_ad_error(err, "reset_pwd")
            self.show_inline_message(False, "Reset Password", user, reason)
