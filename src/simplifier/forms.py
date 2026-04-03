from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QGroupBox, QMessageBox, QFrame
)
from src.simplifier.ad_utils import ADUtils
from PyQt5.QtCore import Qt

class BaseForm(QFrame):
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
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        
        # Title
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.title_label)
        
        # Form Layout
        self.form_layout = QVBoxLayout()
        self.form_layout.setSpacing(10)
        self.layout.addLayout(self.form_layout)

    def show_message(self, success, message, detail=""):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information if success else QMessageBox.Warning)
        msg.setWindowTitle("Result")
        msg.setText(message)
        if detail:
            msg.setInformativeText(detail)
        msg.exec_()

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
            self.show_message(False, "Username and Password are required.")
            return

        success, out, err = ADUtils.create_user(user, pwd, desc)
        if success:
            self.show_message(True, f"User '{user}' created successfully.")
            self.username_input.clear()
            self.password_input.clear()
            self.desc_input.clear()
        else:
            # Check for common password requirement error
            if "password" in err.lower() and ("requirement" in err.lower() or "complexity" in err.lower()):
                self.show_message(False, "Password requirement not met.", "Please ensure the password meets the length, complexity, and history requirements of the domain.")
            else:
                self.show_message(False, "Failed to create user.", err)

class RemoveUserForm(BaseForm):
    def __init__(self):
        super().__init__("Remove User")
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username to Remove")
        self.form_layout.addWidget(self.username_input)
        
        self.btn = QPushButton("Remove User")
        self.btn.setStyleSheet("background-color: #ffcccc;")
        self.btn.clicked.connect(self.execute)
        self.form_layout.addWidget(self.btn)
        
    def execute(self):
        user = self.username_input.text()
        
        if not user:
            self.show_message(False, "Username is required.")
            return

        # Verification dialog could be added here
        
        success, out, err = ADUtils.remove_user(user)
        if success:
            self.show_message(True, f"User '{user}' removed successfully.")
            self.username_input.clear()
        else:
            self.show_message(False, "Failed to remove user.", err)

class PrivilegeForm(BaseForm):
    def __init__(self):
        super().__init__("Escalate Privilege / Add to Group")
        
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
            self.show_message(False, "Username and Group are required.")
            return

        success, out, err = ADUtils.add_to_group(user, group)
        if success:
            self.show_message(True, f"User '{user}' added to '{group}'.")
            self.username_input.clear()
        else:
            self.show_message(False, "Failed to add user to group.", err)

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
        # ADUtils needs a function for this, we didn't add it explicitly yet but create_user does it.
        # We need Set-ADAccountPassword wrapper.
    def execute(self):
        user = self.username_input.text()
        pwd = self.password_input.text()
        
        if not user or not pwd:
            self.show_message(False, "Username and New Password are required.")
            return

        success, out, err = ADUtils.reset_password(user, pwd)
        if success:
            self.show_message(True, f"Password for '{user}' reset successfully.")
            self.username_input.clear()
            self.password_input.clear()
        else:
            self.show_message(False, "Failed to reset password.", err)
