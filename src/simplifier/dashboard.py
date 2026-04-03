from PyQt5.QtWidgets import QWidget, QGridLayout, QLabel, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QFrame
from src.simplifier.forms import AddUserForm, RemoveUserForm, PrivilegeForm, PasswordResetForm
from src.simplifier.ad_utils import ADUtils
import json
from PyQt5.QtCore import Qt

class SimplifierDashboard(QWidget):
    def __init__(self):
        super().__init__()
        
        self.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 14px;
                background-color: #fdfdfd;
            }
            QPushButton {
                padding: 10px;
                background-color: #0078D7;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005A9E;
            }
            QPushButton[destructive="true"] {
                background-color: #d13438;
            }
            QPushButton[destructive="true"]:hover {
                background-color: #a80000;
            }
        """)

        self.layout = QGridLayout()
        # Reduce margins and spacing to fix congestion
        self.layout.setContentsMargins(20, 20, 20, 10)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        
        # Add Forms directly (they are already CardFrames with titles)
        self.layout.addWidget(AddUserForm(), 0, 0)
        
        remove_form = RemoveUserForm()
        remove_form.btn.setProperty("destructive", True)
        self.layout.addWidget(remove_form, 0, 1)
        
        self.layout.addWidget(PrivilegeForm(), 1, 0)
        self.layout.addWidget(PasswordResetForm(), 1, 1)
        
        # Add AD User Directory as a uniform CardFrame
        dir_card = QFrame()
        dir_card.setObjectName("CardFrame")
        dir_card.setStyleSheet("""
            #CardFrame {
                background-color: white;
                border-radius: 10px;
                border: 1px solid #e0e0e0;
            }
        """)
        dir_layout = QVBoxLayout(dir_card)
        dir_layout.setContentsMargins(15, 15, 15, 15)
        dir_layout.setSpacing(10)
        
        title_label = QLabel("Active Directory User Overview")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        title_label.setAlignment(Qt.AlignCenter)
        dir_layout.addWidget(title_label)
        
        self.refresh_btn = QPushButton("Refresh Directory")
        self.refresh_btn.clicked.connect(self.refresh_directory)
        dir_layout.addWidget(self.refresh_btn)
        
        self.dir_table = QTableWidget()
        self.dir_table.setColumnCount(2)
        self.dir_table.setHorizontalHeaderLabels(["Username", "Assigned Groups/Privileges"])
        self.dir_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.dir_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.dir_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.dir_table.setStyleSheet("background-color: #ffffff; alternate-background-color: #f9f9f9;")
        self.dir_table.setAlternatingRowColors(True)
        dir_layout.addWidget(self.dir_table)
        
        self.layout.addWidget(dir_card, 2, 0, 1, 2)
        
        # Add basic info label at bottom
        info_label = QLabel("Note: Ensure you are running as Administrator for AD commands to work.")
        info_label.setStyleSheet("color: gray; font-style: italic; font-size: 12px;")
        info_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(info_label, 3, 0, 1, 2)
        
        # Load directory initially
        self.refresh_directory()

    def refresh_directory(self):
        self.refresh_btn.setText("Refreshing...")
        self.refresh_btn.setEnabled(False)
        self.dir_table.setRowCount(0)
        
        success, out, err = ADUtils.get_all_users_and_groups()
        if success and out:
            try:
                users = json.loads(out)
                if isinstance(users, dict):
                    users = [users]
                self.dir_table.setRowCount(len(users))
                for i, user in enumerate(users):
                    self.dir_table.setItem(i, 0, QTableWidgetItem(str(user.get("Name", ""))))
                    self.dir_table.setItem(i, 1, QTableWidgetItem(str(user.get("Groups", ""))))
            except Exception as e:
                print("Failed to parse AD users json:", e)
        
        self.refresh_btn.setText("Refresh Directory")
        self.refresh_btn.setEnabled(True)
