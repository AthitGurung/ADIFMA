from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, 
    QPushButton, QFrame, QSplitter, QTreeWidget, QTreeWidgetItem, QCheckBox
)
from src.simplifier.forms import AddUserForm, RemoveUserForm, PrivilegeForm, PasswordResetForm
from src.simplifier.ad_utils import ADUtils
import json
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QDateTime

class ADDataFetcher(QThread):
    data_fetched = pyqtSignal(bool, list)

    def run(self):
        success, out, err = ADUtils.get_all_users_and_groups()
        if success and out:
            try:
                users = json.loads(out)
                if isinstance(users, dict):
                    users = [users]
                self.data_fetched.emit(True, users)
            except Exception as e:
                print("Failed to parse AD users json:", e)
                self.data_fetched.emit(False, [])
        else:
            self.data_fetched.emit(False, [])

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
            QTreeWidget, QTableWidget {
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                background-color: white;
            }
            #CardFrame {
                background-color: white;
                border-radius: 10px;
                border: 1px solid #e0e0e0;
            }
        """)

        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(15, 15, 15, 15)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        
        # === TOP SECTION: FORMS ===
        top_layout = QHBoxLayout()
        top_layout.setSpacing(15)
        
        self.add_form = AddUserForm()
        self.remove_form = RemoveUserForm()
        self.priv_form = PrivilegeForm()
        self.reset_form = PasswordResetForm()
        
        self.remove_form.btn.setProperty("destructive", True)
        
        # Connect signals
        self.add_form.action_completed.connect(self.log_activity)
        self.remove_form.action_completed.connect(self.log_activity)
        self.priv_form.action_completed.connect(self.log_activity)
        self.reset_form.action_completed.connect(self.log_activity)
        
        top_layout.addWidget(self.add_form)
        top_layout.addWidget(self.remove_form)
        top_layout.addWidget(self.priv_form)
        top_layout.addWidget(self.reset_form)
        
        self.layout.addLayout(top_layout, 1)
        
        # === MIDDLE SECTION: SPLITTER (LOGS | TREE) ===
        middle_splitter = QSplitter(Qt.Horizontal)
        
        # Middle Left: User Activity Log
        log_card = QFrame()
        log_card.setObjectName("CardFrame")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(10, 10, 10, 10)
        log_title = QLabel("User Activity Result Panel")
        log_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        log_layout.addWidget(log_title)
        
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(5)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "User", "Action", "Status", "Reason"])
        self.log_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setAlternatingRowColors(True)
        log_layout.addWidget(self.log_table)
        
        middle_splitter.addWidget(log_card)
        
        # Middle Right: Tree View
        tree_card = QFrame()
        tree_card.setObjectName("CardFrame")
        tree_layout = QVBoxLayout(tree_card)
        tree_layout.setContentsMargins(10, 10, 10, 10)
        tree_title = QLabel("Active Directory Structure")
        tree_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        tree_layout.addWidget(tree_title)
        
        self.ad_tree = QTreeWidget()
        self.ad_tree.setHeaderLabel("Domain / Groups / Users")
        tree_layout.addWidget(self.ad_tree)
        
        middle_splitter.addWidget(tree_card)
        
        # Adjust Splitter Sizes
        middle_splitter.setSizes([500, 300])
        self.layout.addWidget(middle_splitter, 3)
        
        # === BOTTOM SECTION: AD DIRECTORY OVERVIEW ===
        dir_card = QFrame()
        dir_card.setObjectName("CardFrame")
        dir_layout = QVBoxLayout(dir_card)
        dir_layout.setContentsMargins(10, 10, 10, 10)
        
        bottom_header = QHBoxLayout()
        title_label = QLabel("Active Directory User Overview")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        bottom_header.addWidget(title_label)
        
        bottom_header.addStretch()
        
        self.auto_refresh_cb = QCheckBox("Enable Auto Refresh (5s)")
        self.auto_refresh_cb.setChecked(True)
        self.auto_refresh_cb.stateChanged.connect(self.toggle_auto_refresh)
        bottom_header.addWidget(self.auto_refresh_cb)
        
        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.setMinimumWidth(120)
        self.refresh_btn.clicked.connect(self.refresh_directory)
        bottom_header.addWidget(self.refresh_btn)
        
        dir_layout.addLayout(bottom_header)
        
        self.dir_table = QTableWidget()
        self.dir_table.setColumnCount(2)
        self.dir_table.setHorizontalHeaderLabels(["Username", "Assigned Groups"])
        self.dir_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.dir_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.dir_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.dir_table.setAlternatingRowColors(True)
        dir_layout.addWidget(self.dir_table)
        
        self.layout.addWidget(dir_card, 2)
        
        # Info Label
        info_label = QLabel("Note: Ensure you are running as Administrator for AD commands to work.")
        info_label.setStyleSheet("color: gray; font-style: italic; font-size: 12px;")
        info_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(info_label)
        
        # Background Fetching Setup
        self.fetcher = ADDataFetcher()
        self.fetcher.data_fetched.connect(self.on_data_fetched)
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_directory)
        self.timer.start(5000) # 5 seconds
        
        self.refresh_directory()

    def log_activity(self, entry):
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
        self.log_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.log_table.setItem(row, 1, QTableWidgetItem(str(entry.get("user", ""))))
        self.log_table.setItem(row, 2, QTableWidgetItem(str(entry.get("action", ""))))
        
        status_item = QTableWidgetItem(entry.get("status", ""))
        if entry.get("status") == "Success":
            status_item.setForeground(Qt.darkGreen)
        else:
            status_item.setForeground(Qt.darkRed)
        self.log_table.setItem(row, 3, status_item)
        
        self.log_table.setItem(row, 4, QTableWidgetItem(str(entry.get("reason", ""))))
        
        # Scroll to bottom
        self.log_table.scrollToBottom()
        # Trigger directory refresh immediately after an action
        if entry.get("status") == "Success":
            self.refresh_directory()

    def toggle_auto_refresh(self):
        if self.auto_refresh_cb.isChecked():
            self.timer.start(5000)
        else:
            self.timer.stop()

    def refresh_directory(self):
        if not self.fetcher.isRunning():
            self.refresh_btn.setText("Refreshing...")
            self.refresh_btn.setEnabled(False)
            self.fetcher.start()

    def on_data_fetched(self, success, users):
        self.refresh_btn.setText("Refresh Now")
        self.refresh_btn.setEnabled(True)
        if not success:
            return
            
        # Update Table
        self.dir_table.setRowCount(len(users))
        
        group_map = {} # Maps group_name to list of users
        
        for i, user in enumerate(users):
            username = str(user.get("Name", ""))
            groups_str = str(user.get("Groups", ""))
            
            self.dir_table.setItem(i, 0, QTableWidgetItem(username))
            self.dir_table.setItem(i, 1, QTableWidgetItem(groups_str))
            
            # Map users to groups for the tree
            if groups_str:
                for grp in [g.strip() for g in groups_str.split(",") if g.strip()]:
                    if grp not in group_map:
                        group_map[grp] = []
                    group_map[grp].append(username)
            else:
                if "No Group" not in group_map:
                    group_map["No Group"] = []
                group_map["No Group"].append(username)
                
        # Store expansion state
        expanded_groups = set()
        root = self.ad_tree.invisibleRootItem()
        domain_item = self.ad_tree.topLevelItem(0)
        if domain_item:
            for i in range(domain_item.childCount()):
                if domain_item.child(i).isExpanded():
                    # Extract group name without the "(N)" count
                    grp_text = domain_item.child(i).text(0)
                    grp_name = grp_text.rsplit(" (", 1)[0]
                    expanded_groups.add(grp_name)
        elif not domain_item:
            # First time load
            expanded_groups.update(["Administrators", "Domain Admins", "Users"])

        # Rebuild Tree
        self.ad_tree.clear()
        
        domain_node = QTreeWidgetItem(self.ad_tree, ["Domain (Local)"])
        domain_node.setExpanded(True)
        
        for grp, members in sorted(group_map.items()):
            grp_node = QTreeWidgetItem(domain_node, [f"{grp} ({len(members)})"])
            if grp in expanded_groups:
                grp_node.setExpanded(True)
                
            for member in sorted(members):
                QTreeWidgetItem(grp_node, [member])

