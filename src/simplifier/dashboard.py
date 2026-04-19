from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QFrame, QSplitter, QTreeWidget, QTreeWidgetItem, QCheckBox,
    QDateEdit, QTimeEdit, QComboBox, QLineEdit, QFileDialog, QMessageBox, QGridLayout,
    QScrollArea
)
from src.simplifier.forms import AddUserForm, RemoveUserForm, PrivilegeForm, PasswordResetForm
from src.simplifier.ad_utils import ADUtils
from src.utils.db_manager import AuditDB
from src.utils.pdf_generator import PDFGenerator
from src.gui.alert_widget import ToastNotification
import json
import pandas as pd
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QDateTime, QDate, QTime
from PyQt5.QtGui import QColor, QFont

# ─────────────────────────────────────────────────────────────────────────────
# Background thread: fetch AD users/groups
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
# Main Dashboard Widget
# ─────────────────────────────────────────────────────────────────────────────
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
            #CounterCard {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
        """)

        self.db = AuditDB()
        self.current_log_df = pd.DataFrame()

        # ── Outer scroll area (mirrors Forensics tab behaviour) ───────────────
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        outer_layout.addWidget(scroll_area)

        scroll_container = QWidget()
        scroll_area.setWidget(scroll_container)

        main_layout = QVBoxLayout(scroll_container)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)

        # ── 0. COUNTER CARDS ──────────────────────────────────────────────────
        main_layout.addLayout(self._build_counter_cards())

        # ── 1. ACTION FORMS (top row) ─────────────────────────────────────────
        top_layout = QHBoxLayout()
        top_layout.setSpacing(15)

        self.add_form    = AddUserForm()
        self.remove_form = RemoveUserForm()
        self.priv_form   = PrivilegeForm()
        self.reset_form  = PasswordResetForm()

        self.remove_form.btn.setProperty("destructive", True)

        for form in (self.add_form, self.remove_form, self.priv_form, self.reset_form):
            form.action_completed.connect(self.log_activity)
            top_layout.addWidget(form)

        main_layout.addLayout(top_layout, 1)

        # ── 2. MIDDLE SPLITTER (logs | tree) ─────────────────────────────────
        middle_splitter = QSplitter(Qt.Horizontal)

        # Left: Activity Log
        log_card = QFrame()
        log_card.setObjectName("CardFrame")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(10, 10, 10, 10)

        log_title = QLabel("User Activity Result Panel")
        log_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        log_layout.addWidget(log_title)

        # Filters
        filter_layout = QGridLayout()
        filter_layout.setSpacing(5)

        self.filter_from_date = QDateEdit()
        self.filter_from_date.setCalendarPopup(True)
        self.filter_from_date.setDate(QDate.currentDate().addDays(-7))

        self.filter_to_date = QDateEdit()
        self.filter_to_date.setCalendarPopup(True)
        self.filter_to_date.setDate(QDate.currentDate())

        self.filter_username = QLineEdit()
        self.filter_username.setPlaceholderText("Search Username...")

        self.filter_action = QComboBox()
        self.filter_action.addItems(["All", "Create User", "Remove User", "Reset Password", "Add to Group"])

        self.filter_status = QComboBox()
        self.filter_status.addItems(["All", "Success", "Failed"])

        self.btn_apply_filters = QPushButton("Filter")
        self.btn_apply_filters.clicked.connect(self.load_logs)

        self.btn_export_csv = QPushButton("Export Excel (.xlsx)")
        self.btn_export_csv.clicked.connect(self.export_excel)

        self.btn_export_pdf = QPushButton("Export PDF")
        self.btn_export_pdf.clicked.connect(self.export_pdf)

        filter_layout.addWidget(QLabel("From:"), 0, 0)
        filter_layout.addWidget(self.filter_from_date, 0, 1)
        filter_layout.addWidget(QLabel("To:"), 0, 2)
        filter_layout.addWidget(self.filter_to_date, 0, 3)
        filter_layout.addWidget(QLabel("Action:"), 0, 4)
        filter_layout.addWidget(self.filter_action, 0, 5)

        filter_layout.addWidget(QLabel("User:"), 1, 0)
        filter_layout.addWidget(self.filter_username, 1, 1, 1, 3)
        filter_layout.addWidget(QLabel("Status:"), 1, 4)
        filter_layout.addWidget(self.filter_status, 1, 5)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.btn_apply_filters)
        btn_layout.addWidget(self.btn_export_csv)
        btn_layout.addWidget(self.btn_export_pdf)

        log_layout.addLayout(filter_layout)
        log_layout.addLayout(btn_layout)

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(6)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Username", "Action", "Status", "Reason", "Description"])
        self.log_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.log_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setAlternatingRowColors(True)
        log_layout.addWidget(self.log_table)

        middle_splitter.addWidget(log_card)

        # Right: AD Tree
        tree_card = QFrame()
        tree_card.setObjectName("CardFrame")
        tree_layout = QVBoxLayout(tree_card)
        tree_layout.setContentsMargins(10, 10, 10, 10)

        tree_header_row = QHBoxLayout()
        tree_title = QLabel("Active Directory Structure")
        tree_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        tree_header_row.addWidget(tree_title)
        tree_header_row.addStretch()
        self.tree_refresh_btn = QPushButton("↻ Refresh")
        self.tree_refresh_btn.setMaximumWidth(90)
        self.tree_refresh_btn.clicked.connect(self.refresh_directory)
        tree_header_row.addWidget(self.tree_refresh_btn)
        tree_layout.addLayout(tree_header_row)

        self.ad_tree = QTreeWidget()
        self.ad_tree.setHeaderLabel("Domain / Groups / Users")
        tree_layout.addWidget(self.ad_tree)

        middle_splitter.addWidget(tree_card)
        middle_splitter.setSizes([560, 280])
        main_layout.addWidget(middle_splitter, 3)

        # ── 3. AUTHENTICATION MONITORING PANEL ───────────────────────────────
        #    Replaces the old "Active Directory User Overview" section
        auth_card = QFrame()
        auth_card.setObjectName("CardFrame")
        auth_layout = QVBoxLayout(auth_card)
        auth_layout.setContentsMargins(10, 10, 10, 10)

        auth_header = QHBoxLayout()
        auth_title = QLabel("🔐 Authentication Monitoring")
        auth_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        auth_header.addWidget(auth_title)
        auth_header.addStretch()

        self.auto_refresh_cb = QCheckBox("Auto Refresh (3s)")
        self.auto_refresh_cb.setChecked(True)
        self.auto_refresh_cb.stateChanged.connect(self.toggle_auto_refresh)
        auth_header.addWidget(self.auto_refresh_cb)

        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.setMinimumWidth(110)
        self.refresh_btn.clicked.connect(self.refresh_directory)
        auth_header.addWidget(self.refresh_btn)

        auth_layout.addLayout(auth_header)

        self.auth_table = QTableWidget()
        self.auth_table.setColumnCount(5)
        self.auth_table.setHorizontalHeaderLabels(["User", "Login Status", "Time", "Source System", "Action"])
        self.auth_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.auth_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.auth_table.setAlternatingRowColors(True)
        auth_layout.addWidget(self.auth_table)

        main_layout.addWidget(auth_card, 2)

        # Info label
        info_label = QLabel("Note: Ensure you are running as Administrator for AD commands to work.")
        info_label.setStyleSheet("color: gray; font-style: italic; font-size: 12px;")
        info_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(info_label)

        # ── Timers & background fetcher ───────────────────────────────────────
        self.fetcher = ADDataFetcher()
        self.fetcher.data_fetched.connect(self.on_data_fetched)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._auto_refresh_tick)
        self.timer.start(3000)  # 3 second interval

        self.refresh_directory()
        self.load_logs()
        self.load_auth_events()

    # ─────────────────────────────────────────────────────────────────────────
    # Counter Cards
    # ─────────────────────────────────────────────────────────────────────────
    def _build_counter_cards(self):
        row = QHBoxLayout()
        row.setSpacing(12)

        specs = [
            ("Total Actions",  "#0078D7", "lbl_total"),
            ("Successful",     "#28a745", "lbl_success"),
            ("Failed",         "#dc3545", "lbl_failed"),
        ]
        for title, color, attr in specs:
            card = QFrame()
            card.setObjectName("CounterCard")
            card.setFixedHeight(80)
            cl = QVBoxLayout(card)
            cl.setAlignment(Qt.AlignCenter)
            cl.setSpacing(2)

            count_lbl = QLabel("0")
            count_lbl.setAlignment(Qt.AlignCenter)
            count_lbl.setFont(QFont("Segoe UI", 22, QFont.Bold))
            count_lbl.setStyleSheet(f"color: {color}; background: transparent; border: none;")

            label_lbl = QLabel(title)
            label_lbl.setAlignment(Qt.AlignCenter)
            label_lbl.setStyleSheet("color: #555; font-size: 12px; background: transparent; border: none;")

            cl.addWidget(count_lbl)
            cl.addWidget(label_lbl)
            row.addWidget(card)
            setattr(self, attr, count_lbl)

        return row

    def _update_counters(self):
        total, success, failed = self.db.get_summary_counts()
        self.lbl_total.setText(str(total))
        self.lbl_success.setText(str(success))
        self.lbl_failed.setText(str(failed))

    # ─────────────────────────────────────────────────────────────────────────
    # Log Panel
    # ─────────────────────────────────────────────────────────────────────────
    def load_logs(self):
        from_date = self.filter_from_date.date().toString("yyyy-MM-dd")
        to_date   = self.filter_to_date.date().toString("yyyy-MM-dd")
        username  = self.filter_username.text().strip()
        action    = self.filter_action.currentText()
        status    = self.filter_status.currentText()

        self.current_log_df = self.db.get_logs(from_date, to_date, username, action, status)

        self.log_table.setRowCount(0)
        for _, row in self.current_log_df.iterrows():
            r = self.log_table.rowCount()
            self.log_table.insertRow(r)

            ts_item   = QTableWidgetItem(str(row.get('timestamp', '')))
            user_item = QTableWidgetItem(str(row.get('username', '')))
            act_item  = QTableWidgetItem(str(row.get('action', '')))
            st_val    = str(row.get('status', ''))
            st_item   = QTableWidgetItem(st_val)
            rsn_item  = QTableWidgetItem(str(row.get('reason', '')))
            desc_item = QTableWidgetItem(str(row.get('description', '')))

            # Color code by status
            if st_val == "Success":
                bg = QColor("#d4edda")
                st_item.setForeground(QColor("#155724"))
            elif st_val == "Failed":
                bg = QColor("#f8d7da")
                st_item.setForeground(QColor("#721c24"))
            else:
                bg = QColor("#fff3cd")
                st_item.setForeground(QColor("#856404"))

            for col, item in enumerate([ts_item, user_item, act_item, st_item, rsn_item, desc_item]):
                item.setBackground(bg)
                self.log_table.setItem(r, col, item)

        self.log_table.scrollToBottom()

    def export_excel(self):
        if self.current_log_df is None or self.current_log_df.empty:
            QMessageBox.warning(self, "Export Error", "No data to export. Please load logs first.")
            return
        PDFGenerator.export_audit_to_excel(self, self.current_log_df)

    def export_csv(self):
        # kept for backward compatibility — redirects to Excel
        self.export_excel()

    def export_pdf(self):
        if self.current_log_df is None or self.current_log_df.empty:
            QMessageBox.warning(self, "Export Error", "No data to export. Please load logs first.")
            return
        PDFGenerator.export_audit_to_pdf(self, self.current_log_df)

    # ─────────────────────────────────────────────────────────────────────────
    # Action Logging
    # ─────────────────────────────────────────────────────────────────────────
    def log_activity(self, entry):
        username    = entry.get("user", "")
        action      = entry.get("action", "")
        status      = entry.get("status", "")
        reason      = entry.get("reason", "")
        description = entry.get("description", "")

        # Guard: never log empty actions to DB
        if not username.strip() or not action.strip():
            return

        self.db.insert_log(username, action, status, reason, description)

        # Immediate UI updates
        self.load_logs()
        self._update_counters()
        self.load_auth_events()

        # Refresh tree immediately on successful AD changes
        if status == "Success":
            self.refresh_directory()

    # ─────────────────────────────────────────────────────────────────────────
    # Authentication Monitoring Panel
    # ─────────────────────────────────────────────────────────────────────────
    def load_auth_events(self):
        """Populate the Authentication Monitoring panel from the audit DB."""
        df = self.db.get_auth_events(limit=200)

        self.auth_table.setRowCount(0)
        if df.empty:
            # Show a placeholder row
            self.auth_table.insertRow(0)
            placeholder = QTableWidgetItem("No authentication events recorded yet.")
            placeholder.setForeground(QColor("#999"))
            self.auth_table.setItem(0, 0, placeholder)
            return

        for _, row in df.iterrows():
            r = self.auth_table.rowCount()
            self.auth_table.insertRow(r)

            username  = str(row.get('username', '—'))
            status    = str(row.get('status', '—'))
            timestamp = str(row.get('timestamp', '—'))
            action    = str(row.get('action', '—'))

            # Derive source system from action label
            if "Login" in action or "Logon" in action:
                source = "Windows Security"
            elif "Create" in action or "Remove" in action:
                source = "AD Simplifier"
            elif "Group" in action or "Privilege" in action:
                source = "Group Policy"
            elif "Password" in action or "Reset" in action:
                source = "AD Simplifier"
            else:
                source = "AD-IFMA"

            # Status display text
            if status == "Success":
                status_display = "✅ Success"
                bg = QColor("#d4edda")
                fg = QColor("#155724")
            elif status == "Failed":
                status_display = "❌ Failed"
                bg = QColor("#f8d7da")
                fg = QColor("#721c24")
            else:
                status_display = f"ℹ️ {status}"
                bg = QColor("#fff3cd")
                fg = QColor("#856404")

            items = [
                QTableWidgetItem(username),
                QTableWidgetItem(status_display),
                QTableWidgetItem(timestamp),
                QTableWidgetItem(source),
                QTableWidgetItem(action),
            ]
            for col, item in enumerate(items):
                item.setBackground(bg)
                if col == 1:
                    item.setForeground(fg)
                    item.setFont(QFont("Segoe UI", 9, QFont.Bold))
                self.auth_table.setItem(r, col, item)

        self.auth_table.scrollToTop()

    # ─────────────────────────────────────────────────────────────────────────
    # Timer / Auto refresh
    # ─────────────────────────────────────────────────────────────────────────
    def _auto_refresh_tick(self):
        """Called every 3 s by the timer — refreshes counters + auth panel."""
        self._update_counters()
        self.load_auth_events()
        self.refresh_directory()

    def toggle_auto_refresh(self):
        if self.auto_refresh_cb.isChecked():
            self.timer.start(3000)
        else:
            self.timer.stop()

    # ─────────────────────────────────────────────────────────────────────────
    # AD Directory / Tree
    # ─────────────────────────────────────────────────────────────────────────
    def refresh_directory(self):
        if not self.fetcher.isRunning():
            self.refresh_btn.setText("Refreshing…")
            self.refresh_btn.setEnabled(False)
            self.tree_refresh_btn.setEnabled(False)
            self.fetcher.start()

    def on_data_fetched(self, success, users):
        self.refresh_btn.setText("Refresh Now")
        self.refresh_btn.setEnabled(True)
        self.tree_refresh_btn.setEnabled(True)

        if not success:
            return

        # ── Build tree ────────────────────────────────────────────────────────
        group_map = {}
        for user in users:
            username   = str(user.get("Name", ""))
            groups_str = str(user.get("Groups", ""))

            if groups_str:
                for grp in [g.strip() for g in groups_str.split(",") if g.strip()]:
                    group_map.setdefault(grp, []).append(username)
            else:
                group_map.setdefault("No Group", []).append(username)

        # Preserve expansion state
        expanded_groups = set()
        domain_item = self.ad_tree.topLevelItem(0)
        if domain_item:
            for i in range(domain_item.childCount()):
                if domain_item.child(i).isExpanded():
                    grp_text = domain_item.child(i).text(0)
                    grp_name = grp_text.rsplit(" (", 1)[0]
                    expanded_groups.add(grp_name)
        else:
            expanded_groups.update(["Administrators", "Domain Admins", "Users"])

        self.ad_tree.clear()
        domain_node = QTreeWidgetItem(self.ad_tree, ["Domain (Local)"])
        domain_node.setExpanded(True)

        for grp, members in sorted(group_map.items()):
            grp_node = QTreeWidgetItem(domain_node, [f"{grp} ({len(members)})"])
            if grp in expanded_groups:
                grp_node.setExpanded(True)
            for member in sorted(members):
                QTreeWidgetItem(grp_node, [member])
