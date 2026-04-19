from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTableWidget, QTableWidgetItem, QGroupBox, QHeaderView, QMessageBox, QFrame, QComboBox,
    QSystemTrayIcon, QStyle, QScrollArea, QListWidget, QListWidgetItem, QDateTimeEdit, QLineEdit, QSplitter
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QDate, QDateTime
from src.ingestion.log_collector import LogCollector
from src.parsing.event_parser import EventParser
from src.analysis.anomaly_detector import AnomalyDetector
import pandas as pd
import datetime
from datetime import timedelta
import pyqtgraph as pg
from src.utils.pdf_generator import PDFGenerator
from src.gui.pie_chart import PieChartWidget
from src.gui.alert_widget import ToastNotification

class CustomDateAxis(pg.AxisItem):
    def tickStrings(self, values, scale, spacing):
        try:
            if spacing >= 86400:
                fmt = "%Y-%m-%d"
            elif spacing >= 3600:
                fmt = "%Y-%m-%d %H:%M"
            else:
                fmt = "%H:%M:%S"
            return [datetime.datetime.fromtimestamp(value).strftime(fmt) for value in values]
        except (ValueError, OSError, OverflowError):
            return [""] * len(values)

# Worker Thread for Analysis to avoid freezing UI
class AnalysisWorker(QThread):
    finished = pyqtSignal(dict) # Returns a dict of DataFrames

    def __init__(self, time_filter="All Time"):
        super().__init__()
        self.time_filter = time_filter

    def run(self):
        results = {}
        events = []
        
        # Read Real Logs
        collector = LogCollector()
        # Read last 2000 events for performance in demo
        try:
            gen = collector.read_logs()
            count = 0
            for evt in gen:
                events.append(evt)
                count += 1
                if count >= 2000: 
                    break
        except Exception as e:
            print(f"Error reading logs: {e}")

        # Parse
        parsed = []
        for evt in events:
             parsed.append(EventParser.parse_event(evt))
        
        df = EventParser.events_to_dataframe(parsed)
        
        # Filter by time if needed
        if not df.empty and self.time_filter != "All Time":
            df['Time'] = pd.to_datetime(df['Time'])
            now = datetime.now()
            if self.time_filter == "Last 1 hour":
                df = df[df['Time'] >= now - timedelta(hours=1)]
            elif self.time_filter == "Last 24 hours":
                df = df[df['Time'] >= now - timedelta(hours=24)]
            elif self.time_filter == "Last 7 days":
                df = df[df['Time'] >= now - timedelta(days=7)]
                
        detector = AnomalyDetector(df)

        # Detect
        results['brute_force'] = detector.detect_brute_force()
        results['privilege'] = detector.detect_new_admin_creation()
        results['user_creation'] = detector.detect_user_creation()
        results['password_change'] = detector.detect_password_changes()
        results['account_mods'] = detector.detect_account_modifications()
        results['authentication'] = detector.detect_authentication_events()
        results['successful_logins'] = detector.detect_successful_logins()
        
        # Aggregate for Timeline
        timeline_events = []
        
        # Add Brute Force Events
        if not results['brute_force'].empty:
            for _, row in results['brute_force'].iterrows():
                timeline_events.append({
                    'Time': row['Time'],
                    'Type': 'Brute Force Attempt',
                    'Actor': 'Unknown',
                    'Target': row['User'],
                    'Description': f"{row['Count']} failed logins"
                })
                
        # Add Privilege Escalation
        if not results['privilege'].empty:
            for _, row in results['privilege'].iterrows():
                timeline_events.append({
                    'Time': row['Time'],
                    'Type': 'Privilege Escalation',
                    'Actor': 'System/Admin', 
                    'Target': row['MemberAdded'],
                    'Description': f"Added to {row['TargetGroup']}"
                })
                
        # Add User Creation
        if not results['user_creation'].empty:
            for _, row in results['user_creation'].iterrows():
                timeline_events.append({
                    'Time': row['Time'],
                    'Type': 'User Creation',
                    'Actor': 'System/Admin',
                    'Target': row['CreatedUser'],
                    'Description': 'New domain/local user created'
                })
                
        # Add Password Changes
        if not results['password_change'].empty:
            for _, row in results['password_change'].iterrows():
                timeline_events.append({
                    'Time': row['Time'],
                    'Type': row['Type'],
                    'Actor': 'System/Admin',
                    'Target': row['TargetUser'],
                    'Description': 'Password Reset / Change'
                })

        # Add Account Modifications
        if not results['account_mods'].empty:
            for _, row in results['account_mods'].iterrows():
                timeline_events.append({
                    'Time': row['Time'],
                    'Type': row['Type'],
                    'Actor': 'System/Admin',
                    'Target': row['TargetUser'],
                    'Description': 'Account Modification or Deletion'
                })
                
        # Add Authentication Events (Failed & Lockouts)
        if not results['authentication'].empty:
            for _, row in results['authentication'].iterrows():
                timeline_events.append({
                    'Time': row['Time'],
                    'Type': row['Type'],
                    'Actor': 'System/Admin',
                    'Target': row['TargetUser'],
                    'Description': 'Failed Logon or Account Lockout'
                })
                
        # Add Successful Logins
        if not results['successful_logins'].empty:
            for _, row in results['successful_logins'].iterrows():
                timeline_events.append({
                    'Time': row['Time'],
                    'Type': row['Type'],
                    'Actor': 'System/Admin',
                    'Target': row['TargetUser'],
                    'Description': 'Successful Logon'
                })

        if timeline_events:
            timeline_df = pd.DataFrame(timeline_events)
            
            # Filter completely invalid target references explicitly just in case anomaly_detector missed some
            timeline_df = timeline_df.dropna(subset=['Target'])
            timeline_df = timeline_df[timeline_df['Target'] != 'Unknown']
            
            # Ensure sorting by time
            timeline_df['Time'] = pd.to_datetime(timeline_df['Time'])
            
            # Drop pure duplicates (e.g., redundant identical events in same millisecond boundary)
            timeline_df = timeline_df.drop_duplicates(subset=['Time', 'Type', 'Target'])
            
            timeline_df = timeline_df.sort_values(by='Time', ascending=False) # Newest first for table
            results['timeline'] = timeline_df
        else:
            results['timeline'] = pd.DataFrame(columns=['Time', 'Type', 'Actor', 'Target', 'Description'])
            
        self.finished.emit(results)


class ForensicsDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.current_timeline_df = pd.DataFrame()
        self.current_view = "Main Dashboard (Overall Incidents)"
        self.alert_cooldowns = {}  # key: (Type, Target), val: last toast timestamp
        self.init_ui()

    def init_ui(self):
        # Global Styles for Forensics Dashboard
        self.setStyleSheet("""
            QFrame#SummaryCard {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
            QLabel#CountLabel {
                font-size: 36px;
                font-weight: bold;
            }
            QLabel#TitleLabel {
                font-size: 14px;
                color: #555555;
            }
            QTableWidget {
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                gridline-color: #f0f0f0;
                background-color: white;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 4px;
                border: none;
                border-bottom: 1px solid #e0e0e0;
                font-weight: bold;
            }
            QPushButton#RunBtn {
                padding: 10px 20px;
                background-color: #0078D7;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton#RunBtn:hover {
                background-color: #005A9E;
            }
        """)

        root_layout = QHBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        
        # --- LEFT SIDE NAVIGATION MENU ---
        nav_menu = QListWidget()
        nav_menu.setMaximumWidth(250)
        nav_menu.setStyleSheet("""
            QListWidget {
                background-color: #2b2b2b;
                color: #e0e0e0;
                font-size: 14px;
                border: none;
            }
            QListWidget::item {
                padding: 15px;
                border-bottom: 1px solid #444;
            }
            QListWidget::item:selected {
                background-color: #0078D7;
                color: white;
                font-weight: bold;
            }
            QListWidget::item:hover {
                background-color: #3f3f3f;
            }
        """)
        
        menu_items = [
            "Main Dashboard (Overall Incidents)",
            "Security Incidents",
            "Privilege Escalation Incidents",
            "User Account Changes"
        ]
        self.nav_menu = nav_menu
        self.nav_menu.addItems(menu_items)
        self.nav_menu.setCurrentRow(0)
        self.nav_menu.currentTextChanged.connect(self.on_menu_changed)
        root_layout.addWidget(self.nav_menu)
        
        # Main scrollable content area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        root_layout.addWidget(scroll)
        
        main_container = QWidget()
        scroll.setWidget(main_container)
        
        layout = QVBoxLayout(main_container)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Setup Timer for Live Updates
        self.live_timer = QTimer(self)
        self.live_timer.timeout.connect(self.run_analysis_silent)

        # --- SUMMARY CARDS ---
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(15)
        
        self.card_bf, self.lbl_bf_count = self.create_summary_card("Incidents Detected")
        self.card_priv, self.lbl_priv_count = self.create_summary_card("Privilege Escalation")
        self.card_create, self.lbl_create_count = self.create_summary_card("User Creations")
        self.card_pw, self.lbl_pw_count = self.create_summary_card("Password Changes")
        
        summary_layout.addWidget(self.card_bf)
        summary_layout.addWidget(self.card_priv)
        summary_layout.addWidget(self.card_create)
        summary_layout.addWidget(self.card_pw)
        
        layout.addLayout(summary_layout)

        # --- CHARTS SECTION ---
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(20)
        
        # Pie Chart Group
        pie_group = QFrame()
        pie_group.setObjectName("SummaryCard")
        pie_layout = QVBoxLayout(pie_group)
        pie_layout.setContentsMargins(15, 15, 15, 15)
        
        pie_title = QLabel("Attack Distribution")
        pie_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        pie_layout.addWidget(pie_title)
        
        self.pie_chart = PieChartWidget()
        pie_layout.addWidget(self.pie_chart)
        pie_group.setMinimumWidth(300)
        
        # --- VISUAL TIMELINE CHART ---
        chart_group = QFrame()
        chart_group.setObjectName("SummaryCard")
        chart_layout = QVBoxLayout(chart_group)
        chart_layout.setContentsMargins(15, 15, 15, 15)
        
        chart_header = QHBoxLayout()
        self.chart_title = QLabel("Incident Timeline Chart")
        self.chart_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        
        self.date_range_label = QLabel("Viewing: -")
        self.date_range_label.setStyleSheet("font-size: 14px; color: #666; font-weight: bold;")
        
        self.status_label = QLabel("Live Analysis Active... (Updating)")
        self.status_label.setStyleSheet("font-size: 14px; color: #28a745; font-weight: bold;")
        
        chart_header.addWidget(self.chart_title)
        chart_header.addStretch()
        chart_header.addWidget(self.date_range_label)
        chart_header.addStretch()
        chart_header.addWidget(self.status_label)
        
        chart_layout.addLayout(chart_header)
        
        # Setup PyQtGraph Chart
        time_axis = CustomDateAxis(orientation='bottom')
        time_axis.enableAutoSIPrefix(False)
        self.plot_widget = pg.PlotWidget(axisItems={'bottom': time_axis})
        self.plot_widget.setMinimumHeight(300) # Increased height
        self.plot_widget.setBackground('w')
        self.plot_widget.setLabel('left', "Event Count", color='#333')
        self.plot_widget.setLabel('bottom', "Time Occurred", color='#333')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setMouseEnabled(x=True, y=False)
        self.plot_widget.setMenuEnabled(False)
        self.plot_widget.hideButtons()
        self.plot_widget.addLegend()
        
        # Setup Today / Live Activity Marker
        self.today_marker = pg.InfiniteLine(angle=90, movable=False, pen=pg.mkPen(color=(40, 167, 69), width=2, style=Qt.DashLine))
        self.plot_widget.addItem(self.today_marker)
        
        # Connect ViewBox Range Changed
        self.plot_widget.getViewBox().sigXRangeChanged.connect(self.update_date_range_label)
        
        # Setup Hover Tooltip for Scatter
        self.crosshair_v = pg.InfiniteLine(angle=90, movable=False, pen=pg.mkPen(color='gray', style=Qt.DashLine))
        self.plot_widget.addItem(self.crosshair_v)
        
        self.tooltip = pg.TextItem(text="", color=(50, 50, 50), fill=(255, 255, 255, 220), border=(150, 150, 150), anchor=(0, 1))
        self.plot_widget.addItem(self.tooltip)
        self.tooltip.hide()
        
        # Connect mouse movement
        self.proxy = pg.SignalProxy(self.plot_widget.scene().sigMouseMoved, rateLimit=60, slot=self.mouse_moved)
        
        chart_layout.addWidget(self.plot_widget)
        
        charts_layout.addWidget(pie_group, 1) # strech 1
        charts_layout.addWidget(chart_group, 3) # strech 3 (timeline is wider)
        layout.addLayout(charts_layout)

        # --- UNIFIED INCIDENT TABLE ---
        table_group = QFrame()
        table_group.setObjectName("SummaryCard")
        table_layout = QVBoxLayout(table_group)
        table_layout.setContentsMargins(15, 15, 15, 15)
        
        table_title = QLabel("Recent Security Events")
        table_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        table_layout.addWidget(table_title)
        
        # --- FILTERS ---
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("From:"))
        self.dt_from = QDateTimeEdit(QDateTime.currentDateTime().addDays(-7))
        self.dt_from.setCalendarPopup(True)
        self.dt_from.setDisplayFormat("yyyy-MM-dd HH:mm")
        filter_layout.addWidget(self.dt_from)
        
        filter_layout.addWidget(QLabel("To:"))
        self.dt_to = QDateTimeEdit(QDateTime.currentDateTime())
        self.dt_to.setCalendarPopup(True)
        self.dt_to.setDisplayFormat("yyyy-MM-dd HH:mm")
        filter_layout.addWidget(self.dt_to)
        
        self.search_user = QLineEdit()
        self.search_user.setPlaceholderText("Search Username...")
        filter_layout.addWidget(self.search_user)
        
        self.action_combo = QComboBox()
        self.action_combo.addItems(["All Actions", "Brute Force Attempt", "Privilege Escalation", "User Creation", "User Deleted", "Account Modified", "Failed Logon", "Account Lockout", "Successful Logon", "Password Change", "Password Reset"])
        filter_layout.addWidget(self.action_combo)
        
        self.status_combo = QComboBox()
        self.status_combo.addItems(["All Statuses", "Success", "Failed", "Information"])
        filter_layout.addWidget(self.status_combo)
        
        filter_btn = QPushButton("Apply Filters")
        filter_btn.clicked.connect(self.update_ui_with_data)
        filter_layout.addWidget(filter_btn)
        
        table_layout.addLayout(filter_layout)
        
        self.table_timeline = self.create_table(["Time", "Event Type", "Actor", "Target", "Status", "Description"])
        self.table_timeline.setMinimumHeight(400) # Force scroll bar by insisting on size
        self.table_timeline.itemSelectionChanged.connect(self.on_table_row_clicked)
        table_layout.addWidget(self.table_timeline)
        
        btn_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export Forensic Report (PDF)")
        self.export_btn.setObjectName("RunBtn")
        self.export_btn.clicked.connect(self.export_pdf)
        btn_layout.addWidget(self.export_btn)
        
        self.export_csv_btn = QPushButton("Export Excel (.xlsx)")
        self.export_csv_btn.setObjectName("RunBtn")
        self.export_csv_btn.clicked.connect(self.export_csv)
        btn_layout.addWidget(self.export_csv_btn)
        
        table_layout.addLayout(btn_layout)
        
        layout.addWidget(table_group)

        # System Tray Icon for Notifications
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.tray_icon.show()

        self.run_analysis_silent()
        self.live_timer.start(5000)

    def on_menu_changed(self, current_text):
        if current_text:
            self.current_view = current_text
            self.update_ui_with_data()

    def update_date_range_label(self, view_box, x_range):
        try:
            start_dt = datetime.datetime.fromtimestamp(x_range[0])
            end_dt = datetime.datetime.fromtimestamp(x_range[1])
            diff = x_range[1] - x_range[0]
            if diff <= 86400 * 2: # < 2 days
                label_text = f"Viewing: {start_dt.strftime('%b %d, %Y')} | {start_dt.strftime('%H:%M')} - {end_dt.strftime('%H:%M')}"
            else:
                label_text = f"Viewing: {start_dt.strftime('%b %d, %Y')} - {end_dt.strftime('%b %d, %Y')}"
            self.date_range_label.setText(label_text)
        except Exception:
            pass

    def mouse_moved(self, evt):
        pos = evt[0]  # Qt coordinates
        if self.plot_widget.sceneBoundingRect().contains(pos):
            mousePoint = self.plot_widget.plotItem.vb.mapSceneToView(pos)
            x_val = mousePoint.x()
            
            self.crosshair_v.setPos(x_val)
            
            if self.current_timeline_df.empty:
                self.tooltip.hide()
                return
                
            df = self.current_timeline_df
            
            # Get current zoom level ratio to determine valid hover distance
            view_range = self.plot_widget.getViewBox().viewRange()[0]
            range_span = view_range[1] - view_range[0]
            # Assure threshold is at least 5 minutes to capture binned points
            threshold = max(range_span * 0.02, 300) 

            try:
                nearby_events = df[abs(df['UnixTime'] - x_val) < threshold]
                
                if not nearby_events.empty:
                    self.tooltip.show()
                    dt_peak = nearby_events.iloc[0]['Time'].strftime('%Y-%m-%d %H:%M')
                    
                    event_colors = {
                        'Brute Force Attempt': '#dc3545',
                        'Privilege Escalation': '#28a745',
                        'User Creation': '#007bff',
                        'Password Reset': '#fd7e14',
                        'Password Change': '#fd7e14',
                        'Account Lockout': '#6f42c1'
                    }
                    
                    categories = {
                        'Brute Force Attempt': 'Authentication',
                        'Privilege Escalation': 'Account Management',
                        'User Creation': 'Account Management',
                        'Password Change': 'Account Management',
                        'Password Reset': 'Account Management',
                        'Account Lockout': 'Authentication'
                    }
                    
                    if self.current_view == "Main Dashboard (Overall Incidents)":
                        total_incidents = len(nearby_events)
                        type_counts = nearby_events['Type'].value_counts()
                        dom_type = type_counts.idxmax()
                        
                        multi_txt = ""
                        for t, c in type_counts.items():
                            c_color = event_colors.get(t, '#333333')
                            multi_txt += f" - {c}x <span style='color:{c_color}; font-weight:bold;'>{t}</span><br>"
                        
                        tool_text = (
                            f"<b>Peak Time:</b> {dt_peak}<br>"
                            f"<b>Total Incidents:</b> {total_incidents}<br>"
                            f"<b>Dominant Type:</b> {dom_type}<br>"
                            f"<b>Breakdown:</b><br>{multi_txt}"
                        )
                    else:
                        total = len(nearby_events)
                        closest = nearby_events.iloc[(nearby_events['UnixTime'] - x_val).abs().argsort()[:1]]
                        row = closest.iloc[0]
                        ev_type = row['Type']
                        ev_color = event_colors.get(ev_type, '#333333')
                        cat = categories.get(ev_type, 'System Event')
                        
                        tool_text = (
                            f"<b>Time:</b> {row['Time'].strftime('%Y-%m-%d %H:%M:%S')}<br>"
                            f"<b>Incidents:</b> {total}<br>"
                            f"<b>Type:</b> <span style='color:{ev_color}; font-weight:bold;'>{ev_type}</span><br>"
                            f"<b>Category:</b> {cat}<br>"
                            f"<b>Target:</b> {row['Target']}<br>"
                            f"<b>Description:</b> {row['Description']}"
                        )
                    self.tooltip.setHtml(tool_text)
                    self.tooltip.setPos(x_val, mousePoint.y())
                else:
                    self.tooltip.hide()
            except Exception as e:
                print(f"Tooltip Error: {e}")
                self.tooltip.hide()
        else:
            self.tooltip.hide()

    def export_pdf(self):
        df_to_export = getattr(self, 'filtered_df', self.current_timeline_df)
        if df_to_export is None or df_to_export.empty:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Export Error", "No data to export. Run analysis first.")
            return
        PDFGenerator.export_to_pdf(self, df_to_export, self.current_view)

    def export_csv(self):
        df_to_export = getattr(self, 'filtered_df', self.current_timeline_df)
        if df_to_export is None or df_to_export.empty:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Export Error", "No data to export. Run analysis first.")
            return
        PDFGenerator.export_to_csv(self, df_to_export)
        
    def on_table_row_clicked(self):
        items = self.table_timeline.selectedItems()
        if not items:
            return
            
        time_item = self.table_timeline.item(items[0].row(), 0)
        time_val = time_item.data(Qt.UserRole)
        
        if pd.notna(time_val):
            ts = time_val.timestamp()
            # Smooth pan/zoom to the timestamp with a +/- 15 min window
            self.plot_widget.setXRange(ts - 900, ts + 900, padding=0)
            
            # Position crosshair directly on the event
            self.crosshair_v.setPos(ts)
            
            # Show tooltip for the clicked row
            df = self.current_timeline_df
            if not df.empty and 'UnixTime' in df.columns:
                nearby = df[abs(df['UnixTime'] - ts) < 1.0]
                if not nearby.empty:
                    row = nearby.iloc[0]
                    self.tooltip.show()
                    tool_text = (
                        f"<b>Time:</b> {row['Time'].strftime('%Y-%m-%d %H:%M:%S')}<br>"
                        f"<b>Type:</b> <span style='font-weight:bold;'>{row['Type']}</span><br>"
                        f"<b>Target:</b> {row['Target']}<br>"
                        f"<b>Description:</b> {row['Description']}"
                    )
                    self.tooltip.setHtml(tool_text)
                    self.tooltip.setPos(ts, 1)


    def create_summary_card(self, title):
        card = QFrame()
        card.setObjectName("SummaryCard")
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setAlignment(Qt.AlignCenter)
        
        lbl_count = QLabel("0")
        lbl_count.setObjectName("CountLabel")
        lbl_count.setAlignment(Qt.AlignCenter)
        
        lbl_title = QLabel(title)
        lbl_title.setObjectName("TitleLabel")
        lbl_title.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(lbl_count)
        layout.addWidget(lbl_title)
        
        # Default Green Style
        lbl_count.setStyleSheet("color: #28a745;")
        
        return card, lbl_count

    def create_table(self, headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setAlternatingRowColors(True)
        table.setStyleSheet("alternate-background-color: #f9f9f9; background-color: #ffffff;")
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        return table

    def run_analysis_silent(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            return
        self.worker = AnalysisWorker()
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.start()

    def update_card_style(self, label, count):
        if count == 0:
            label.setStyleSheet("color: #28a745;") # Green
        elif count <= 5:
            label.setStyleSheet("color: #fd7e14;") # Orange
        else:
            label.setStyleSheet("color: #dc3545;") # Red

    def on_analysis_finished(self, results):
        self.status_label.setText("Live Analysis Active... (Updating)")
        
        timeline = results.get('timeline', pd.DataFrame())
        if timeline is not None and not timeline.empty:
            timeline['Time'] = pd.to_datetime(timeline['Time'])
            # Precompute UnixTime once to prevent UI locking during mouse hover math
            timeline['UnixTime'] = timeline['Time'].apply(lambda d: d.timestamp())
            
            if not self.current_timeline_df.empty:
                latest_old = self.current_timeline_df['Time'].max()
                new_events = timeline[timeline['Time'] > latest_old]
                
                # Setup Categories
                crit_types = ['Failed Logon', 'Brute Force Attempt', 'Account Lockout']
                warn_types = ['Privilege Escalation']
                info_types = ['User Creation', 'User Deleted', 'Password Change', 'Password Reset', 'Account Modified']
                
                # Group repeated events for anti-spam
                grouped_events = new_events.groupby(['Type', 'Target']).size().reset_index(name='count')
                
                for _, grp in grouped_events.iterrows():
                    ev_type = grp['Type']
                    target = grp['Target']
                    evt_count = grp['count']
                    
                    # Find exact most recent record in this bundle for the UI timestamp link
                    rep_event = new_events[(new_events['Type'] == ev_type) & (new_events['Target'] == target)].iloc[0]
                    ts = rep_event['UnixTime']
                    ts_str = rep_event['Time'].strftime('%H:%M:%S')
                    desc = rep_event.get('Description', '')

                    # Cooldown Check (30 seconds per Type+Target)
                    now_ts = datetime.datetime.now().timestamp()
                    cache_key = (ev_type, target)
                    last_fired = self.alert_cooldowns.get(cache_key, 0)
                    
                    if now_ts - last_fired < 30:
                        continue # Skip UI popup, but let it go to DB invisibly later if applicable
                    self.alert_cooldowns[cache_key] = now_ts
                    
                    # Categorize
                    if ev_type in crit_types:
                        cat_label = "🔴 Critical"
                        color_hex = "#dc3545"
                        nav_dest = "Security Incidents"
                    elif ev_type in warn_types:
                        cat_label = "🟠 Warning"
                        color_hex = "#fd7e14"
                        nav_dest = "Privilege Escalation Incidents"
                    elif ev_type in info_types:
                        # Sometimes Info, sometimes Warning based on failure (if tracking)
                        cat_label = "🔵 Info"
                        color_hex = "#0078D7"
                        nav_dest = "User Account Changes"
                    else:
                        cat_label = "⚪ Notice"
                        color_hex = "#6c757d"
                        nav_dest = "Main Dashboard (Overall Incidents)"
                        
                    msg_body = f"{evt_count}x '{ev_type}' events detected for '{target}'. {desc}"
                    
                    # 1. Floating Toast popup (Internal)
                    if hasattr(self, 'parent') and self.parent():
                        toast = ToastNotification(self.parent(), title=f"{cat_label}: {ev_type}", message=msg_body, color_hex=color_hex)
                        toast.show_toast()
                    
                    # 2. System Tray Fallback (External)
                    try:
                        self.tray_icon.showMessage(cat_label, msg_body, QSystemTrayIcon.Information, 5000)
                    except: pass
                    


        self.current_timeline_df = timeline
        self.update_ui_with_data()

    def update_ui_with_data(self):
        if self.current_timeline_df is None or self.current_timeline_df.empty:
            return
            
        df = self.current_timeline_df.copy()
        
        # Apply Navigation Menu Filter & Contextual Card Titles
        if self.current_view == "Main Dashboard (Overall Incidents)":
            title_1, title_2, title_3, title_4 = "Total Incidents", "Privilege Escalations", "User Creations", "Failed Attempts"
        elif self.current_view == "Security Incidents":
            title_1, title_2, title_3, title_4 = "Failed Logins", "Brute Force Attempts", "Account Lockouts", "Suspicious Auth"
            df = df[df['Type'].isin(['Failed Logon', 'Brute Force Attempt', 'Account Lockout', 'Malware'])]
        elif self.current_view == "Privilege Escalation Incidents":
            title_1, title_2, title_3, title_4 = "Group Additions", "Admin Role Assignments", "Unauthorized Priv Changes", "Total Priv Incidents"
            df = df[df['Type'] == 'Privilege Escalation']
        elif self.current_view == "User Account Changes":
            title_1, title_2, title_3, title_4 = "Users Created", "Users Deleted", "Password Changes/Resets", "Account Modifications"
            df = df[df['Type'].isin(['User Creation', 'User Deleted', 'Password Change', 'Password Reset', 'Account Modified'])]
        else:
            title_1, title_2, title_3, title_4 = "Total", "Privilege", "User", "Password"
            
        self.card_bf.findChild(QLabel, "TitleLabel").setText(title_1)
        self.card_priv.findChild(QLabel, "TitleLabel").setText(title_2)
        self.card_create.findChild(QLabel, "TitleLabel").setText(title_3)
        self.card_pw.findChild(QLabel, "TitleLabel").setText(title_4)
        
        # Apply UI Filters from Table Controls
        from_dt = self.dt_from.dateTime().toPyDateTime()
        to_dt = self.dt_to.dateTime().toPyDateTime()
        df = df[(df['Time'] >= from_dt) & (df['Time'] <= to_dt)]
        
        s_user = self.search_user.text().lower()
        if s_user:
            df = df[df['Target'].astype(str).str.lower().str.contains(s_user) | df['Actor'].astype(str).str.lower().str.contains(s_user)]
            
        action_f = self.action_combo.currentText()
        if action_f != "All Actions":
            df = df[df['Type'] == action_f]
            
        status_f = self.status_combo.currentText()
        if status_f != "All Statuses":
            if status_f == "Failed":
                df = df[df['Type'].isin(['Failed Logon', 'Brute Force Attempt', 'Account Lockout'])]
            elif status_f == "Success":
                df = df[df['Type'].isin(['Successful Logon'])]
            else:
                df = df[~df['Type'].isin(['Failed Logon', 'Brute Force Attempt', 'Account Lockout', 'Successful Logon'])]
                
        self.filtered_df = df.copy()

        # Update Summary Card Counts
        if self.current_view == "Main Dashboard (Overall Incidents)":
            c1 = len(df)
            c2 = len(df[df['Type'] == 'Privilege Escalation'])
            c3 = len(df[df['Type'] == 'User Creation'])
            c4 = len(df[df['Type'].isin(['Brute Force Attempt', 'Failed Logon', 'Account Lockout'])])
        elif self.current_view == "Security Incidents":
            c1 = len(df[df['Type'] == 'Failed Logon'])
            c2 = len(df[df['Type'] == 'Brute Force Attempt'])
            c3 = len(df[df['Type'] == 'Account Lockout'])
            c4 = 0 
        elif self.current_view == "Privilege Escalation Incidents":
            c1 = len(df[df['Type'] == 'Privilege Escalation'])
            c2 = 0 
            c3 = 0 
            c4 = len(df)
        elif self.current_view == "User Account Changes":
            c1 = len(df[df['Type'] == 'User Creation'])
            c2 = len(df[df['Type'] == 'User Deleted'])
            c3 = len(df[df['Type'].isin(['Password Change', 'Password Reset'])])
            c4 = len(df[df['Type'] == 'Account Modified'])
        else:
            c1, c2, c3, c4 = 0, 0, 0, 0
            
        self.lbl_bf_count.setText(str(c1))
        self.lbl_priv_count.setText(str(c2))
        self.lbl_create_count.setText(str(c3))
        self.lbl_pw_count.setText(str(c4))
        
        self.update_card_style(self.lbl_bf_count, c1)
        self.update_card_style(self.lbl_priv_count, c2)
        self.update_card_style(self.lbl_create_count, c3)
        self.update_card_style(self.lbl_pw_count, c4)

        # 1. Update Timeline Table
        self.populate_table(self.table_timeline, df, ['Time', 'Type', 'Actor', 'Target', 'Status', 'Description'])
        self.table_timeline.setSortingEnabled(True)
        
        # 2. Update Pie Chart
        pie_data = df.groupby('Type').size().to_dict()
        self.pie_chart.update_data(pie_data)
        
        # 4. Update Chart
        self.update_chart(df)
        
    def update_chart(self, timeline_df):
        self.plot_widget.clear()
        
        # Re-add persistent UI elements that were just cleared
        self.plot_widget.addItem(self.today_marker)
        self.plot_widget.addItem(self.crosshair_v)
        self.plot_widget.addItem(self.tooltip)
        
        if self.plot_widget.plotItem.legend is not None:
            self.plot_widget.plotItem.legend.clear()
            
        if timeline_df.empty:
            return

        # Update Today Marker
        self.today_marker.setPos(datetime.datetime.now().timestamp())

        timeline_df = timeline_df.copy()
        timeline_df['DateBin'] = timeline_df['Time'].dt.floor('5min') # Bin by 5 min
        
        # Create complete time range for 0 padding
        min_time = timeline_df['DateBin'].min()
        max_time = timeline_df['DateBin'].max()
        if pd.isna(min_time): return
        
        # Create full index to ensure lines drop to zero
        full_idx = pd.date_range(start=min_time, end=max_time, freq='5min')
        
        # Timeline peaks mode
        if self.current_view == "Main Dashboard (Overall Incidents)":
            grouped = timeline_df.groupby('DateBin').size()
            grouped = grouped.reindex(full_idx, fill_value=0).reset_index()
            grouped.columns = ['DateBin', 'Count']
            
            x = grouped['DateBin'].apply(lambda d: d.timestamp()).values
            y = grouped['Count'].values
            
            self.plot_widget.plot(
                x, y, 
                pen=pg.mkPen(color=(220, 53, 69), width=2), 
                symbol=None, 
                fillLevel=0,
                fillBrush=(220, 53, 69, 100),
                name="Peak Incidents (Live)"
            )
        else:
            grouped = timeline_df.groupby(['DateBin', 'Type']).size()
            grouped = grouped.reset_index(name='Count')
            if grouped.empty: return
            
            colors = {
                'Brute Force Attempt': (220, 53, 69),      # Red
                'Privilege Escalation': (40, 167, 69),     # Green
                'User Creation': (0, 123, 255),            # Blue
                'Password Reset': (253, 126, 20),          # Orange
                'Password Change': (253, 126, 20),         # Orange
                'Account Lockouts': (111, 66, 193)         # Purple
            }
            symbols = {
                'Brute Force Attempt': 'x',
                'Privilege Escalation': 's',
                'User Creation': 'o',
                'Password Reset': 'd',
                'Password Change': '+'
            }
            
            types = grouped['Type'].unique()
            for event_type in types:
                type_data = grouped[grouped['Type'] == event_type].set_index('DateBin')['Count']
                type_data = type_data.reindex(full_idx, fill_value=0).reset_index()
                type_data.columns = ['DateBin', 'Count']
                    
                x = type_data['DateBin'].apply(lambda d: d.timestamp()).values
                y = type_data['Count'].values
                
                color = colors.get(event_type, (100, 100, 100))
                
                self.plot_widget.plot(
                    x, y, 
                    pen=pg.mkPen(color=color, width=2), 
                    symbol=None, 
                    fillLevel=0,
                    fillBrush=(color[0], color[1], color[2], 50),
                    name=event_type
                )

    def _derive_status(self, etype):
        """Derive a human-readable status from the event type string."""
        e = str(etype).lower()
        if any(k in e for k in ('brute', 'failed logon', 'lockout', 'fail')):
            return 'Failed'
        elif any(k in e for k in ('successful', 'success')):
            return 'Success'
        elif any(k in e for k in ('privilege', 'escalation')):
            return 'Warning'
        return 'Info'

    def populate_table(self, table, df, columns):
        from PyQt5.QtGui import QColor, QFont
        table.setSortingEnabled(False)
        table.setRowCount(0)
        if df.empty:
            return

        # Color-code rows: Green = Success, Red = Failed, Yellow = Warning/Info
        COLOR_MAP = {
            'success': (QColor('#d4edda'), QColor('#155724')),  # bg, fg
            'failed':  (QColor('#f8d7da'), QColor('#721c24')),
            'warning': (QColor('#fff3cd'), QColor('#856404')),
            'info':    (QColor('#ffffff'), QColor('#333333')),
        }

        table.setRowCount(len(df))
        for i, (_, row) in enumerate(df.iterrows()):
            etype  = str(row.get('Type', ''))
            status = self._derive_status(etype)

            level  = status.lower() if status.lower() in COLOR_MAP else 'info'
            bg_col, fg_col = COLOR_MAP[level]

            for j, col in enumerate(columns):
                if col == 'Status':
                    val = status
                else:
                    val = str(row.get(col, ''))
                item = QTableWidgetItem(val)
                item.setBackground(bg_col)
                if col in ('Type', 'Status'):
                    item.setForeground(fg_col)
                    item.setFont(QFont('Segoe UI', 9, QFont.Bold))
                if col == 'Time':
                    item.setData(Qt.UserRole, pd.to_datetime(val, errors='coerce'))
                table.setItem(i, j, item)
