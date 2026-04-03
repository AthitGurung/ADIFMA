from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTableWidget, QTableWidgetItem, QGroupBox, QHeaderView, QMessageBox, QFrame, QComboBox,
    QSystemTrayIcon, QStyle
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from src.ingestion.log_collector import LogCollector
from src.parsing.event_parser import EventParser
from src.analysis.anomaly_detector import AnomalyDetector
import pandas as pd
from datetime import datetime, timedelta
import pyqtgraph as pg
from src.utils.pdf_generator import PDFGenerator

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

        if timeline_events:
            timeline_df = pd.DataFrame(timeline_events)
            # Ensure sorting by time
            timeline_df['Time'] = pd.to_datetime(timeline_df['Time'])
            timeline_df = timeline_df.sort_values(by='Time', ascending=False) # Newest first for table
            results['timeline'] = timeline_df
        else:
            results['timeline'] = pd.DataFrame(columns=['Time', 'Type', 'Actor', 'Target', 'Description'])
            
        self.finished.emit(results)


class ForensicsDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.current_timeline_df = pd.DataFrame()
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

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Setup Timer for Live Updates
        self.live_timer = QTimer(self)
        self.live_timer.timeout.connect(self.run_analysis_silent)

        # --- SUMMARY CARDS ---
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(15)
        
        self.card_bf, self.lbl_bf_count = self.create_summary_card("Brute Force Attempts")
        self.card_priv, self.lbl_priv_count = self.create_summary_card("Privilege Escalation")
        self.card_create, self.lbl_create_count = self.create_summary_card("User Creations")
        self.card_pw, self.lbl_pw_count = self.create_summary_card("Password Changes")
        
        summary_layout.addWidget(self.card_bf)
        summary_layout.addWidget(self.card_priv)
        summary_layout.addWidget(self.card_create)
        summary_layout.addWidget(self.card_pw)
        
        layout.addLayout(summary_layout)

        # --- VISUAL TIMELINE CHART ---
        chart_group = QFrame()
        chart_group.setObjectName("SummaryCard")
        chart_layout = QVBoxLayout(chart_group)
        chart_layout.setContentsMargins(15, 15, 15, 15)
        
        chart_header = QHBoxLayout()
        chart_title = QLabel("Incident Timeline Chart")
        chart_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        
        self.status_label = QLabel("Live Analysis Active... (Updating)")
        self.status_label.setStyleSheet("font-size: 14px; color: #28a745; font-weight: bold;")
        
        self.time_filter = QComboBox()
        self.time_filter.addItems(["All Time", "Last 1 hour", "Last 24 hours", "Last 7 days"])
        self.time_filter.setStyleSheet("padding: 5px; font-size: 14px;")
        
        self.chart_filter = QComboBox()
        self.chart_filter.addItems(["All Events", "Brute Force Attempt", "Privilege Escalation", "User Creation", "Password Reset", "Password Change"])
        self.chart_filter.setStyleSheet("padding: 5px; font-size: 14px;")
        self.chart_filter.currentTextChanged.connect(lambda: self.update_chart(self.current_timeline_df))
        
        chart_header.addWidget(chart_title)
        chart_header.addStretch()
        chart_header.addWidget(self.status_label)
        chart_header.addWidget(self.time_filter)
        chart_header.addWidget(self.chart_filter)
        
        chart_layout.addLayout(chart_header)
        
        # Setup PyQtGraph Chart
        time_axis = pg.DateAxisItem(orientation='bottom')
        self.plot_widget = pg.PlotWidget(axisItems={'bottom': time_axis})
        self.plot_widget.setMinimumHeight(200)
        self.plot_widget.setBackground('w')
        self.plot_widget.setLabel('left', "Event Count", color='#333')
        self.plot_widget.setLabel('bottom', "Time Occurred", color='#333')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setMouseEnabled(x=False, y=False)
        self.plot_widget.setMenuEnabled(False)
        self.plot_widget.hideButtons()
        self.plot_widget.addLegend()
        
        chart_layout.addWidget(self.plot_widget)
        layout.addWidget(chart_group)

        # --- UNIFIED INCIDENT TABLE ---
        table_group = QFrame()
        table_group.setObjectName("SummaryCard")
        table_layout = QVBoxLayout(table_group)
        table_layout.setContentsMargins(15, 15, 15, 15)
        
        table_title = QLabel("Recent Security Events")
        table_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        table_layout.addWidget(table_title)
        
        self.table_timeline = self.create_table(["Time", "Event Type", "Actor", "Target", "Description"])
        table_layout.addWidget(self.table_timeline)
        
        self.export_btn = QPushButton("Export Forensic Report (PDF)")
        self.export_btn.setObjectName("RunBtn")
        self.export_btn.clicked.connect(self.export_pdf)
        table_layout.addWidget(self.export_btn)
        
        layout.addWidget(table_group)

        # System Tray Icon for Notifications
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.tray_icon.show()

        self.run_analysis_silent()
        self.live_timer.start(5000)

    def export_pdf(self):
        PDFGenerator.export_to_pdf(self, self.current_timeline_df)

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
        self.worker = AnalysisWorker(self.time_filter.currentText())
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
        
        # Update Summary
        bf = results.get('brute_force', pd.DataFrame())
        priv = results.get('privilege', pd.DataFrame())
        create = results.get('user_creation', pd.DataFrame())
        pw = results.get('password_change', pd.DataFrame())
        
        self.lbl_bf_count.setText(str(len(bf)))
        self.lbl_priv_count.setText(str(len(priv)))
        self.lbl_create_count.setText(str(len(create)))
        self.lbl_pw_count.setText(str(len(pw)))
        
        self.update_card_style(self.lbl_bf_count, len(bf))
        self.update_card_style(self.lbl_priv_count, len(priv))
        self.update_card_style(self.lbl_create_count, len(create))
        self.update_card_style(self.lbl_pw_count, len(pw))

        # Update Timeline Table
        # Check for new events to notify before updating current_timeline_df
        timeline = results.get('timeline', pd.DataFrame())
        
        if not self.current_timeline_df.empty and not timeline.empty:
            latest_old = self.current_timeline_df['Time'].max()
            new_events = timeline[timeline['Time'] > latest_old]
            for _, row in new_events.iterrows():
                if row['Type'] in ['User Creation', 'Privilege Escalation']:
                    self.tray_icon.showMessage(
                        "Security Alert", 
                        f"New {row['Type']} detected: {row['Target']}",
                        QSystemTrayIcon.Warning,
                        5000
                    )

        self.current_timeline_df = timeline
        self.populate_table(self.table_timeline, timeline, ['Time', 'Type', 'Actor', 'Target', 'Description'])
        self.table_timeline.setSortingEnabled(True)

        # Plot Data on Chart
        self.update_chart(self.current_timeline_df)
        
    def update_chart(self, timeline_df):
        self.plot_widget.clear()
        if timeline_df is None or timeline_df.empty:
            return
            
        # Ensure Time is datetime
        filter_val = self.chart_filter.currentText()
        if filter_val != "All Events":
            timeline_df = timeline_df[timeline_df['Type'] == filter_val]
            
        if timeline_df.empty:
            return

        timeline_df = timeline_df.copy()
        timeline_df['Time'] = pd.to_datetime(timeline_df['Time'])
        
        time_val = self.time_filter.currentText()
        if time_val == "Last 1 hour":
            timeline_df['DateBin'] = timeline_df['Time'].dt.floor('T')
        else:
            timeline_df['DateBin'] = timeline_df['Time'].dt.floor('H')
        
        grouped = timeline_df.groupby(['DateBin', 'Type']).size().reset_index(name='Count')
        
        if grouped.empty:
            return
            
        colors = {
            'Brute Force Attempt': (220, 53, 69),      # #dc3545
            'Privilege Escalation': (253, 126, 20),    # #fd7e14
            'User Creation': (0, 123, 255),            # #007bff
            'Password Reset': (108, 117, 125),         # #6c757d
            'Password Change': (108, 117, 125)         # #6c757d
        }
        
        symbols = {
            'Brute Force Attempt': 'x',
            'Privilege Escalation': 's',
            'User Creation': 'o',
            'Password Reset': 'd',
            'Password Change': '+'
        }
        
        types = grouped['Type'].unique()
        
        # We need to manually clear the legend items to prevent duplicate legend entries
        if self.plot_widget.plotItem.legend is not None:
            self.plot_widget.plotItem.legend.clear()
            
        for event_type in types:
            type_data = grouped[grouped['Type'] == event_type].sort_values('DateBin')
            if type_data.empty:
                continue
                
            # Convert datetime to timestamp for pyqtgraph
            x = type_data['DateBin'].astype('int64') // 10**9
            y = type_data['Count'].values
            
            color = colors.get(event_type, (100, 100, 100))
            symbol = symbols.get(event_type, 'o')
            
            # Plot as a line with symbols
            self.plot_widget.plot(
                x, y, 
                pen=pg.mkPen(color=color, width=2), 
                symbol=symbol, 
                symbolBrush=color,
                symbolPen='w',
                symbolSize=10,
                fillLevel=0,
                fillBrush=(color[0], color[1], color[2], 50),
                name=event_type
            )

    def populate_table(self, table, df, columns):
        table.setSortingEnabled(False) # Disable while populating
        table.setRowCount(0)
        if df.empty:
            return
            
        table.setRowCount(len(df))
        for i, row in df.iterrows():
            for j, col in enumerate(columns):
                val = str(row.get(col, ""))
                item = QTableWidgetItem(val)
                # Keep original data for sorting if it's a number
                if col == 'Time':
                    # Add simple padding for string sort or keep as is
                    item.setData(Qt.UserRole, pd.to_datetime(val))
                table.setItem(i, j, item)
