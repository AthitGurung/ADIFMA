from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget
from src.simplifier.dashboard import SimplifierDashboard

from src.gui.forensics_dashboard import ForensicsDashboard

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AD-IFMA: Active Directory Forensics & Monitoring")
        self.resize(1200, 800)
        
        # Central Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Tabs
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Add Simplifier Tab
        self.simplifier_tab = SimplifierDashboard()
        self.tabs.addTab(self.simplifier_tab, "AD Simplifier")
        
        # Add Forensics Tab
        self.forensics_tab = ForensicsDashboard()
        self.tabs.addTab(self.forensics_tab, "Forensics & Monitoring")
