import sys
import os
from PyQt5.QtWidgets import QApplication
from src.gui.dashboard import MainWindow

def main():
    # Ensure src is in path
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    
    app = QApplication(sys.argv)
    app.setApplicationName("AD-IFMA")
    
    # Global Style
    app.setStyleSheet("""
        * {
            font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
        }
        QMainWindow, QWidget#CentralWidget {
            background-color: #f0f2f5;
        }
        QTabWidget::pane {
            border: 1px solid #dcdcdc;
            background: white;
            border-radius: 4px;
        }
        QTabBar::tab {
            background: #e9ecef;
            border: 1px solid #dcdcdc;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: bold;
            color: #333;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            min-width: 180px;
        }
        QTabBar::tab:selected {
            background: white;
            color: #0078D7;
            border-bottom-color: white;
        }
    """)
    
    window = MainWindow()
    window.central_widget.setObjectName("CentralWidget")
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
