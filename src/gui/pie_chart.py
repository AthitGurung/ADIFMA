from PyQt5.QtWidgets import QWidget
from PyQt5.QtGui import QPainter, QBrush, QPen, QColor, QFont
from PyQt5.QtCore import Qt, QRectF

class PieChartWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(250, 200)
        self.data_counts = {}
        
        # Specific colors for each attack type based on user request
        self.colors = {
            'Brute Force Attempt': QColor(220, 53, 69),      # Red
            'Privilege Escalation': QColor(40, 167, 69),     # Green
            'User Creation': QColor(0, 123, 255),            # Blue
            'Password Changes': QColor(253, 126, 20),        # Orange
            'Password Reset': QColor(253, 126, 20),          # Orange (Same as change)
            'Account Lockouts': QColor(111, 66, 193),        # Purple
        }
        
    def update_data(self, counts_dict):
        self.data_counts = counts_dict
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        rect = self.rect()
        margin = 10
        # We need enough space for the legend, so the pie max width is constrained
        legend_width = 150
        size = min(rect.width() - legend_width - margin*3, rect.height() - margin*2)
        
        if size <= 0: return

        pie_rect = QRectF(margin, margin, size, size)
        
        total = sum(self.data_counts.values())
        if total <= 0:
            painter.setPen(QPen(Qt.gray, 1, Qt.DashLine))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(pie_rect)
            painter.drawText(pie_rect, Qt.AlignCenter, "No Data")
            return
            
        start_angle = 0
        
        # Legend coordinates
        legend_x = margin + size + 20
        legend_y = margin + 20
        
        # We want to display them in a sorted order or just as they come
        for key, value in self.data_counts.items():
            if value <= 0: continue
            
            # PyQt angles are in 16ths of a degree
            span_angle = int((value / total) * 360 * 16)
            
            # Default to grey if not in our color map
            color = self.colors.get(key, QColor(108, 117, 125)) 
            
            # Draw Pie Slice
            painter.setBrush(QBrush(color))
            painter.setPen(QPen(Qt.white, 1))
            painter.drawPie(pie_rect, start_angle, span_angle)
            start_angle += span_angle
            
            # Draw Legend Rectangle
            painter.drawRect(int(legend_x), int(legend_y), 12, 12)
            
            # Draw Legend Text
            painter.setPen(Qt.black)
            font = painter.font()
            font.setPointSize(8)
            painter.setFont(font)
            
            # Calculate percentage for display
            percent = (value / total) * 100
            label_text = f"{key}\n({value} - {percent:.1f}%)"
            
            # Use drawText with a boundingRect so the newline \n is handled
            text_rect = QRectF(legend_x + 20, legend_y - 2, legend_width - 20, 30)
            painter.drawText(text_rect, Qt.AlignLeft | Qt.AlignTop, label_text)
            
            legend_y += 35
