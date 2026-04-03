from PyQt5.QtWidgets import QMessageBox, QFileDialog
from PyQt5.QtPrintSupport import QPrinter
from PyQt5.QtGui import QTextDocument
from datetime import datetime

class PDFGenerator:
    @staticmethod
    def export_to_pdf(parent, df, report_title="Forensics Report"):
        if df is None or df.empty:
            QMessageBox.warning(parent, "Export Error", "No data to export.")
            return

        # Prompt user for save location
        default_name = f"AD_IFMA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath, _ = QFileDialog.getSaveFileName(parent, "Save PDF Report", default_name, "PDF Files (*.pdf)")
        
        if not filepath:
            return  # User cancelled

        # Create HTML string to represent the PDF structure
        html = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; }}
                    h1 {{ color: #0078D7; text-align: center; }}
                    p {{ color: #555; text-align: center; font-size: 12px; }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 10px; }}
                    th, td {{ border: 1px solid #dddddd; padding: 6px; text-align: left; }}
                    th {{ background-color: #f2f2f2; font-weight: bold; }}
                    .Brute {{ color: #dc3545; }}
                    .Privilege {{ color: #fd7e14; }}
                </style>
            </head>
            <body>
                <h1>{report_title}</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Event Type</th>
                            <th>Actor</th>
                            <th>Target</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        # Generate rows
        for _, row in df.iterrows():
            etype = str(row.get('Type', ''))
            row_class = ''
            if 'Brute' in etype:
                row_class = 'Brute'
            elif 'Privilege' in etype:
                row_class = 'Privilege'
                
            html += "<tr>"
            html += f"<td>{row.get('Time', '')}</td>"
            html += f"<td class='{row_class}'>{etype}</td>"
            html += f"<td>{row.get('Actor', '')}</td>"
            html += f"<td>{row.get('Target', '')}</td>"
            html += f"<td>{row.get('Description', '')}</td>"
            html += "</tr>"

        html += """
                    </tbody>
                </table>
            </body>
        </html>
        """

        # Print using QPrinter
        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(filepath)

        doc = QTextDocument()
        doc.setHtml(html)
        doc.print_(printer)

        QMessageBox.information(parent, "Export Successful", f"Report successfully exported to:\n{filepath}")
