"""
PDF and Excel export utilities for AD-IFMA.

IMPORTANT: Qt's QTextDocument HTML renderer only supports a LIMITED subset of
HTML/CSS. Specifically:
  - NO CSS class selectors  (tr.myclass does NOT work)
  - NO border-radius
  - NO border-left / border-right shortcuts with 3 values
  - NO flexbox / grid
  - YES inline styles, basic colors, font-weight, padding, background-color on <td>/<th>
  - YES <table>, <tr>, <th>, <td>, <h1>-<h3>, <b>, <br>, <p>, <ul>, <li>

All HTML generated here uses ONLY inline styles on individual elements.
"""

from PyQt5.QtWidgets import QMessageBox, QFileDialog
from PyQt5.QtPrintSupport import QPrinter
from PyQt5.QtGui import QTextDocument
from datetime import datetime
import pandas as pd


# ─────────────────────────────────────────────────────────────────────────────
# Row colour helpers  (return inline style strings for <tr> / <td>)
# ─────────────────────────────────────────────────────────────────────────────
_ROW_STYLES = {
    "success": ("background-color:#d4edda;", "color:#155724;font-weight:bold;"),
    "failed":  ("background-color:#f8d7da;", "color:#721c24;font-weight:bold;"),
    "warning": ("background-color:#fff3cd;", "color:#856404;font-weight:bold;"),
    "info":    ("background-color:#ffffff;", "color:#333333;"),
}

def _level_from_status(status_str):
    s = str(status_str).lower()
    if "success" in s:          return "success"
    if "fail"    in s:          return "failed"
    if "warn"    in s:          return "warning"
    return "info"

def _level_from_type(etype_str):
    e = str(etype_str).lower()
    if any(k in e for k in ("brute", "failed logon", "lockout", "fail")):
        return "failed"
    if any(k in e for k in ("privilege", "escalation")):
        return "warning"
    if any(k in e for k in ("successful", "success")):
        return "success"
    return "info"

def _status_label(etype_str):
    e = str(etype_str).lower()
    if any(k in e for k in ("brute", "failed logon", "lockout", "fail")):
        return "Failed"
    if any(k in e for k in ("successful", "success")):
        return "Success"
    if any(k in e for k in ("privilege", "escalation")):
        return "Warning"
    return "Info"


# ─────────────────────────────────────────────────────────────────────────────
# Shared Qt-safe HTML page scaffold
# ─────────────────────────────────────────────────────────────────────────────
_PAGE_OPEN = """<html>
<head>
<style>
  body {{ font-family: Arial, sans-serif; font-size: 12pt; color: #222222; }}
  h1   {{ color: #0078D7; text-align: center; font-size: 18pt; }}
  h2   {{ color: #333333; font-size: 13pt; border-bottom: 1px solid #0078D7; padding-bottom: 2px; margin-top: 18px; }}
  p    {{ margin: 4px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th   {{ background-color: #0078D7; color: #ffffff; font-weight: bold; padding: 6px 8px; text-align: left; border: 1px solid #aaa; }}
  td   {{ padding: 6px 8px; text-align: left; border: 1px solid #cccccc; }}
</style>
</head>
<body>
"""
# NOTE: double braces {{ }} in the CSS above are literal { } for non-f-string use.
# We use .format() below, so inner {{ }} stays as { } in final output.

_PAGE_CLOSE = "</body></html>"


def _page_open(title, subtitle, generated):
    """Return the opening HTML boilerplate (no f-string — safe for CSS braces)."""
    return _PAGE_OPEN + (
        "<h1>{title}</h1>"
        "<p style='text-align:center;color:#555;font-size:11pt;'>{subtitle}</p>"
        "<p style='text-align:center;color:#888;font-size:10pt;'>"
        "Generated: {generated}</p>"
    ).format(title=title, subtitle=subtitle, generated=generated)


def _summary_table(rows_kv):
    """Render a two-column summary table: label | value (Qt-safe)."""
    html = (
        "<table style='width:60%;margin-top:8px;'>"
        "<col style='width:50%;'/><col style='width:50%;'/>"
    )
    for label, value, color in rows_kv:
        html += (
            "<tr>"
            "<td style='padding:5px 8px;border:1px solid #ccc;font-weight:bold;'>{label}</td>"
            "<td style='padding:5px 8px;border:1px solid #ccc;color:{color};font-weight:bold;'>{value}</td>"
            "</tr>"
        ).format(label=label, value=value, color=color)
    html += "</table>"
    return html


def _th(*labels):
    """Render a header row."""
    cells = "".join(
        "<th style='background-color:#0078D7;color:#ffffff;padding:6px 8px;"
        "border:1px solid #888;font-weight:bold;'>{}</th>".format(lbl)
        for lbl in labels
    )
    return "<tr>{}</tr>".format(cells)


def _td_row(level, *values):
    """Render a data row with colour coding based on level."""
    bg_style, txt_style = _ROW_STYLES.get(level, _ROW_STYLES["info"])
    cells = "".join(
        "<td style='padding:5px 8px;border:1px solid #cccccc;{row_bg}'>{val}</td>".format(
            row_bg=bg_style, val=str(v) if str(v) != "nan" else ""
        )
        for v in values
    )
    return "<tr style='{bg}'>{cells}</tr>".format(bg=bg_style, cells=cells)


def _save_pdf(parent, html_str, default_name):
    filepath, _ = QFileDialog.getSaveFileName(
        parent, "Save PDF Report", default_name, "PDF Files (*.pdf)"
    )
    if not filepath:
        return False
    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(filepath)
    doc = QTextDocument()
    doc.setHtml(html_str)
    doc.print_(printer)
    QMessageBox.information(parent, "Export Successful",
                            "Report saved to:\n{}".format(filepath))
    return True


# ─────────────────────────────────────────────────────────────────────────────
class PDFGenerator:

    # ── AD Simplifier PDF ─────────────────────────────────────────────────────
    @staticmethod
    def export_audit_to_pdf(parent, df, report_title="AD-IFMA — Active Directory Operation Report"):
        if df is None or df.empty:
            QMessageBox.warning(parent, "Export Error",
                                "No data to export.\nPlease load log entries first.")
            return

        # -- Counts --------------------------------------------------------
        total   = len(df)
        success = int(df['status'].astype(str).str.lower().eq('success').sum()) \
                  if 'status' in df.columns else 0
        failed  = int(df['status'].astype(str).str.lower().eq('failed').sum()) \
                  if 'status' in df.columns else 0

        # -- Date range ----------------------------------------------------
        try:
            date_range = "{} to {}".format(df['timestamp'].min(), df['timestamp'].max())
        except Exception:
            date_range = "N/A"

        # -- Build HTML ----------------------------------------------------
        html = _page_open("AD-IFMA", report_title,
                           datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        html += "<h2>Summary</h2>"
        html += _summary_table([
            ("Report Period",  date_range,     "#333333"),
            ("Total Actions",  str(total),     "#0078D7"),
            ("Successful",     str(success),   "#28a745"),
            ("Failed",         str(failed),    "#dc3545"),
        ])

        html += "<h2>Detailed Actions</h2>"
        html += "<table>"
        html += _th("Time", "Action", "User", "Status", "Reason / Description")

        for _, row in df.iterrows():
            status_val = str(row.get('status', ''))
            reason_val = str(row.get('reason', '') or row.get('description', ''))
            level      = _level_from_status(status_val)
            html += _td_row(
                level,
                row.get('timestamp', ''),
                row.get('action',    ''),
                row.get('username',  ''),
                status_val,
                reason_val,
            )

        html += "</table>"

        html += "<h2>Notes</h2>"
        html += (
            "<ul>"
            "<li>All operations are logged in real-time by AD-IFMA.</li>"
            "<li>Failed actions include the reason for failure.</li>"
            "<li style='color:#28a745;'>Green = Success</li>"
            "<li style='color:#dc3545;'>Red = Failed</li>"
            "<li style='color:#856404;'>Yellow = Warning</li>"
            "</ul>"
        )

        html += _PAGE_CLOSE

        default_name = "AD_IFMA_AuditLog_{}.pdf".format(
            datetime.now().strftime('%Y%m%d_%H%M%S'))
        _save_pdf(parent, html, default_name)

    # ── Forensic PDF ──────────────────────────────────────────────────────────
    @staticmethod
    def export_to_pdf(parent, df, report_title="Forensics Report"):
        if df is None or df.empty:
            QMessageBox.warning(parent, "Export Error",
                                "No forensic data to export.\nRun analysis first.")
            return

        # -- Counts --------------------------------------------------------
        total = len(df)

        failed_types  = ['Failed Logon', 'Brute Force Attempt', 'Account Lockout']
        success_types = ['Successful Logon']

        n_failed  = int(df['Type'].isin(failed_types).sum())  if 'Type' in df.columns else 0
        n_success = int(df['Type'].isin(success_types).sum()) if 'Type' in df.columns else 0
        n_info    = total - n_failed - n_success

        # -- Date range ----------------------------------------------------
        try:
            min_date = df['Time'].min().strftime('%Y-%m-%d %H:%M')
            max_date = df['Time'].max().strftime('%Y-%m-%d %H:%M')
            date_range = "{} to {}".format(min_date, max_date)
        except Exception:
            date_range = "N/A"

        # -- Key Findings --------------------------------------------------
        try:
            if 'Type' in df.columns and not df['Type'].empty:
                tc = df['Type'].value_counts()
                most_freq = str(tc.idxmax())
                freq_val  = int(tc.max())
            else:
                most_freq, freq_val = "N/A", 0

            user_col = df['Target'] if 'Target' in df.columns else pd.Series(dtype=str)
            user_col = user_col[~user_col.isin(["Unknown", "SYSTEM", "LOCAL SERVICE", ""])]
            if not user_col.empty:
                top_user   = str(user_col.value_counts().idxmax())
                top_user_v = int(user_col.value_counts().max())
            else:
                top_user, top_user_v = "N/A", 0
        except Exception as e:
            print("PDF key findings error:", e)
            most_freq, top_user     = "N/A", "N/A"
            freq_val,  top_user_v   = 0, 0

        # -- Build HTML ----------------------------------------------------
        html = _page_open("AD-IFMA",
                           "Forensic Incident Report — {}".format(report_title),
                           datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        # Section 1: Summary
        html += "<h2>1. Summary</h2>"
        html += _summary_table([
            ("Report Period",       date_range,         "#333333"),
            ("Total Incidents",     str(total),         "#0078D7"),
            ("Security Failures",   str(n_failed),      "#dc3545"),
            ("Successful Events",   str(n_success),     "#28a745"),
            ("Informational",       str(n_info),        "#333333"),
        ])

        # Section 2: Key Findings
        html += "<h2>2. Key Findings</h2>"
        html += _summary_table([
            ("Most Frequent Incident",
             "{} ({} occurrences)".format(most_freq, freq_val), "#333"),
            ("Most Targeted User",
             "{} ({} occurrences)".format(top_user,  top_user_v), "#333"),
        ])

        # Section 3: Breakdown by type
        html += "<h2>3. Incident Breakdown by Type</h2>"
        html += "<table>"
        html += _th("Incident Type", "Count")
        if 'Type' in df.columns:
            for t_name, t_count in df['Type'].value_counts().items():
                level = _level_from_type(str(t_name))
                html += _td_row(level, t_name, t_count)
        html += "</table>"

        # Section 4: Detailed incident table
        html += "<h2>4. Detailed Incident Table</h2>"
        html += "<table>"
        html += _th("Time", "Incident Type", "User", "Status", "Description")

        for _, row in df.iterrows():
            etype  = str(row.get('Type',        ''))
            user   = str(row.get('Target',      row.get('Actor', 'Unknown')))
            desc   = str(row.get('Description', ''))
            t_val  = row.get('Time', '')
            status = _status_label(etype)
            level  = _level_from_type(etype)

            try:
                t_str = t_val.strftime('%Y-%m-%d %H:%M') \
                        if hasattr(t_val, 'strftime') else str(t_val)
            except Exception:
                t_str = str(t_val)

            html += _td_row(level, t_str, etype, user, status, desc)

        html += "</table>"
        html += _PAGE_CLOSE

        default_name = "AD_IFMA_ForensicReport_{}.pdf".format(
            datetime.now().strftime('%Y%m%d_%H%M%S'))
        _save_pdf(parent, html, default_name)

    # ── Excel Export (.xlsx) ──────────────────────────────────────────────────
    @staticmethod
    def export_to_csv(parent, df):
        """Export data as a formatted Excel workbook (.xlsx)."""
        if df is None or df.empty:
            QMessageBox.warning(parent, "Export Error",
                                "No data to export.\nRun analysis first.")
            return

        default_name = "AD_IFMA_Export_{}.xlsx".format(
            datetime.now().strftime('%Y%m%d_%H%M%S'))
        filepath, _ = QFileDialog.getSaveFileName(
            parent, "Save Excel File", default_name,
            "Excel Files (*.xlsx)"
        )
        if not filepath:
            return

        try:
            import openpyxl
            from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
            from openpyxl.utils import get_column_letter
        except ImportError:
            QMessageBox.critical(parent, "Missing Library",
                                 "openpyxl is required for Excel export.\n"
                                 "Run: pip install openpyxl")
            return

        # -- Prepare DataFrame ---------------------------------------------
        export_df = df.copy()

        # Standardise columns regardless of source (forensics vs audit DB)
        def _col(df_, *names):
            for n in names:
                if n in df_.columns:
                    return df_[n]
            return pd.Series([""] * len(df_), index=df_.index)

        export_df['Timestamp']   = _col(export_df, 'Time', 'timestamp')
        export_df['Username']    = export_df.apply(
            lambda r: r.get('Target', r.get('Actor', r.get('username', 'Unknown'))), axis=1)
        export_df['Action']      = _col(export_df, 'Type', 'action')
        export_df['Status']      = _col(export_df, 'status').apply(
            lambda s: s if str(s).strip() else "Info")
        # Override status for forensic df where status is derived from type
        if 'Type' in export_df.columns and 'status' not in df.columns:
            export_df['Status'] = export_df['Type'].apply(_status_label)
        export_df['Reason']      = _col(export_df, 'reason', 'Description', 'description')
        export_df['Description'] = _col(export_df, 'Description', 'description')

        cols = ['Timestamp', 'Username', 'Action', 'Status', 'Reason', 'Description']
        cols = [c for c in cols if c in export_df.columns]
        out  = export_df[cols].copy()

        # -- Build Workbook ------------------------------------------------
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "AD-IFMA Events"

        # Styles
        header_font    = Font(name='Calibri', bold=True, color="FFFFFF", size=11)
        header_fill    = PatternFill("solid", fgColor="0078D7")
        header_align   = Alignment(horizontal="center", vertical="center", wrap_text=True)
        thin_border    = Border(
            left=Side(style='thin'), right=Side(style='thin'),
            top=Side(style='thin'), bottom=Side(style='thin')
        )

        fill_success = PatternFill("solid", fgColor="D4EDDA")
        fill_failed  = PatternFill("solid", fgColor="F8D7DA")
        fill_warning = PatternFill("solid", fgColor="FFF3CD")
        fill_info    = PatternFill("solid", fgColor="FFFFFF")

        font_success = Font(name='Calibri', color="155724", size=10)
        font_failed  = Font(name='Calibri', color="721C24", size=10)
        font_warning = Font(name='Calibri', color="856404", size=10)
        font_normal  = Font(name='Calibri', size=10)
        cell_align   = Alignment(vertical="center", wrap_text=True)

        # Header row
        ws.row_dimensions[1].height = 24
        for col_idx, col_name in enumerate(cols, start=1):
            cell = ws.cell(row=1, column=col_idx, value=col_name)
            cell.font      = header_font
            cell.fill      = header_fill
            cell.alignment = header_align
            cell.border    = thin_border

        # Data rows
        for row_idx, (_, row) in enumerate(out.iterrows(), start=2):
            ws.row_dimensions[row_idx].height = 18
            status_str = str(row.get('Status', '')).lower()
            if 'success' in status_str:
                row_fill, row_font = fill_success, font_success
            elif 'fail' in status_str:
                row_fill, row_font = fill_failed, font_failed
            elif 'warn' in status_str or 'info' in status_str:
                row_fill, row_font = fill_warning, font_warning
            else:
                row_fill, row_font = fill_info, font_normal

            for col_idx, col_name in enumerate(cols, start=1):
                val  = row.get(col_name, '')
                # Convert Timestamp to string
                if hasattr(val, 'strftime'):
                    val = val.strftime('%Y-%m-%d %H:%M:%S')
                elif str(val) == 'nan':
                    val = ''
                cell = ws.cell(row=row_idx, column=col_idx, value=str(val))
                cell.font      = row_font
                cell.fill      = row_fill
                cell.alignment = cell_align
                cell.border    = thin_border

        # Auto-fit column widths
        col_widths = {
            'Timestamp': 20, 'Username': 18, 'Action': 22,
            'Status': 12, 'Reason': 30, 'Description': 40
        }
        for col_idx, col_name in enumerate(cols, start=1):
            ws.column_dimensions[get_column_letter(col_idx)].width = \
                col_widths.get(col_name, 20)

        # Freeze header row
        ws.freeze_panes = "A2"

        # Auto-filter
        ws.auto_filter.ref = ws.dimensions

        try:
            wb.save(filepath)
            QMessageBox.information(parent, "Export Successful",
                                    "Excel file saved to:\n{}".format(filepath))
        except Exception as e:
            QMessageBox.critical(parent, "Export Error",
                                 "Failed to save Excel file:\n{}".format(e))

    # ── Audit CSV Export (simplified dashboard) ───────────────────────────────
    @staticmethod
    def export_audit_to_excel(parent, df):
        """Export the AD Simplifier audit log as a formatted Excel workbook."""
        if df is None or df.empty:
            QMessageBox.warning(parent, "Export Error",
                                "No data to export.\nLoad log entries first.")
            return
        # Reuse the generic export — columns match (timestamp, username, action, status, reason, description)
        PDFGenerator.export_to_csv(parent, df)
