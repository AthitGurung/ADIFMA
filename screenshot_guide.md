# AD-IFMA Evidence Generation Guide
This guide provides step-by-step instructions on what to capture on your screen for all 20 test cases mentioned in the `Testing Documentation`. Following these steps will give you the exact visual evidence needed to make the report look legitimate and highly professional.

---

## Part 1: Capturing Unit Testing Evidence

**Test Case 1 (SQLite DB Initialization)**
1. Ensure your application has run at least once to create the local database.
2. Open a tool like **DB Browser for SQLite** or **DBeaver**.
3. Point it to your `ad_monitor.db` file.
4. Expand the database structure to show the list of tables (users_table, alerts_table etc.).
5. **Take Screenshot:** Capture the database tree showing that the tables were successfully created.

**Test Case 2 (Fetching AD Users)**
1. Open up VS Code and open your terminal.
2. Create a temporary debug script (or just run your `ad_utils.py` file manually if it has a print statement at the bottom) to execute the `get_ad_users()` function.
3. Let the terminal flood with the JSON data or Python dictionary data representing your AD users.
4. **Take Screenshot:** Capture the terminal window showing the parsed data stream.

**Test Case 3 (Fetching Disabled Accounts)**
1. Just like Test Case 2, run a modified specific test script or query targeting only `get_disabled_users()`.
2. Ensure the terminal output strictly shows accounts that are turned off (you may want to manually disable a test user in AD before doing this).
3. **Take Screenshot:** Capture the terminal output proving the filtered data output.

**Test Case 4 (Brute Force Anomaly Detection)**
1. Manually add debug print statements to `anomaly_detector.py` that print out `ANOMALY_DETECTED: TRUE - Cause: Multiple Failed Logins`.
2. Run a mocked script pushing 5 bad login events.
3. **Take Screenshot:** Capture the terminal successfully flagging the mocked event in plain text.

**Test Case 5 (Out-of-Hours Anomaly Detection)**
1. Again, run a mocked data piece passing a mock timestamp like "03:00 AM".
2. Allow `anomaly_detector.py` to process it.
3. **Take Screenshot:** Capture the terminal output printing something corresponding to `Warning: Out of expected hours login...`.

**Test Case 6 (PyQT Background Thread Signals)**
1. Make sure you have `logging.debug("Signal emitted: data_updated")` somewhere in your `SyncThread` thread code.
2. Run the application from your IDE terminal.
3. **Take Screenshot:** Highlight the terminal or Output pane in VS Code showing the moment the signal successfully fired without crashing.

**Test Case 7 (PDF Generator Core function)**
1. Run your `pdf_generator.py` core function locally to export a sample `report.pdf`.
2. Open the resulting `report.pdf` using Adobe Acrobat or your Edge/Chrome browser.
3. **Take Screenshot:** Zoom out slightly so you can see the layout of the generated PDF and capture that as evidence.

**Test Case 8 (Secure PowerShell Password Reset)**
1. Use your AD interface to submit a successful password change.
2. Inside your IDE terminal, you should be printing the Exit Code from your python subprocess when the Powershell finishes.
3. **Take Screenshot:** Capture the terminal returning an `Exit Code: 0` or similar debug text noting "Password successfully modified in AD".

**Test Case 9 (Log appending)**
1. Let your application run and deliberately trigger an action that updates `logs/ad_ifma.log` (such as launching the application or turning off the AD server to trigger an error).
2. Open `ad_ifma.log` inside Notepad or VS Code.
3. **Take Screenshot:** Highlight the very bottom lines of the log containing `WARNING` or `ERROR` tags next to a fresh Date and Time.

**Test Case 10 (Handling Phantom User)**
1. In your debug script, try to pull data for user `FakeBobAdmin99`.
2. The python script should not crash, but rather hit your `except` block and print a warning like `Exception Handled Safely: User not found in AD`.
3. **Take Screenshot:** Capture the IDE terminal printing out this exact warning message, visually showing it handled the error rather than throwing a traceback.

---

## Part 2: Capturing System Testing Evidence

**Test Case 1 (Main UI Initialization)**
1. Run `python main.py`.
2. Once the program launches, maximize it.
3. **Take Screenshot:** Take a clean image of your entire main Monitoring dashboard showing the aesthetic design and empty/populated tables.

**Test Case 2 (Dashboard Pie Charts Dynamic Binding)**
1. On your main AD-IFMA dashboard, look at the graphical widgets (User Status, Roles pie charts).
2. Use the Windows snipping tool.
3. **Take Screenshot:** Box out the actual visual Pie Chart reflecting your Active vs Inactive ratio.

**Test Case 3 (UI Navigation Integrity)**
1. Because a document requires still images, take two successive images to prove the UI states didn't overwrite or freeze.
2. **Take Screenshot A:** Snipping view of the Forensics Panel layout.
3. **Take Screenshot B:** Snipping view of the Simplifier/Monitoring Panel layout. (You can combine them side-by-side in Paint to form one 'Evidence' piece).

**Test Case 4 (Force Sync Functionality)**
1. Open AD Users & Computers (or the Admin center) externally and add a new user.
2. In AD-IFMA, click the "Refresh/Force Sync" button on the UI.
3. **Take Screenshot:** Take an image specifically showing the "Total Active Users" KPI metric increasing (or capture a before/after split of that exact data card).

**Test Case 5 (Live Alert Popups)**
1. From AD Users & Computers, purposely initiate an action you know will trigger an immediate forensics alert (like intentionally trying to login with bad passwords).
2. Wait for AD-IFMA to display its custom visual alert popup overlapping the dashboard.
3. **Take Screenshot:** Capture the entire application exactly while the alert banner is visible.

**Test Case 6 (User Table Interaction / Forms)**
1. Go to your AD-Users datatable inside the UI.
2. Double-click any random row.
3. A PyQT Dialog or Form should expand offering more details/modification tools for that user.
4. **Take Screenshot:** Capture the program with the secondary Dialog window open perfectly over the main table.

**Test Case 7 (Frontend PDF Generation Dialogs)**
1. Navigate to the Forensics layout.
2. Click heavily interactive buttons like `Export Security Report`.
3. An internal QFileDialog will open asking you where to save it. When you finish, there should be a `File Saved Successfully` system popup.
4. **Take Screenshot:** Capture the application UI with the "Success / Report exported" dialog firmly in the center.

**Test Case 8 (Table Advanced Filtering)**
1. In the main AD user view where your QTableWidget sits, locate your text search bar.
2. Type in a specific name, for example `Admin`.
3. The table should restrict itself to merely 1-3 rows immediately.
4. **Take Screenshot:** Capture the table and search bar proving the UI is currently filtering the row models smoothly.

**Test Case 9 (Simplifier Reset Form Wizard)**
1. Navigate to your Simplifier/Action form.
2. Click 'Reset Password' for a specific user and type mock pass-phrase `********`.
3. Hit submit.
4. **Take Screenshot:** Capture the green checkmark or PyQT notification stating that the AD interaction was successful via the visual layer.

**Test Case 10 (Memory Profiling)**
1. Leave your AD-IFMA system running for an hour on an explicit polling interval (e.g. 1 minute refreshes).
2. Hit `Ctrl+Shift+Esc` to open the internal **Windows Task Manager**.
3. Find your mapped Python process (`main.py` referencing AD-IFMA).
4. Click into the performance monitoring tab strictly for this process.
5. **Take Screenshot:** Capture the graph over time reflecting that RAM usage stayed stable (e.g., hovering around 100-200MB) without sloping upwards into a memory leak.
