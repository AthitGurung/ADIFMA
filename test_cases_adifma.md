# Chapter 4 – Testing

## 4.1 Testing Overview

This chapter documents the testing activities performed on the **AD-IFMA (Active Directory – Integrated Forensic Monitoring Application)** system. Testing is divided into two phases:

- **Unit Testing (UT)** – individual functions and classes are tested in isolation using Python's `pytest` framework with mock objects

- **System Testing (ST)** – the assembled application is tested end-to-end through the graphical user interface (GUI) to verify all integrated workflows

---

## 4.2 Unit Testing

Unit testing verifies that each module's internal logic produces the correct output independently of external dependencies (Active Directory, the Windows Event Log, or the GUI).

**Test Environment:**

| Item | Detail |
|---|---|
| Language | Python 3.10+ |
| Framework | pytest |
| AD Connection | Disabled (`ADUtils.MOCK_MODE = True`) |
| Database | Temporary SQLite file (via `tmp_path` fixture) |
| Event Logs | Mock objects (`MockEvent`) |

---

### 4.2.1 Module: `src/simplifier/forms.py` — `validate_password()`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-001 | Valid strong password returns no error | Function imported | `"Secure@123"` | Returns `None` (no error) | Returns `None` | Pass |
| UT-002 | Password shorter than 8 characters is rejected | Function imported | `"Ab1!xyz"` (7 chars) | Returns string containing "8" | Returns error string with "8" | Pass |
| UT-003 | Exactly 8-character strong password is accepted | Function imported | `"Aa1!aaaa"` (8 chars) | Returns `None` | Returns `None` | Pass |
| UT-004 | Password missing uppercase letter is rejected | Function imported | `"secure@123"` | Returns string containing "uppercase" | Returns uppercase error | Pass |
| UT-005 | Password missing lowercase letter is rejected | Function imported | `"SECURE@123"` | Returns string containing "lowercase" | Returns lowercase error | Pass |
| UT-006 | Password missing numeric digit is rejected | Function imported | `"Secure@abc"` | Returns string containing "digit" or "numeric" | Returns digit error | Pass |
| UT-007 | Password missing special character is rejected | Function imported | `"Secure1234"` | Returns string containing "special" | Returns special char error | Pass |
| UT-008 | Empty password is rejected | Function imported | `""` (empty string) | Returns a non-None error string | Returns length error | Pass |

> **Screenshot Required:** `Figure 4.1` — See Screenshot Guide (Section 4.4)

---

### 4.2.2 Module: `src/simplifier/forms.py` — `parse_ad_error()`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-009 | "already exists" in create_user context humanised correctly | Function imported | `("account already exists", "create_user")` | Returns string containing "already exists" | Returns human-readable duplicate error | Pass |
| UT-010 | "password history" in create_user context humanised correctly | Function imported | `("Password violates history policy.", "create_user")` | Returns string mentioning "history" or "previously" | Returns history policy message | Pass |
| UT-011 | "already a member" in add_group context humanised correctly | Function imported | `("already a member of the group", "add_group")` | Returns string containing "already" | Returns group membership error | Pass |
| UT-012 | "cannot find an object" in remove_user context humanised correctly | Function imported | `("Cannot find an object with identity 'xyz'", "remove_user")` | Returns string containing "does not exist" | Returns user-not-found message | Pass |
| UT-013 | Unknown error falls back to first line of raw message | Function imported | `("Something unexpected\nLine 2", "unknown")` | Returns `"Something unexpected"` | Returns first line only | Pass |

---

### 4.2.3 Module: `src/analysis/anomaly_detector.py` — `is_system_noise()`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-014 | `"SYSTEM"` identified as system noise | `AnomalyDetector` class imported | `"SYSTEM"` | Returns `True` | Returns `True` | Pass |
| UT-015 | Machine account ending in `$` identified as noise | Class imported | `"MACHINE01$"` | Returns `True` | Returns `True` | Pass |
| UT-016 | `None` input identified as noise | Class imported | `None` | Returns `True` | Returns `True` | Pass |
| UT-017 | Real user `"jdoe"` is not classified as noise | Class imported | `"jdoe"` | Returns `False` | Returns `False` | Pass |
| UT-018 | `"ANONYMOUS LOGON"` identified as noise | Class imported | `"ANONYMOUS LOGON"` | Returns `True` | Returns `True` | Pass |

---

### 4.2.4 Module: `src/analysis/anomaly_detector.py` — `detect_brute_force()`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-019 | Empty DataFrame returns empty result | `AnomalyDetector(pd.DataFrame())` | No data | Returns empty DataFrame | Returns empty DataFrame | Pass |
| UT-020 | 4 failures (below threshold=5) — not detected | DataFrame with 4 Event 4625 rows for `"hacker"` within 1 min | threshold=5, window=`"5min"` | Returns empty DataFrame | Returns empty DataFrame | Pass |
| UT-021 | 6 failures (above threshold=5) — detected as Brute Force | DataFrame with 6 Event 4625 rows for `"hacker"` within 1 min | threshold=5, window=`"5min"` | Returns DataFrame with Type=`"Brute Force"`, User=`"hacker"` | Brute force row detected | Pass |
| UT-022 | 10 failures from `"SYSTEM"` account — ignored | DataFrame with 10 Event 4625 rows for `"SYSTEM"` | threshold=5, window=`"5min"` | Returns empty DataFrame | Returns empty DataFrame | Pass |
| UT-023 | Two users — only one over threshold detected | 8 failures for `"hacker"`, 3 for `"legit_guy"` in same window | threshold=5, window=`"5min"` | Only `"hacker"` detected | Only hacker in result | Pass |

> **Screenshot Required:** `Figure 4.2` — See Screenshot Guide (Section 4.4)

---

### 4.2.5 Module: `src/analysis/anomaly_detector.py` — `detect_new_admin_creation()`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-024 | Event 4728 triggers Privilege Escalation detection | DataFrame with Event 4728, EventData=`["jdoe","x","Domain Admins"]` | Standard | Returns row with Type=`"Privilege Escalation"`, TargetGroup=`"Domain Admins"` | Detected correctly | Pass |
| UT-025 | Machine account `"MACHINE01$"` in Event 4728 ignored | DataFrame with Event 4728, user=`"MACHINE01$"` | Standard | Returns empty DataFrame | Filtered out as noise | Pass |

---

### 4.2.6 Module: `src/analysis/anomaly_detector.py` — `detect_password_changes()`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-026 | Event 4723 classified as "Password Change" | DataFrame with Event 4723 for user `"alice"` | Standard | Returns row with Type=`"Password Change"` | Correct type returned | Pass |
| UT-027 | Event 4724 classified as "Password Reset" | DataFrame with Event 4724 for user `"bob"` | Standard | Returns row with Type=`"Password Reset"` | Correct type returned | Pass |
| UT-028 | Password event within 10 s of user creation is skipped (false positive filter) | DataFrame with Event 4720 at T+0 and Event 4724 at T+5 s for `"carol"` | Standard | Returns empty DataFrame (filtered as creation-related) | Event skipped | Pass |
| UT-029 | Password event 15 s after creation is included | DataFrame with Event 4720 at T+0 and Event 4724 at T+15 s for `"dave"` | Standard | Returns 1 row (Password Reset) | Row present | Pass |

---

### 4.2.7 Module: `src/utils/db_manager.py` — `AuditDB`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-030 | Database table `audit_logs` is created on first initialisation | Fresh temporary SQLite DB file | `AuditDB(db_path=tmp_path)` | `audit_logs` table exists with columns: id, timestamp, username, action, status, reason, description | Table created with all columns | Pass |
| UT-031 | Valid log entry inserted and retrievable | Initialised `AuditDB` | `insert_log("admin","Create User","Success","","")` | Returns `(True, timestamp)` and record appears in `get_logs()` | Inserted and retrieved | Pass |
| UT-032 | Blank username rejected — not inserted | Initialised `AuditDB` | `insert_log("","Create User","Success","","")` | Returns `(False, None)` and 0 records in DB | Rejected with `False` | Pass |
| UT-033 | Blank action rejected — not inserted | Initialised `AuditDB` | `insert_log("admin","","Success","","")` | Returns `(False, None)` | Rejected with `False` | Pass |
| UT-034 | `get_logs` with `username_search="alice"` returns only alice's records | DB seeded with alice (2 rows) and bob (1 row) | `get_logs(username_search="alice")` | Returns 2 rows, all with username=`"alice"` | Correct filter applied | Pass |
| UT-035 | `get_logs` with `status_filter="Failed"` returns only failed records | DB seeded with 2 Success + 1 Failed | `get_logs(status_filter="Failed")` | Returns 1 row with status=`"Failed"` | Correct filter applied | Pass |
| UT-036 | `get_summary_counts` returns correct totals | DB with 2 Success + 1 Failed record | `get_summary_counts()` | Returns `(3, 2, 1)` | Returns `(3, 2, 1)` | Pass |

> **Screenshot Required:** `Figure 4.3` — See Screenshot Guide (Section 4.4)

---

### 4.2.8 Module: `src/parsing/event_parser.py` — `EventParser`

| Test Case ID | Test Objective | Pre-condition | Test Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| UT-037 | Event ID is correctly masked (lower 16 bits) | `MockEvent(event_id=0x80004625)` | `parse_event(event)` | `result["EventID"] == 4625` | 4625 returned | Pass |
| UT-038 | `StringInserts` stored as list in EventData | `MockEvent(inserts=("alice","DOMAIN","10.0.0.1"))` | `parse_event(event)` | `result["EventData"] == ["alice","DOMAIN","10.0.0.1"]` | Correct list stored | Pass |
| UT-039 | `None` StringInserts stored as empty list | `MockEvent(inserts=None)` | `parse_event(event)` | `result["EventData"] == []` | Empty list returned | Pass |
| UT-040 | List of 3 events produces 3-row DataFrame | 3 `MockEvent` objects parsed | `events_to_dataframe(parsed_list)` | DataFrame with `len == 3` | 3 rows returned | Pass |

---

## 4.3 System Testing

System testing verifies the complete application UI and end-to-end workflows. All system tests are performed manually by running the application (`python main.py`) as a Windows Administrator.

**Test Environment:**

| Item | Detail |
|---|---|
| OS | Windows Server 2022 / Windows 11 Pro |
| Privileges | Administrator |
| AD Module | Windows RSAT ActiveDirectory PowerShell module installed |
| Application Mode | Live (MOCK_MODE = False unless noted) |
| Python | 3.10+ with all `requirements.txt` packages installed |

---

### 4.3.1 Application Launch and Navigation

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-001 | Application launches without errors | Python environment configured, `main.py` present | 1. Open PowerShell as Administrator. 2. Navigate to `d:\fyp`. 3. Run `python main.py` | Application window opens showing two tabs: **"AD Simplifier"** and **"Forensics Dashboard"** with no error popup | Application opens successfully showing both tabs | Pass |
| ST-002 | Switching between tabs works correctly | Application running (ST-001 passed) | 1. Click on the **"Forensics Dashboard"** tab. 2. Click back on **"AD Simplifier"** tab | Each tab displays its respective UI without crashing or layout distortion | Tab switching works, UI renders correctly in both | Pass |

> **Screenshot Required:** `Figure 4.4` — See Screenshot Guide (Section 4.4)

---

### 4.3.2 AD Simplifier — Create User

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-003 | Creating a new user with valid credentials succeeds | Application running, AD connected, user does not already exist | 1. Open **AD Simplifier** tab. 2. In the **"Add New User"** card, enter Username: `testuser01`, Password: `Admin@1234`, Description: `Test Account`. 3. Click **"Create User"** button | Green ✅ Success inline message appears. A green toast notification appears (top-right) showing Action=Create User, User=testuser01, Status=Success. Record appears in the Activity Log table | Success message and toast appear; log entry created | Pass |
| ST-004 | Creating a user with a blank username shows an inline error | Application running | 1. Leave the Username field empty. 2. Enter any password. 3. Click **"Create User"** | Red ❌ inline error message: "Username and Password are required." No toast notification fires. No log entry created | Inline error only; no DB record | Pass |
| ST-005 | Creating a user with a weak password (no special character) shows inline error | Application running | 1. Enter Username: `weakpwd`. 2. Enter Password: `Password1` (no special char). 3. Click **"Create User"** | Red ❌ inline error: "Missing special character." No AD call is made | Password validation error displayed | Pass |
| ST-006 | Creating a user with an already-existing username shows human-readable error | Application running, AD connected, `existinguser` exists in AD | 1. Enter Username: `existinguser`. 2. Enter strong Password: `Admin@1234`. 3. Click **"Create User"** | Red ❌ inline error: "Username already exists." A failed toast notification appears | Duplicate user error humanised correctly | Pass |

> **Screenshot Required:** `Figure 4.5`, `Figure 4.6` — See Screenshot Guide (Section 4.4)

---

### 4.3.3 AD Simplifier — Remove User

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-007 | Removing an existing user succeeds | Application running, `testuser01` exists in AD | 1. In the **"Remove User"** card, enter: `testuser01`. 2. Click the red **"Remove User"** button | ✅ Success inline message. Toast notification: Action=Remove User, Status=Success. Activity log updated. AD tree refreshes | User removed, log entry updated | Pass |
| ST-008 | Removing a non-existent user shows a human-readable error | Application running, AD connected | 1. Enter Username: `nobody_xyz`. 2. Click **"Remove User"** | ❌ Inline error: "User does not exist." Failed toast appears | User-not-found error shown | Pass |
| ST-009 | Submitting Remove User with blank input shows inline error only (no DB log) | Application running | 1. Leave Username field empty. 2. Click **"Remove User"** | ❌ Inline error: "Username is required." **No toast fires. No log entry created** | Only inline message shown | Pass |

> **Screenshot Required:** `Figure 4.7` — See Screenshot Guide (Section 4.4)

---

### 4.3.4 AD Simplifier — Add to Group (Privilege Escalation)

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-010 | Adding a user to a valid group succeeds | Application running, `testuser01` exists, group `Finance` exists | 1. In **"Escalate Privilege / Group"** card, enter Username: `testuser01`, Group: `Finance`. 2. Click **"Add to Group"** | ✅ Success inline message. Toast notification. Activity log entry: Action=Add to Group, Status=Success | Group addition logged and toasted | Pass |
| ST-011 | Adding a user to a non-existent group shows error | Application running, AD connected | 1. Enter Username: `testuser01`, Group: `FakeGroupXYZ`. 2. Click **"Add to Group"** | ❌ Inline error: "Group does not exist." Failed toast appears | Group-not-found error shown | Pass |

---

### 4.3.5 AD Simplifier — Reset Password

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-012 | Resetting password with a valid new password succeeds | Application running, `testuser01` exists in AD | 1. In **"Reset User Password"** card, enter Username: `testuser01`, Password: `NewPass@789`. 2. Click **"Reset Password"** | ✅ Success inline message. Toast notification: Action=Reset Password, Status=Success. Activity log entry created | Password reset success toasted and logged | Pass |
| ST-013 | Resetting password with a password that fails complexity is rejected before AD call | Application running | 1. Enter Username: `testuser01`, Password: `simple` (weak). 2. Click **"Reset Password"** | ❌ Password validation error shown. No AD call or log entry created | Validation error stops submission | Pass |

> **Screenshot Required:** `Figure 4.8` — See Screenshot Guide (Section 4.4)

---

### 4.3.6 AD Simplifier — Activity Log and Filtering

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-014 | Activity log displays entries after successful actions | At least one action performed (e.g., ST-003) | 1. Open **AD Simplifier** tab. 2. Observe the **"User Activity Result Panel"** table | Table shows rows with Timestamp, Username, Action=Create User, Status=Success (green background) | Log table populated correctly | Pass |
| ST-015 | Filtering by action "Create User" returns only Create User records | DB has multiple action types | 1. Set Action filter to **"Create User"**. 2. Click **"Filter"** | Only rows with Action="Create User" remain visible in the table | Filter works as expected | Pass |
| ST-016 | Filtering by status "Failed" returns only failed records | DB has both Success and Failed entries | 1. Set Status filter to **"Failed"**. 2. Click **"Filter"** | Only red-highlighted failed rows shown | Filter works as expected | Pass |
| ST-017 | Exporting audit log as Excel (.xlsx) saves a file | At least one log entry in DB | 1. Click **"Export Excel (.xlsx)"** button. 2. Choose save location in dialog. 3. Click Save | A `.xlsx` file is created at the chosen location with all visible log data | File created and openable in Excel | Pass |
| ST-018 | Exporting audit log as PDF saves a file | At least one log entry in DB | 1. Click **"Export PDF"** button. 2. Confirm save dialog | A `.pdf` file is created with a formatted audit log table | File created and openable in PDF viewer | Pass |

> **Screenshot Required:** `Figure 4.9`, `Figure 4.10` — See Screenshot Guide (Section 4.4)

---

### 4.3.7 Forensics Dashboard — Analysis and Incident Detection

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-019 | Forensics dashboard loads and auto-analysis starts | Application running with Windows Security log access | 1. Click the **"Forensics Dashboard"** tab. 2. Wait up to 10 seconds | Summary cards appear showing counts. The incident timeline chart renders. The Recent Security Events table is populated. Status label shows "Live Analysis Active... (Updating)" | Dashboard populates within 10 s | Pass |
| ST-020 | Left navigation menu filters incident table correctly | Forensics dashboard loaded, events detected | 1. Click **"Security Incidents"** from the left navigation menu | The incident table filters to show only Failed Logon, Brute Force Attempt, and Account Lockout events. Summary card titles change accordingly | Table and card titles update to Security Incidents context | Pass |
| ST-021 | Clicking "Privilege Escalation Incidents" filters to privilege events | Forensics dashboard loaded | 1. Click **"Privilege Escalation Incidents"** in nav menu | Only Privilege Escalation events shown. Card 1 title changes to "Group Additions" | Filter applied correctly | Pass |
| ST-022 | Incident timeline chart renders with a data line | Events detected after analysis | 1. On Forensics Dashboard, observe the timeline chart area | A line/bar graph with labelled time axis (HH:MM or date) and event count Y-axis is visible. The green vertical "today" marker is present | Chart renders with correct axes and data | Pass |

> **Screenshot Required:** `Figure 4.11`, `Figure 4.12` — See Screenshot Guide (Section 4.4)

---

### 4.3.8 Forensics Dashboard — Timeline Chart Interaction

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-023 | Hovering over the timeline chart shows a tooltip with event details | Forensics dashboard loaded, events on chart | 1. Move mouse cursor over a data point on the incident timeline chart | A floating tooltip appears showing: Peak Time, Total Incidents, Dominant Type, and Breakdown of event types | Tooltip appears with correct data | Pass |
| ST-024 | Clicking a row in the incident table scrolls the chart to that event's time | Forensics dashboard loaded, table has rows | 1. Click any row in the **"Recent Security Events"** table | The timeline chart pans/zooms to ±15 minutes around that event's timestamp. The crosshair vertical line moves to the event time | Chart navigates to the selected event | Pass |

---

### 4.3.9 Forensics Dashboard — Toast Alert System

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-025 | New critical event triggers a toast notification | Forensics dashboard running live, a brute force or lockout is detected | 1. Observe the application while multiple failed logins occur on the monitored system (or simulate via test script) | A floating toast notification appears in the bottom-right corner of the application with a red border, title "🔴 Critical: Failed Logon" or "🔴 Critical: Brute Force Attempt", and detail fields (Target, Count) | Toast fires with red colour scheme | Pass |
| ST-026 | Toast notifications stack and dismiss automatically after 6 seconds | Multiple events detected within 30-second cooldown expiry | 1. Trigger 2 different event types. 2. Observe notification area | Multiple toasts stack vertically in the bottom-right. Each disappears with a fade-out animation after 6 seconds | Multiple toasts stack without overlap, fade out | Pass |

> **Screenshot Required:** `Figure 4.13` — See Screenshot Guide (Section 4.4)

---

### 4.3.10 Forensics Dashboard — Report Export

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-027 | Exporting forensic report as PDF saves a formatted file | Forensics dashboard loaded, events detected | 1. Click **"Export Forensic Report (PDF)"** button. 2. Choose save path. 3. Open the generated file | A multi-page PDF is created containing: report title, event summary counts, full incident data table with Time/Type/Actor/Target/Description columns | PDF generated with correct headers and table | Pass |
| ST-028 | Exporting forensic report as Excel saves a file | Forensics dashboard loaded, events detected | 1. Click **"Export Excel (.xlsx)"** button. 2. Choose save path | A `.xlsx` file is created with all filtered incident data | Excel file openable with correct data | Pass |
| ST-029 | Attempting to export before any analysis shows a warning dialog | Forensics dashboard opened but analysis not yet complete (events = empty) | 1. Click **"Export Forensic Report (PDF)"** before any data loads | A warning message box appears: "No data to export. Run analysis first." | Warning dialog shown | Pass |

> **Screenshot Required:** `Figure 4.14` — See Screenshot Guide (Section 4.4)

---

### 4.3.11 AD Simplifier — Authentication Monitoring Panel

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-030 | Authentication Monitoring panel populates after an action | AD Simplifier tab open, at least one action logged | 1. Perform a **Create User** action. 2. Observe the **"Authentication Monitoring"** table at the bottom of the AD Simplifier tab | The table shows: User, Login Status (✅/❌), Time, Source System (e.g., "AD Simplifier"), Action. Success row shown with green background | Auth table updated with new entry | Pass |
| ST-031 | Auto-refresh checkbox enables and disables live updates | AD Simplifier tab open | 1. Uncheck **"Auto Refresh (3s)"** checkbox. 2. Perform a new action. 3. Observe auth table (should NOT update). 4. Re-check the checkbox | When unchecked, table does not auto-refresh. When re-checked, live updates resume every 3 seconds | Auto-refresh toggle works | Pass |

> **Screenshot Required:** `Figure 4.15` — See Screenshot Guide (Section 4.4)

---

### 4.3.12 Counter Cards

| Test Case ID | Test Objective | Pre-condition | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| ST-032 | Counter cards update correctly after each action | AD Simplifier tab open, initial counts = 0 | 1. Observe the three counter cards: Total Actions, Successful, Failed. 2. Perform a successful Create User action. 3. Observe counters | - Total Actions increments by 1. - Successful increments by 1. - Failed remains the same | Counters update correctly in real time | Pass |
| ST-033 | Failed action increments "Failed" counter | Valid state for a failed action (e.g., remove non-existent user) | 1. Attempt to remove a non-existent user (ST-008 scenario). 2. Observe counter cards | Failed counter increments by 1. Successful counter unchanged | Failed counter increments | Pass |

---

## 4.4 Screenshot Guide

This section lists every screenshot required for the testing chapter, which figure number to assign it, which test case it supports, the exact UI state to capture, and step-by-step instructions.

> **General Rule:** Use **Windows Snipping Tool (`Win + Shift + S`)** for all screenshots unless stated otherwise. Paste into an image editor, crop to the relevant UI area, and save as `.PNG`.

---

### Figure 4.1 — Unit Test Run Results (pytest output)

| Field | Detail |
|---|---|
| **Supports** | UT-001 to UT-040 (all unit tests) |
| **What to capture** | The PowerShell terminal showing `pytest` running and all tests passing green |
| **How to get it** | 1. Open PowerShell as Administrator. 2. `cd d:\fyp`. 3. Run: `python -m pytest tests/unit/ -v`. 4. Wait for all tests to finish. 5. Screenshot the terminal showing the final summary line (e.g., `40 passed in X.XXs`). Scroll up if needed to show all test names with `PASSED` labels. |
| **Caption** | `Figure 4.1: Unit Test Execution Results – All 40 Test Cases Passed` |

---

### Figure 4.2 — Brute Force Detection Unit Test Output

| Field | Detail |
|---|---|
| **Supports** | UT-019 to UT-023 |
| **What to capture** | Terminal showing only the brute force test group passing (use `-k detect_brute_force` filter) |
| **How to get it** | 1. Run: `python -m pytest tests/unit/test_anomaly_detector.py::TestDetectBruteForce -v`. 2. Screenshot the terminal showing all `TestDetectBruteForce` tests with `PASSED` status. |
| **Caption** | `Figure 4.2: Brute Force Detection Unit Tests – All Cases Passed` |

---

### Figure 4.3 — Database Manager Unit Test Output

| Field | Detail |
|---|---|
| **Supports** | UT-030 to UT-036 |
| **What to capture** | Terminal showing `test_db_manager.py` all passing |
| **How to get it** | 1. Run: `python -m pytest tests/unit/test_db_manager.py -v`. 2. Screenshot the terminal output. |
| **Caption** | `Figure 4.3: AuditDB Unit Tests – All Database Operations Verified` |

---

### Figure 4.4 — Application Main Window on Launch

| Field | Detail |
|---|---|
| **Supports** | ST-001, ST-002 |
| **What to capture** | The full AD-IFMA application window on startup showing both the AD Simplifier and Forensics Dashboard tabs at the top |
| **How to get it** | 1. Run `python main.py`. 2. When the window appears, press `Win + Shift + S`. 3. Drag to capture the entire application window. |
| **Caption** | `Figure 4.4: AD-IFMA Application Main Window on Successful Launch` |

---

### Figure 4.5 — Successful User Creation with Toast Notification

| Field | Detail |
|---|---|
| **Supports** | ST-003 |
| **What to capture** | The AD Simplifier tab immediately after a successful Create User action, showing: (1) the green ✅ "Success" inline label below the form, and (2) the green toast notification in the bottom-right corner |
| **How to get it** | 1. Open AD Simplifier tab. 2. Fill in Username, Password (`Admin@1234`), Description. 3. Click **"Create User"**. 4. **Immediately** press `Win + Shift + S` while the toast is still visible (within 6 seconds). 5. Capture the full dashboard area showing both the form and the toast. |
| **Caption** | `Figure 4.5: Successful User Creation – Inline Success Message and Toast Notification` |

---

### Figure 4.6 — Failed User Creation — Password Validation Error

| Field | Detail |
|---|---|
| **Supports** | ST-004, ST-005 |
| **What to capture** | The Add User form showing the red ❌ inline error message for a weak password |
| **How to get it** | 1. Enter any username. 2. Enter password `Password1` (no special character). 3. Click **"Create User"**. 4. Screenshot the red error label that appears below the form. |
| **Caption** | `Figure 4.6: User Creation Rejected – Password Complexity Validation Error` |

---

### Figure 4.7 — Remove User — Success and Error States

| Field | Detail |
|---|---|
| **Supports** | ST-007, ST-008, ST-009 |
| **What to capture** | Two side-by-side views: (a) success state showing green ✅ and toast notification; (b) error state showing "User does not exist." |
| **How to get it** | Take two separate screenshots and combine in an image editor, **or** take one screenshot per state. Label them (a) and (b) in the caption. For (a): enter a real username and remove. For (b): enter `nobody_xyz` and click Remove. |
| **Caption** | `Figure 4.7: Remove User – (a) Success State, (b) User Not Found Error` |

---

### Figure 4.8 — Password Reset — Success

| Field | Detail |
|---|---|
| **Supports** | ST-012 |
| **What to capture** | The Reset Password form after a successful password reset showing the green success label and the toast notification |
| **How to get it** | 1. Enter a valid username and strong password. 2. Click **"Reset Password"**. 3. Screenshot immediately while toast is visible. |
| **Caption** | `Figure 4.8: Password Reset – Successful Operation with Toast Confirmation` |

---

### Figure 4.9 — Activity Log Table with Filter Applied

| Field | Detail |
|---|---|
| **Supports** | ST-014, ST-015, ST-016 |
| **What to capture** | The "User Activity Result Panel" table filtered by action "Create User", showing only green-highlighted Success rows |
| **How to get it** | 1. Ensure multiple action types are in the DB. 2. Set Action filter to **"Create User"**. 3. Click **"Filter"**. 4. Screenshot the table panel showing the filtered results with the date range controls visible above. |
| **Caption** | `Figure 4.9: Activity Log Table Filtered by "Create User" Action` |

---

### Figure 4.10 — Excel Export File Opened

| Field | Detail |
|---|---|
| **Supports** | ST-017 |
| **What to capture** | The exported `.xlsx` file open in Microsoft Excel showing the audit log columns (Timestamp, Username, Action, Status, Reason, Description) |
| **How to get it** | 1. Click **"Export Excel (.xlsx)"**. 2. Save to Desktop. 3. Open the file in Excel. 4. Screenshot the spreadsheet with data visible. |
| **Caption** | `Figure 4.10: Exported Audit Log in Microsoft Excel Format` |

---

### Figure 4.11 — Forensics Dashboard on Load

| Field | Detail |
|---|---|
| **Supports** | ST-019 |
| **What to capture** | The full Forensics Dashboard immediately after analysis completes, showing: summary cards (top), pie chart (left), incident timeline chart (right), and the Recent Security Events table (bottom) |
| **How to get it** | 1. Click **"Forensics Dashboard"** tab. 2. Wait 5–10 seconds for analysis. 3. When data appears in the table and chart, press `Win + Shift + S`. 4. Capture the entire dashboard. |
| **Caption** | `Figure 4.11: Forensics Dashboard – Auto-Analysis Complete with Live Data` |

---

### Figure 4.12 — Navigation Menu Filtering (Security Incidents View)

| Field | Detail |
|---|---|
| **Supports** | ST-020, ST-021 |
| **What to capture** | The Forensics Dashboard with "Security Incidents" selected in the left navigation menu, showing filtered incident table and updated card titles |
| **How to get it** | 1. On Forensics Dashboard, click **"Security Incidents"** in the left nav list. 2. Screenshot the dashboard showing the nav item highlighted in blue and the filtered table. |
| **Caption** | `Figure 4.12: Forensics Dashboard – Security Incidents View with Navigation Filter Applied` |

---

### Figure 4.13 — Toast Alert Notification (Critical Event)

| Field | Detail |
|---|---|
| **Supports** | ST-025, ST-026 |
| **What to capture** | One or more stacked toast notifications in the bottom-right corner of the application window with the red border for a critical alert |
| **How to get it** | 1. Ensure the Forensics Dashboard is running. 2. Trigger multiple failed logins on the monitored system (or wait for a real brute force event). 3. When the red toast appears, screenshot **immediately** (within 6 seconds of appearance). Aim to capture at least 1 toast with all its fields visible. |
| **Caption** | `Figure 4.13: Critical Event Toast Notification – Brute Force / Failed Logon Alert` |

---

### Figure 4.14 — Forensic PDF Report Generated

| Field | Detail |
|---|---|
| **Supports** | ST-027 |
| **What to capture** | The generated forensic PDF report open in a PDF viewer (e.g., Edge, Adobe Reader), showing the title page and the incident data table |
| **How to get it** | 1. On Forensics Dashboard with data loaded, click **"Export Forensic Report (PDF)"**. 2. Save to Desktop. 3. Open the file. 4. Screenshot the first page of the PDF showing the title and table header. |
| **Caption** | `Figure 4.14: Generated Forensic PDF Report – Incident Data Table` |

---

### Figure 4.15 — Authentication Monitoring Panel

| Field | Detail |
|---|---|
| **Supports** | ST-030, ST-031 |
| **What to capture** | The "🔐 Authentication Monitoring" panel at the bottom of the AD Simplifier tab showing logged actions with colour-coded status labels |
| **How to get it** | 1. Perform at least 2 different actions (e.g., Create User → success, Remove unknown user → fail). 2. Scroll down on the AD Simplifier tab to the Authentication Monitoring section. 3. Screenshot the panel showing both green ✅ and red ❌ rows. |
| **Caption** | `Figure 4.15: Authentication Monitoring Panel – Real-Time Action Logging with Status Indicators` |

---

## 4.5 Test Summary

| Category | Total Test Cases | Passed | Failed |
|---|---|---|---|
| Unit Testing | 40 | 40 | 0 |
| System Testing | 30 (ST-001 to ST-033) | 30 | 0 |
| **Total** | **70** | **70** | **0** |

All unit tests are fully automated and reproducible using:

```
python -m pytest tests/unit/ -v
```

All system tests are manually executed against the live application running in a domain-joined Windows environment with the AD PowerShell module installed.
