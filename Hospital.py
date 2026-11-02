import csv
from datetime import datetime
import hashlib
import hmac
import secrets
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk
import mysql.connector

#DATABASE SETTINGS
DB_HOST = "localhost"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = "@RhonilenSQL30"
DB_NAME = "hospital_db"


def get_connection():
  """Bawat operation ay may sariling database connection."""
  return mysql.connector.connect(
      host=DB_HOST,
      port=DB_PORT,
      user=DB_USER,
      password=DB_PASSWORD,
      database=DB_NAME,
      connection_timeout=5,
  )


def close_database(connection, cursor):
  if cursor is not None:
    cursor.close()
  if connection is not None and connection.is_connected():
    connection.close()


def database_error(error):
  if error.errno == 1062:
    messagebox.showwarning(
        "Duplicate Patient", "May gumagamit na ng Patient No. na ito."
    )
  else:
    messagebox.showerror(
        "Database Error",
        "Hindi natuloy ang operation. Check ang MySQL service, database import,"
        " at DB settings sa app.py.\n\n"
        + str(error),
    )


#PASSWORD HELPERS
PASSWORD_ITERATIONS = 120000


def hash_password(password, salt):
  return hashlib.pbkdf2_hmac(
      "sha256",
      password.encode("utf-8"),
      bytes.fromhex(salt),
      PASSWORD_ITERATIONS,
  ).hex()


def password_matches(password, salt, saved_hash):
  return hmac.compare_digest(hash_password(password, salt), saved_hash)


#FORM AND SESSION VARIABLES
current_user_id = None
current_username = ""
selected_patient_id = None

GENDERS = ("", "Female", "Male", "Prefer not to say")
TRIAGE_LEVELS = ("Critical", "Urgent", "Stable")
STATUSES = ("Admitted", "Under Treatment", "Discharged", "Dead on Arrival")

COLUMNS = (
    "patient_id",
    "patient_no",
    "full_name",
    "age",
    "gender",
    "room_no",
    "condition_type",
    "triage_status",
    "admission_date",
    "status",
)
HEADINGS = (
    "ID",
    "Patient No.",
    "Full Name",
    "Age",
    "Gender",
    "Room / Ward",
    "Condition / Disease",
    "Triage Priority",
    "Admission Date",
    "Status",
)


#LOGIN / LOGOUT
def login():
  global current_user_id, current_username
  username = username_var.get().strip()
  password = login_password_var.get()
  if not username or not password:
    messagebox.showwarning("Missing Login", "Enter your username and password.")
    return

  connection = None
  cursor = None
  try:
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT user_id, username, password_salt, password_hash "
        "FROM users WHERE username = %s",
        (username,),
    )
    user = cursor.fetchone()
    if user is None or not password_matches(password, user[2], user[3]):
      login_password_var.set("")
      messagebox.showwarning("Login Failed", "Incorrect username or password.")
      return
    current_user_id = user[0]
    current_username = user[1]
    login_password_var.set("")
    show_password_var.set(False)
    toggle_password()
    login_frame.pack_forget()
    main_frame.pack(fill="both", expand=True)
    welcome_var.set("Logged in as: " + current_username)
    clear_form()
    refresh_patients()
    search_entry.focus_set()
  except mysql.connector.Error as error:
    database_error(error)
  finally:
    close_database(connection, cursor)


def logout():
  global current_user_id, current_username
  if not messagebox.askyesno("Logout", "Log out of the system?"):
    return
  clear_form()
  for item in tree.get_children():
    tree.delete(item)
  search_var.set("")
  triage_filter_var.set("All")
  status_filter_var.set("All")
  summary_var.set("")
  for variable in count_vars:
    variable.set("0")
  displayed_var.set("0 records displayed")
  current_user_id = None
  current_username = ""
  main_frame.pack_forget()
  username_var.set("")
  login_password_var.set("")
  show_password_var.set(False)
  toggle_password()
  login_frame.pack(fill="both", expand=True)
  username_entry.focus_set()


def toggle_password():
  login_password_entry.configure(show="" if show_password_var.get() else "*")


def change_password():
  if current_user_id is None:
    return
  window = tk.Toplevel(root)
  window.title("Change Password")
  window.resizable(False, False)
  window.transient(root)
  window.grab_set()
  width, height = 500, 320
  x = root.winfo_rootx() + (root.winfo_width() - width) // 2
  y = root.winfo_rooty() + (root.winfo_height() - height) // 2
  window.geometry(f"{width}x{height}+{x}+{y}")
  panel = ttk.Frame(window, padding=20)
  panel.pack(fill="both", expand=True)
  old_var = tk.StringVar()
  new_var = tk.StringVar()
  confirm_var = tk.StringVar()
  for row, (label, variable) in enumerate(
      (("Current Password", old_var), ("New Password", new_var), ("Confirm Password", confirm_var))
  ):
    ttk.Label(panel, text=label).grid(row=row, column=0, sticky="w", pady=8)
    entry = ttk.Entry(panel, textvariable=variable, show="*", width=25)
    entry.grid(row=row, column=1, padx=8, pady=8)
    if row == 0:
      entry.focus_set()
  ttk.Label(panel, text="New password: 6 to 128 characters.").grid(
      row=3, column=0, columnspan=2, pady=5
  )

  def save_password():
    new_password = new_var.get()
    if not 6 <= len(new_password) <= 128 or not new_password.strip():
      messagebox.showwarning(
          "Invalid Password", "Use 6 to 128 characters.", parent=window
      )
      return
    if new_password != confirm_var.get():
      messagebox.showwarning(
          "Mismatch", "New passwords do not match.", parent=window
      )
      return
    connection = None
    cursor = None
    try:
      connection = get_connection()
      cursor = connection.cursor()
      cursor.execute(
          "SELECT password_salt, password_hash FROM users WHERE user_id = %s",
          (current_user_id,),
      )
      user = cursor.fetchone()
      if user is None or not password_matches(old_var.get(), user[0], user[1]):
        messagebox.showwarning(
            "Incorrect Password", "Current password is incorrect.", parent=window
        )
        return
      salt = secrets.token_hex(16)
      cursor.execute(
          "UPDATE users SET password_salt = %s, password_hash = %s WHERE"
          " user_id = %s",
          (salt, hash_password(new_password, salt), current_user_id),
      )
      connection.commit()
      messagebox.showinfo(
          "Success", "Password changed successfully.", parent=window
      )
      window.destroy()
    except mysql.connector.Error as error:
      database_error(error)
    finally:
      close_database(connection, cursor)

  ttk.Button(
      panel,
      text="Save Password",
      style="Primary.TButton",
      command=save_password,
  ).grid(row=4, column=0, pady=12)
  ttk.Button(panel, text="Cancel", command=window.destroy).grid(
      row=4, column=1, pady=12
  )


#FORM HELPERS / VALIDATION
def clear_form():
  global selected_patient_id
  selected_patient_id = None
  form_title_var.set("Admit new patient")
  for variable in patient_vars:
    variable.set("")
  # Leave patient_no blank because it will auto-generate!
  patient_no_var.set("(Auto-generated)")
  triage_var.set("Critical")
  status_var.set("Admitted")
  date_var.set(datetime.now().strftime("%Y-%m-%d %H:%M"))
  for item in tree.selection():
    tree.selection_remove(item)


def validate_form():
  # Note: patient_no is handled automatically now, so we exclude it from manual checks
  values = tuple(variable.get().strip() for variable in patient_vars)
  # values layout: (patient_no, full_name, age, gender, room_no, condition_type, triage_status, admission_date, status)
  _, full_name, age, gender, room_no, condition_type, triage_status, admission_date, status = values

  if not full_name or not age or not room_no or not condition_type or not admission_date:
    messagebox.showwarning(
        "Missing Data", "Full Name, Age, Room, Condition, and Date are required."
    )
    return None

  try:
    age_int = int(age)
    if age_int < 0 or age_int > 150:
      raise ValueError()
  except ValueError:
    messagebox.showwarning("Invalid Age", "Age must be a valid number between 0 and 150.")
    return None

  if gender not in GENDERS or triage_status not in TRIAGE_LEVELS or status not in STATUSES:
    messagebox.showwarning("Invalid Selection", "Please select valid options from dropdowns.")
    return None

  return (full_name, age_int, gender, room_no, condition_type, triage_status, admission_date, status)

def on_tree_select(event=None):
  global selected_patient_id
  selected = tree.selection()
  if not selected:
    return
  values = tree.item(selected[0], "values")
  selected_patient_id = int(values[0])
  form_title_var.set("Edit patient details")
  for variable, value in zip(patient_vars, values[1:]):
    variable.set(value)


# ---------------- READ / SEARCH / FILTER ----------------
def load_patients():
  if current_user_id is None:
    return
  connection = None
  cursor = None
  try:
    connection = get_connection()
    cursor = connection.cursor()
    keyword = search_var.get().strip()
    pattern = "%" + keyword + "%"
    
    sql = """
        SELECT patient_id, patient_no, full_name, age, gender,
               room_no, condition_type, triage_status, admission_date, status
        FROM patients
        WHERE (patient_no LIKE %s OR full_name LIKE %s OR condition_type LIKE %s OR room_no LIKE %s)
    """
    parameters = [pattern, pattern, pattern, pattern]
    
    if triage_filter_var.get() != "All":
      sql += " AND triage_status = %s"
      parameters.append(triage_filter_var.get())
      
    if status_filter_var.get() != "All":
      sql += " AND status = %s"
      parameters.append(status_filter_var.get())
      
    sql += " ORDER BY patient_id DESC"
    cursor.execute(sql, tuple(parameters))
    rows = cursor.fetchall()
    
    cursor.execute("""
        SELECT COUNT(*), 
               COALESCE(SUM(triage_status = 'Critical'), 0),
               COALESCE(SUM(triage_status = 'Urgent'), 0),
               COALESCE(SUM(triage_status = 'Stable'), 0) 
        FROM patients
    """)
    total, critical, urgent, stable = cursor.fetchone()
    
    clear_form()
    for item in tree.get_children():
      tree.delete(item)
      
    for index, row in enumerate(rows):
      tree.insert(
          "",
          "end",
          values=tuple("" if value is None else value for value in row),
          tags=("even" if index % 2 == 0 else "odd",),
      )
      
    for variable, number in zip(count_vars, (total, critical, urgent, stable)):
      variable.set(str(number))
      
    displayed_var.set(f"{len(rows)} records displayed")
    summary_var.set(
        f"Total: {total}    Critical: {critical}    Urgent: {urgent}    "
        f"Stable: {stable}    |    Showing: {len(rows)}"
    )
  except mysql.connector.Error as error:
    database_error(error)
  finally:
    close_database(connection, cursor)


def refresh_patients():
  search_var.set("")
  triage_filter_var.set("All")
  status_filter_var.set("All")
  load_patients()


# ---------------- CREATE ----------------
def add_patient():
  if current_user_id is None:
    return
  validated_data = validate_form()
  if validated_data is None:
    return
    
  connection = None
  cursor = None
  try:
    connection = get_connection()
    cursor = connection.cursor()
    
    # 1. Insert patient first to get the auto-incremented patient_id
    cursor.execute(
        """
        INSERT INTO patients
            (patient_no, full_name, age, gender, room_no,
             condition_type, triage_status, admission_date, status)
        VALUES ('TEMP', %s, %s, %s, %s, %s, %s, %s, %s)
    """,
        validated_data,
    )
    
    new_id = cursor.lastrowid
    # 2. Automatically generate a clean patient number like PT-001, PT-002 based on its ID
    auto_patient_no = f"PT-{new_id:03d}"
    
    # 3. Update the row with the real auto-generated patient_no
    cursor.execute(
        "UPDATE patients SET patient_no = %s WHERE patient_id = %s",
        (auto_patient_no, new_id)
    )
    
    connection.commit()
    messagebox.showinfo("Success", f"Patient admitted successfully! Assigned ID: {auto_patient_no}")
    clear_form()
    refresh_patients()
  except mysql.connector.Error as error:
    database_error(error)
  finally:
    close_database(connection, cursor)

# ---------------- UPDATE ----------------
def update_patient():
  if current_user_id is None:
    return
  if selected_patient_id is None:
    messagebox.showwarning("Select Patient", "Select a patient from the table first.")
    return
  values = validate_form()
  if values is None:
    return
  connection = None
  cursor = None
  try:
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        UPDATE patients SET full_name = %s,
            age = %s, gender = %s, room_no = %s, condition_type = %s,
            triage_status = %s, admission_date = %s, status = %s
        WHERE patient_id = %s
    """,
        values + (selected_patient_id,),
    )
    if cursor.rowcount == 0:
      cursor.execute(
          "SELECT patient_id FROM patients WHERE patient_id = %s",
          (selected_patient_id,),
      )
      if cursor.fetchone() is None:
        messagebox.showwarning(
            "Not Found", "This patient record was removed. Refreshing table."
        )
        clear_form()
        load_patients()
        return
    connection.commit()
    messagebox.showinfo("Success", "Patient details updated successfully.")
    clear_form()
    load_patients()
  except mysql.connector.Error as error:
    database_error(error)
  finally:
    close_database(connection, cursor)


# ---------------- DELETE ----------------
def delete_patient():
  if current_user_id is None:
    return
  if selected_patient_id is None:
    messagebox.showwarning("Select Patient", "Select a patient from the table first.")
    return
  if not messagebox.askyesno(
      "Confirm Discharge / Removal",
      "Remove record for patient " + patient_no_var.get() + "?",
  ):
    return
  connection = None
  cursor = None
  try:
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM patients WHERE patient_id = %s", (selected_patient_id,))
    if cursor.rowcount == 0:
      messagebox.showwarning(
          "Not Found", "This patient has already been removed."
      )
    else:
      connection.commit()
      messagebox.showinfo("Success", "Patient record deleted successfully.")
    clear_form()
    load_patients()
  except mysql.connector.Error as error:
    database_error(error)
  finally:
    close_database(connection, cursor)


# ---------------- EXPORT ----------------
def export_csv():
  if current_user_id is None:
    return
  items = tree.get_children()
  if not items:
    messagebox.showwarning(
        "No Records", "There are no displayed patient records to export."
    )
    return
  filename = filedialog.asksaveasfilename(
      title="Export Patient Records",
      defaultextension=".csv",
      initialfile="hospital_patient_records.csv",
      filetypes=[("CSV files", "*.csv")],
  )
  if not filename:
    return
  try:
    with open(filename, "w", newline="", encoding="utf-8-sig") as file:
      writer = csv.writer(file)
      writer.writerow(HEADINGS)
      for item in items:
        values = tree.item(item, "values")
        writer.writerow([
            "'" + str(value)
            if str(value).lstrip().startswith(("=", "+", "-", "@"))
            else value
            for value in values
        ])
    messagebox.showinfo(
        "Export Complete", f"Exported {len(items)} record(s).\n\n{filename}"
    )
  except OSError as error:
    messagebox.showerror("Export Error", str(error))


def show_help():
  messagebox.showinfo(
      "Hospital System Guide",
      "1. Fill out the form, then click 'Admit Patient'.\n"
      "2. Click any row in the directory table to edit its details.\n"
      "3. Select a row and click 'Delete / Discharge' to remove it.\n"
      "4. 'Clear' empties the form inputs.\n"
      "5. Search filters by Patient No., Name, Room, or Condition.\n"
      "6. Use Triage or Status filters for quick categorization.\n"
      "7. 'Export CSV' saves currently displayed records.\n\n"
      "F11: Full screen    Esc: Window mode",
  )


def toggle_fullscreen(event=None):
  root.attributes("-fullscreen", not root.attributes("-fullscreen"))
  return "break"


def leave_fullscreen(event=None):
  root.attributes("-fullscreen", False)
  return "break"


def exit_program():
  if messagebox.askyesno("Exit", "Close the Hospital Management System?"):
    root.destroy()


# ---------------- WINDOW & UI SETUP ----------------
root = tk.Tk()
root.title("Hospital Patient & Triage Management System")
root.geometry("1280x800")
root.minsize(960, 720)
root.attributes("-fullscreen", True)
root.protocol("WM_DELETE_WINDOW", exit_program)
root.bind("<F11>", toggle_fullscreen)
root.bind("<Escape>", leave_fullscreen)


def pick_font(*names):
  """Use the first installed font; Tk substitutes if none are found."""
  available = set(tkfont.families(root))
  for name in names:
    if name in available:
      return name
  return names[-1]


BODY_FONT = pick_font("Segoe UI", "Helvetica Neue", "Noto Sans", "DejaVu Sans", "Helvetica")
DISPLAY_FONT = pick_font("Georgia", "Cambria", "Noto Serif", "DejaVu Serif", "Times")

# Palette: cool paper page, deep teal chrome, triage colors reserved for triage.
PAGE = "#edf1f0"
WHITE = "#ffffff"
INK = "#16232b"
MUTED = "#5f6f76"
BORDER = "#d3dddb"
SIDEBAR = "#113a3f"
SIDEBAR_HOVER = "#1a4f55"
SIDEBAR_ACTIVE = "#236a70"
SIDEBAR_TEXT = "#d4e4e3"
SIDEBAR_MUTED = "#8fb0b0"
TEAL = "#0e6b6b"
TEAL_DARK = "#0a5555"
SOFT = "#e2ebea"
SOFT_HOVER = "#d2dfdd"
ROW_ALT = "#f5f8f7"
ROW_SELECTED = "#cde5e2"
CRITICAL = "#c0262d"
URGENT = "#b36b00"
STABLE = "#2f7d4f"
DANGER_BG = "#fbe8e6"
DANGER_HOVER = "#f5d1cd"

root.configure(background=PAGE)
root.option_add("*TCombobox*Listbox.background", WHITE)
root.option_add("*TCombobox*Listbox.foreground", INK)
root.option_add("*TCombobox*Listbox.selectBackground", TEAL)
root.option_add("*TCombobox*Listbox.selectForeground", WHITE)
root.option_add("*TCombobox*Listbox.font", (BODY_FONT, 10))

style = ttk.Style(root)
style.theme_use("clam")
style.configure(".", font=(BODY_FONT, 10), background=PAGE, foreground=INK)

# Frames
style.configure("TFrame", background=PAGE)
style.configure("Card.TFrame", background=WHITE)
style.configure("Nav.TFrame", background=SIDEBAR)

# Labels
style.configure("TLabel", background=PAGE, foreground=INK)
style.configure("Muted.TLabel", foreground=MUTED, font=(BODY_FONT, 9))
style.configure("Card.TLabel", background=WHITE, foreground=INK)
style.configure("Field.TLabel", background=WHITE, foreground=MUTED, font=(BODY_FONT, 9))
style.configure("CardMuted.TLabel", background=WHITE, foreground=MUTED, font=(BODY_FONT, 9))
style.configure("Title.TLabel", font=(DISPLAY_FONT, 24, "bold"))
style.configure("Section.TLabel", background=WHITE, font=(DISPLAY_FONT, 15, "bold"))
style.configure("LoginTitle.TLabel", background=WHITE, font=(DISPLAY_FONT, 26, "bold"))
style.configure("Stat.TLabel", background=WHITE, font=(DISPLAY_FONT, 28, "bold"))
style.configure("Nav.TLabel", background=SIDEBAR, foreground=SIDEBAR_TEXT)
style.configure("NavMuted.TLabel", background=SIDEBAR, foreground=SIDEBAR_MUTED, font=(BODY_FONT, 9))
style.configure("Brand.TLabel", background=SIDEBAR, foreground=WHITE, font=(DISPLAY_FONT, 22, "bold"))
style.configure("Hero.TLabel", background=SIDEBAR, foreground=WHITE, font=(DISPLAY_FONT, 26, "bold"))
style.configure("HeroSub.TLabel", background=SIDEBAR, foreground=SIDEBAR_TEXT, font=(BODY_FONT, 11))

# Inputs
for name in ("TEntry", "TCombobox"):
  style.configure(
      name,
      fieldbackground=WHITE, foreground=INK,
      bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
      padding=(8, 6),
  )
  style.map(
      name,
      bordercolor=[("focus", TEAL)],
      lightcolor=[("focus", TEAL)],
      darkcolor=[("focus", TEAL)],
  )
style.configure("TCombobox", background=SOFT, arrowcolor=MUTED)
style.map(
    "TCombobox",
    fieldbackground=[("readonly", WHITE)],
    selectbackground=[("readonly", WHITE)],
    selectforeground=[("readonly", INK)],
)
style.map("TEntry", fieldbackground=[("readonly", SOFT)])
style.configure("Login.TEntry", padding=(12, 10))
style.configure("TCheckbutton", background=WHITE, foreground=MUTED, font=(BODY_FONT, 9))
style.map("TCheckbutton", background=[("active", WHITE)])


# Buttons: flat fills, no bevel.
def button_style(name, background, foreground, hover, padding=(14, 9), anchor="center"):
  style.configure(
      name,
      background=background, foreground=foreground,
      bordercolor=background, lightcolor=background, darkcolor=background,
      borderwidth=1, relief="flat", padding=padding, anchor=anchor,
      font=(BODY_FONT, 10, "bold"),
  )
  style.map(
      name,
      background=[("pressed", hover), ("active", hover)],
      bordercolor=[("pressed", hover), ("active", hover)],
      lightcolor=[("pressed", hover), ("active", hover)],
      darkcolor=[("pressed", hover), ("active", hover)],
  )


button_style("TButton", SOFT, INK, SOFT_HOVER)
button_style("Primary.TButton", TEAL, WHITE, TEAL_DARK)
button_style("Secondary.TButton", SOFT, INK, SOFT_HOVER)
button_style("Danger.TButton", DANGER_BG, CRITICAL, DANGER_HOVER)
button_style("Nav.TButton", SIDEBAR, SIDEBAR_TEXT, SIDEBAR_HOVER, padding=(14, 11), anchor="w")
button_style("Selected.Nav.TButton", SIDEBAR_ACTIVE, WHITE, SIDEBAR_ACTIVE, padding=(14, 11), anchor="w")

# Table
style.configure(
    "Treeview",
    background=WHITE, fieldbackground=WHITE, foreground=INK,
    rowheight=38, font=(BODY_FONT, 10), borderwidth=0,
)
style.map(
    "Treeview",
    background=[("selected", ROW_SELECTED)],
    foreground=[("selected", INK)],
)
style.configure(
    "Treeview.Heading",
    background=SOFT, foreground=INK, font=(BODY_FONT, 9, "bold"),
    padding=(10, 10), relief="flat", borderwidth=0,
)
style.map("Treeview.Heading", background=[("active", SOFT_HOVER)])
style.configure(
    "TScrollbar",
    background=SOFT_HOVER, troughcolor=ROW_ALT, bordercolor=BORDER,
    lightcolor=SOFT_HOVER, darkcolor=SOFT_HOVER, arrowcolor=MUTED,
)

# ---------------- TKINTER VARIABLES ----------------
username_var = tk.StringVar()
login_password_var = tk.StringVar()
show_password_var = tk.BooleanVar(value=False)
welcome_var = tk.StringVar()
summary_var = tk.StringVar()
form_title_var = tk.StringVar(value="Admit new patient")
count_vars = [tk.StringVar(value="0") for _ in range(4)]
displayed_var = tk.StringVar(value="0 records displayed")

patient_no_var = tk.StringVar()
full_name_var = tk.StringVar()
age_var = tk.StringVar()
gender_var = tk.StringVar()
room_var = tk.StringVar()
condition_var = tk.StringVar()
triage_var = tk.StringVar(value="Critical")
date_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d %H:%M"))
status_var = tk.StringVar(value="Admitted")

patient_vars = (
    patient_no_var, full_name_var, age_var, gender_var,
    room_var, condition_var, triage_var, date_var, status_var
)
search_var = tk.StringVar()
triage_filter_var = tk.StringVar(value="All")
status_filter_var = tk.StringVar(value="All")

# ---------------- LOGIN SCREEN ----------------
login_frame = ttk.Frame(root, padding=20)
login_frame.pack(fill="both", expand=True)
login_card = ttk.Frame(login_frame, style="Card.TFrame", width=900, height=480)
login_card.place(relx=0.5, rely=0.5, anchor="center")
login_card.pack_propagate(False)

login_brand = ttk.Frame(login_card, style="Nav.TFrame", width=450, padding=36)
login_brand.pack(side="left", fill="y")
login_brand.pack_propagate(False)
ttk.Label(login_brand, text="Hospital ER", style="Brand.TLabel").pack(anchor="w", pady=(4, 44))
ttk.Label(login_brand, text="Patient &\nTriage Management\nSystem", style="Hero.TLabel", justify="left").pack(anchor="w")
ttk.Label(login_brand, text="Emergency ward records\nand priority tracking.", style="HeroSub.TLabel", justify="left").pack(anchor="w", pady=(22, 0))
ttk.Label(login_brand, text="Medical staff portal", style="NavMuted.TLabel").pack(side="bottom", anchor="w")

login_panel = ttk.Frame(login_card, style="Card.TFrame", padding=(48, 40))
login_panel.pack(side="left", fill="both", expand=True)
ttk.Label(login_panel, text="Staff sign in", style="LoginTitle.TLabel").pack(anchor="w")
ttk.Label(login_panel, text="Enter your credentials to open patient records.", style="CardMuted.TLabel").pack(anchor="w", pady=(6, 24))


ttk.Label(login_panel, text="Username", style="Field.TLabel").pack(anchor="w", pady=(0, 4))
username_entry = ttk.Entry(login_panel, textvariable=username_var, style="Login.TEntry")
username_entry.pack(fill="x", pady=(0, 14))

ttk.Label(login_panel, text="Password", style="Field.TLabel").pack(anchor="w", pady=(0, 4))
login_password_entry = ttk.Entry(login_panel, textvariable=login_password_var, show="*", style="Login.TEntry")
login_password_entry.pack(fill="x", pady=(0, 10))

ttk.Checkbutton(login_panel, text="Show password", variable=show_password_var, command=toggle_password).pack(anchor="w", pady=(0, 18))
ttk.Button(login_panel, text="Sign in", style="Primary.TButton", command=login).pack(fill="x")
ttk.Button(login_panel, text="Exit application", style="Secondary.TButton", command=exit_program).pack(fill="x", pady=(10, 0))
ttk.Label(login_frame, text="Default login: admin / admin123", style="Muted.TLabel").pack(side="bottom", pady=8)

username_entry.bind("<Return>", lambda event: login())
login_password_entry.bind("<Return>", lambda event: login())

# ---------------- MAIN WORKSPACE ----------------
main_frame = ttk.Frame(root)
sidebar = ttk.Frame(main_frame, style="Nav.TFrame", width=210, padding=(14, 26))
sidebar.pack(side="left", fill="y")
sidebar.pack_propagate(False)

ttk.Label(sidebar, text="Hospital", style="Brand.TLabel").pack(anchor="w", padx=12)
ttk.Label(sidebar, text="ER & ward portal", style="NavMuted.TLabel").pack(anchor="w", padx=12, pady=(2, 32))

ttk.Button(sidebar, text="Patient directory", style="Selected.Nav.TButton", command=lambda: search_entry.focus_set()).pack(fill="x", pady=2)
ttk.Button(sidebar, text="Export CSV", style="Nav.TButton", command=export_csv).pack(fill="x", pady=2)
ttk.Button(sidebar, text="Help & guide", style="Nav.TButton", command=show_help).pack(fill="x", pady=2)

ttk.Button(sidebar, text="Exit application", style="Nav.TButton", command=exit_program).pack(side="bottom", fill="x", pady=2)
ttk.Button(sidebar, text="Log out", style="Nav.TButton", command=logout).pack(side="bottom", fill="x", pady=2)
ttk.Button(sidebar, text="Change password", style="Nav.TButton", command=change_password).pack(side="bottom", fill="x", pady=2)
ttk.Label(sidebar, textvariable=welcome_var, style="NavMuted.TLabel", wraplength=170).pack(side="bottom", anchor="w", padx=12, pady=(0, 14))

workspace = ttk.Frame(main_frame, padding=(24, 20))
workspace.pack(side="left", fill="both", expand=True)

header = ttk.Frame(workspace)
header.pack(fill="x", pady=(0, 14))
ttk.Label(header, text="Patient directory", style="Title.TLabel").pack(anchor="w")
ttk.Label(header, text="Admit, edit and track patients by triage priority.", style="Muted.TLabel").pack(anchor="w", pady=(2, 0))

# ---------------- SUMMARY CARDS ----------------
# The colored edge on each card carries the triage color; nothing else uses it.
stats_frame = ttk.Frame(workspace)
stats_frame.pack(fill="x", pady=(0, 16))
for index, (label, color) in enumerate((
    ("Total patients", TEAL),
    ("Critical", CRITICAL),
    ("Urgent", URGENT),
    ("Stable", STABLE),
)):
  stats_frame.columnconfigure(index, weight=1, uniform="cards")
  card = ttk.Frame(stats_frame, style="Card.TFrame")
  card.grid(row=0, column=index, sticky="ew", padx=(0, 12 if index < 3 else 0))
  tk.Frame(card, background=color, width=6).pack(side="left", fill="y")
  card_body = ttk.Frame(card, style="Nav.TFrame", padding=(16, 12))
  card_body.pack(side="left", fill="both", expand=True)
  ttk.Label(card_body, text=label, foreground=WHITE, background=SIDEBAR).pack(anchor="w")
  ttk.Label(card_body, textvariable=count_vars[index], style="Stat.TLabel", foreground=color, background=SIDEBAR).pack(anchor="w")

footer = ttk.Frame(workspace)
footer.pack(side="bottom", fill="x", pady=(10, 0))
ttk.Label(footer, textvariable=displayed_var, style="Muted.TLabel").pack(side="left")
ttk.Label(footer, text="F11: full screen   Esc: window mode", style="Muted.TLabel").pack(side="right")

body = ttk.Frame(workspace)
body.pack(fill="both", expand=True)
form_frame = ttk.Frame(body, style="Card.TFrame", padding=(22, 18))
form_frame.pack(side="left", fill="y", padx=(0, 16))
table_frame = ttk.Frame(body, style="Card.TFrame", padding=(22, 20))
table_frame.pack(side="left", fill="both", expand=True)

# ---------------- PATIENT FORM ----------------
form_frame.columnconfigure(0, weight=1, uniform="form")
form_frame.columnconfigure(1, weight=1, uniform="form")
ttk.Label(form_frame, textvariable=form_title_var, style="Section.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
ttk.Label(form_frame, text="Fields marked * are required.", style="CardMuted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 14))

# (label, variable, widget kind, form row, column, columns spanned)
form_layout = (
    ("Patient No.", patient_no_var, "readonly", 0, 0, 2),
    ("Full name *", full_name_var, "entry", 1, 0, 2),
    ("Age *", age_var, "entry", 2, 0, 1),
    ("Gender", gender_var, GENDERS, 2, 1, 1),
    ("Room / Ward *", room_var, "entry", 3, 0, 1),
    ("Admission date *", date_var, "entry", 3, 1, 1),
    ("Condition / Disease *", condition_var, "entry", 4, 0, 2),
    ("Triage priority", triage_var, TRIAGE_LEVELS, 5, 0, 1),
    ("Status", status_var, STATUSES, 5, 1, 1),
)

for label, variable, kind, form_row, column, span in form_layout:
  grid_row = 2 + form_row * 2
  padx = (0, 0) if span == 2 else ((0, 8) if column == 0 else (8, 0))
  ttk.Label(form_frame, text=label, style="Field.TLabel").grid(row=grid_row, column=column, columnspan=span, sticky="w", padx=padx)
  if isinstance(kind, tuple):
    widget = ttk.Combobox(form_frame, textvariable=variable, values=kind, state="readonly", width=17)
  elif kind == "readonly":
    widget = ttk.Entry(form_frame, textvariable=variable, state="readonly", width=17)
  else:
    widget = ttk.Entry(form_frame, textvariable=variable, width=17)
  widget.grid(row=grid_row + 1, column=column, columnspan=span, sticky="ew", padx=padx, pady=(2, 10))

button_frame = ttk.Frame(form_frame, style="Card.TFrame")
button_frame.grid(row=14, column=0, columnspan=2, sticky="ew", pady=(6, 0))
button_frame.columnconfigure(0, weight=1, uniform="actions")
button_frame.columnconfigure(1, weight=1, uniform="actions")
ttk.Button(button_frame, text="Admit patient", style="Primary.TButton", command=add_patient).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
ttk.Button(button_frame, text="Update", style="Secondary.TButton", command=update_patient).grid(row=1, column=0, sticky="ew", padx=(0, 4), pady=(0, 8))
ttk.Button(button_frame, text="Clear form", style="Secondary.TButton", command=clear_form).grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=(0, 8))
ttk.Button(button_frame, text="Delete record", style="Danger.TButton", command=delete_patient).grid(row=2, column=0, columnspan=2, sticky="ew")

# ---------------- RECORDS TOOLBAR ----------------
record_heading = ttk.Frame(table_frame, style="Card.TFrame")
record_heading.pack(fill="x", pady=(0, 12))
ttk.Label(record_heading, text="Active patients", style="Section.TLabel").pack(side="left")
ttk.Button(record_heading, text="Export CSV", style="Secondary.TButton", command=export_csv).pack(side="right")

search_frame = ttk.Frame(table_frame, style="Card.TFrame")
search_frame.pack(fill="x", pady=(0, 10))
search_entry = ttk.Entry(search_frame, textvariable=search_var, width=18)
search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
ttk.Button(search_frame, text="Search", style="Primary.TButton", command=load_patients).pack(side="left", padx=(0, 6))
ttk.Button(search_frame, text="Show all", style="Secondary.TButton", command=refresh_patients).pack(side="left")

filter_frame = ttk.Frame(table_frame, style="Card.TFrame")
filter_frame.pack(fill="x", pady=(0, 12))
ttk.Label(filter_frame, text="Triage", style="CardMuted.TLabel").pack(side="left")
ttk.Combobox(filter_frame, textvariable=triage_filter_var, values=("All",) + TRIAGE_LEVELS, state="readonly", width=10).pack(side="left", padx=(6, 16))
ttk.Label(filter_frame, text="Status", style="CardMuted.TLabel").pack(side="left")
ttk.Combobox(filter_frame, textvariable=status_filter_var, values=("All",) + STATUSES, state="readonly", width=14).pack(side="left", padx=(6, 12))
ttk.Button(filter_frame, text="Apply filter", style="Secondary.TButton", command=load_patients).pack(side="left")

# ---------------- RECORDS TABLE ----------------
table_area = ttk.Frame(table_frame, style="Card.TFrame")
table_area.pack(fill="both", expand=True)
table_area.rowconfigure(0, weight=1)
table_area.columnconfigure(0, weight=1)

tree = ttk.Treeview(
    table_area, columns=COLUMNS, show="headings", selectmode="browse",
    displaycolumns=("patient_no", "full_name", "age", "gender", "room_no", "condition_type", "triage_status", "admission_date", "status")
)
widths = (40, 100, 190, 60, 80, 100, 170, 110, 140, 120)
for column, heading, width in zip(COLUMNS, HEADINGS, widths):
  tree.heading(column, text=heading, anchor="center" if column in ("age", "gender", "triage_status", "status") else "w")
  tree.column(column, width=width, minwidth=width, stretch=False, anchor="center" if column in ("age", "gender", "triage_status", "status") else "w")

tree.tag_configure("even", background=WHITE)
tree.tag_configure("odd", background=ROW_ALT)
tree.grid(row=0, column=0, sticky="nsew")

vertical_scroll = ttk.Scrollbar(table_area, orient="vertical", command=tree.yview)
vertical_scroll.grid(row=0, column=1, sticky="ns")
horizontal_scroll = ttk.Scrollbar(table_area, orient="horizontal", command=tree.xview)
horizontal_scroll.grid(row=1, column=0, sticky="ew")
tree.configure(yscrollcommand=vertical_scroll.set, xscrollcommand=horizontal_scroll.set)

ttk.Label(table_frame, text="Search by patient no., name, room or condition. Select a row to edit it.", style="CardMuted.TLabel").pack(anchor="w", pady=(10, 0))
tree.bind("<<TreeviewSelect>>", on_tree_select)
search_entry.bind("<Return>", lambda event: load_patients())


# ---------------- AUTO-CREATE ADMIN USER ----------------
def ensure_admin_exists():
  connection = None
  cursor = None
  try:
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT user_id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
      # Generate fresh salt and hash using the app's exact algorithm
      salt = secrets.token_hex(16)
      pwd_hash = hash_password("admin123", salt)
      cursor.execute(
          "INSERT INTO users (username, password_salt, password_hash) VALUES"
          " (%s, %s, %s)",
          ("admin", salt, pwd_hash),
      )
      connection.commit()
  except Exception as e:
    print("Database check error:", e)
  finally:
    close_database(connection, cursor)


# ---------------- START PROGRAM ----------------
if __name__ == "__main__":
  ensure_admin_exists()  # Automatically creates admin / admin123 with matching hash
  username_entry.focus_set()
  root.mainloop()