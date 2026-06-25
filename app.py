import sqlite3
import random
import string
import os
import re
from datetime import datetime, timedelta
from functools import wraps
import bcrypt

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "real_tailors_erp_secret_2024"

# ─────────────────────────────────────────────────────────────────
# MAIL CONFIGURATION
# ─────────────────────────────────────────────────────────────────
app.config['MAIL_SERVER']         = 'smtp.gmail.com'
app.config['MAIL_PORT']           = 587
app.config['MAIL_USE_TLS']        = True
app.config['MAIL_USERNAME']       = 'your_gmail@gmail.com'    # ← YOUR GMAIL
app.config['MAIL_PASSWORD']       = 'xxxx xxxx xxxx xxxx'     # ← APP PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = ('Real Tailors ERP', 'your_gmail@gmail.com')

mail = Mail(app)

# ─────────────────────────────────────────────────────────────────
# DATABASE ARCHITECTURE SETUP
# ─────────────────────────────────────────────────────────────────
OWNERS_DB = "real_tailors_owners.db"

def get_owners_db():
    conn = sqlite3.connect(OWNERS_DB)
    conn.row_factory = sqlite3.Row
    return conn

def get_db_connection():
    """Uses owner's private isolated DB from session; defaults to sandbox filename if unauthenticated."""
    db_name = session.get('owner_db', 'real_tailors_erp.db')
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def setup_owners_db():
    """Creates the central orchestration tables for multi-tenant accounts and temporary tokens."""
    conn = get_owners_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS Owners (
            OwnerID    INTEGER PRIMARY KEY AUTOINCREMENT,
            Name       TEXT    NOT NULL,
            Mobile     TEXT    UNIQUE NOT NULL,
            Email      TEXT    UNIQUE NOT NULL,
            ShopName   TEXT    NOT NULL,
            Password   TEXT    NOT NULL,
            CreatedAt  TEXT    DEFAULT (datetime('now')),
            IsActive   INTEGER DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS OTP_Requests (
            ID         INTEGER PRIMARY KEY AUTOINCREMENT,
            Email      TEXT    NOT NULL,
            OTP        TEXT    NOT NULL,
            ExpiresAt  TEXT    NOT NULL,
            Used       INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def setup_shop_db(owner_id):
    """Dynamically spawns/migrates isolated internal databases for new registered entities."""
    db_name = f"shop_{owner_id}.db"
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Customers (
            CustID INTEGER PRIMARY KEY AUTOINCREMENT,
            Date TEXT, Name TEXT, Mobile TEXT UNIQUE,
            Shirt_Data TEXT, Pant_Data TEXT, Suit_Data TEXT, Kurtha_Data TEXT, Extra_Data TEXT
        )""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Bills (
            BillID INTEGER PRIMARY KEY AUTOINCREMENT,
            CustID INTEGER, Date TEXT, Delivery_Date TEXT, Bill_Book_No TEXT, Status TEXT,
            Shirt_Q INTEGER, Shirt_P REAL, Pant_Q INTEGER, Pant_P REAL,
            Suit_Q INTEGER, Suit_P REAL, Kurtha_Q INTEGER, Kurtha_P REAL,
            Total_Amount REAL, Paid_Amount REAL, Discount REAL DEFAULT 0, Balance_Due REAL,
            Cloth_Price REAL DEFAULT 0.0,
            FOREIGN KEY(CustID) REFERENCES Customers(CustID)
        )""")
        
    # Safe runtime schema migration check for legacy updates
    try:
        cursor.execute("ALTER TABLE Bills ADD COLUMN Cloth_Price REAL DEFAULT 0.0")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE Bills ADD COLUMN Discount REAL DEFAULT 0.0")
    except sqlite3.OperationalError:
        pass
        
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────────────────────────
# SECURITY & AUXILIARY HELPERS
# ─────────────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def generate_otp(length=6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def validate_password(pwd: str) -> str | None:
    if len(pwd) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', pwd):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[0-9]', pwd):
        return "Password must contain at least one number."
    if not re.search(r'[#@!$%^&*]', pwd):
        return "Password must contain at least one special character (#@!$%^&*)."
    return None

def mask_email(email: str) -> str:
    parts = email.split('@')
    name  = parts[0]
    masked = name[0] + '*' * max(1, len(name)-2) + name[-1] if len(name) > 2 else name[0] + '*'
    return masked + '@' + parts[1]

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'owner_id' not in session:
            flash("Please login to continue.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_globals():
    if 'theme' not in session:
        session['theme'] = 'dark'
    return dict(
        current_theme = session['theme'],
        shop_name     = session.get('shop_name', 'Real Tailors'),
        owner_name    = session.get('owner_name', ''),
        is_logged_in  = 'owner_id' in session,
    )

# ─────────────────────────────────────────────────────────────────
# AUTHENTICATION ENGINE ROUTES
# ─────────────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'owner_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name      = request.form.get('name',         '').strip()
        mobile    = request.form.get('mobile',       '').strip()
        email     = request.form.get('email',        '').strip().lower()
        shop_name = request.form.get('shop_name',    '').strip()
        password  = request.form.get('password',     '')
        confirm   = request.form.get('confirm_password', '')

        if not all([name, mobile, email, shop_name, password]):
            flash("All fields are required.", "error")
            return redirect(url_for('register'))
        if not re.match(r'^[0-9]{10}$', mobile):
            flash("Enter a valid 10-digit mobile number.", "error")
            return redirect(url_for('register'))
        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))
        pwd_error = validate_password(password)
        if pwd_error:
            flash(pwd_error, "error")
            return redirect(url_for('register'))

        conn = get_owners_db()
        try:
            cursor = conn.execute(
                "INSERT INTO Owners (Name, Mobile, Email, ShopName, Password) VALUES (?,?,?,?,?)",
                (name, mobile, email, shop_name, hash_password(password))
            )
            owner_id = cursor.lastrowid
            conn.commit()

            setup_shop_db(owner_id)

            try:
                msg = Message(
                    subject=f"Welcome to {shop_name} ERP — Account Created",
                    recipients=[email]
                )
                msg.body = f"Hello {name},\n\nYour Real Tailors ERP account has been verified successfully!\n\nLOGIN ACCESS:\n  Username/ID: {mobile}\n\nKeep your data password credentials safe.\n\n— Administration Core"
                mail.send(msg)
            except Exception as e:
                print(f"[MAIL ERROR] Welcome email failed: {e}")

            flash(f"Account created! Welcome, {name}. Please login.", "success")
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash("Mobile number or email already registered.", "error")
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'owner_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        mobile   = request.form.get('mobile',   '').strip()
        password = request.form.get('password', '')

        conn  = get_owners_db()
        owner = conn.execute(
            "SELECT * FROM Owners WHERE Mobile=? AND IsActive=1", (mobile,)
        ).fetchone()
        conn.close()

        if not owner or not check_password(password, owner['Password']):
            flash("Invalid mobile number or password.", "error")
            return redirect(url_for('login'))

        session['owner_id']   = owner['OwnerID']
        session['owner_name'] = owner['Name']
        session['shop_name']  = owner['ShopName']
        session['owner_db']   = f"shop_{owner['OwnerID']}.db"
        session['theme']      = 'dark'

        flash(f"Welcome back, {owner['Name']}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    step = int(request.args.get('step', 1))

    if request.method == 'POST':
        step = int(request.form.get('step', 1))

        if step == 1:
            email = request.form.get('email', '').strip().lower()
            conn  = get_owners_db()
            owner = conn.execute(
                "SELECT * FROM Owners WHERE Email=? AND IsActive=1", (email,)
            ).fetchone()
            conn.close()

            if not owner:
                flash("No account found with that email.", "error")
                return render_template('forgot_password.html', step=1)

            otp        = generate_otp(6)
            expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
            conn2 = get_owners_db()
            conn2.execute(
                "INSERT INTO OTP_Requests (Email, OTP, ExpiresAt) VALUES (?,?,?)",
                (email, otp, expires_at)
            )
            conn2.commit()
            conn2.close()

            try:
                msg = Message(
                    subject="Real Tailors ERP — Password Reset OTP",
                    recipients=[email]
                )
                msg.body = f"Hello {owner['Name']},\n\nYour token verification code is: {otp}\n\nValid for 10 minutes.\n\n— Administration Core"
                mail.send(msg)
                flash(f"OTP sent to {mask_email(email)}. Check your inbox.", "success")
            except Exception as e:
                print(f"[MAIL ERROR] OTP send failed: {e}")
                flash("Failed to send OTP email. Check your mail config.", "error")
                return render_template('forgot_password.html', step=1)

            return render_template('forgot_password.html', step=2, email=email, masked_email=mask_email(email))

        if step == 2:
            email = request.form.get('email', '').strip().lower()
            otp   = request.form.get('otp_combined', '').strip()

            conn  = get_owners_db()
            row   = conn.execute("""
                SELECT * FROM OTP_Requests
                WHERE Email=? AND OTP=? AND Used=0
                  AND ExpiresAt > datetime('now')
                ORDER BY ID DESC LIMIT 1
            """, (email, otp)).fetchone()
            conn.close()

            if not row:
                flash("Invalid or expired OTP. Please try again.", "error")
                return render_template('forgot_password.html', step=2, email=email, masked_email=mask_email(email))

            conn2 = get_owners_db()
            conn2.execute("UPDATE OTP_Requests SET Used=1 WHERE ID=?", (row['ID'],))
            conn2.commit()
            conn2.close()

            return render_template('forgot_password.html', step=3, email=email)

        if step == 3:
            email    = request.form.get('email',            '').strip().lower()
            new_pwd  = request.form.get('new_password',     '')
            confirm  = request.form.get('confirm_password', '')

            if new_pwd != confirm:
                flash("Passwords do not match.", "error")
                return render_template('forgot_password.html', step=3, email=email)

            pwd_error = validate_password(new_pwd)
            if pwd_error:
                flash(pwd_error, "error")
                return render_template('forgot_password.html', step=3, email=email)

            conn = get_owners_db()
            conn.execute(
                "UPDATE Owners SET Password=? WHERE Email=?",
                (hash_password(new_pwd), email)
            )
            conn.commit()
            conn.close()

            flash("Password updated successfully! Please login.", "success")
            return redirect(url_for('login'))

    return render_template('forgot_password.html', step=step)

# ─────────────────────────────────────────────────────────────────
# CORE CORE FUNCTIONAL ROUTES (SECURED)
# ─────────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    return render_template(
        'dashboard.html',
        shop_name=session.get('shop_name', 'Real Tailors'),
        owner_name=session.get('owner_name', '')
    )

@app.route('/toggle-theme')
def toggle_theme():
    session['theme'] = 'light' if session.get('theme') == 'dark' else 'dark'
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/new-form', methods=['GET', 'POST'])
@login_required
def new_form():
    if request.method == 'POST':
        c_id = request.form.get('cust_id', '').strip()
        name = request.form.get('name', '').strip()
        mobile = request.form.get('mobile', '').strip()
        date = request.form.get('date', '').strip()

        if not name or not mobile:
            flash("Name and Mobile are strictly required!", "error")
            return redirect(url_for('new_form'))

        data = {k: ",".join([request.form.get(f"{k.lower()}_{i}", "") for i in range(12)]) for k in ["SHIRT", "PANT", "SUIT", "KURTHA", "EXTRA"]}

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if c_id:
                cursor.execute("""
                INSERT INTO Customers (CustID, Date, Name, Mobile, Shirt_Data, Pant_Data, Suit_Data, Kurtha_Data, Extra_Data)
                VALUES (?,?,?,?,?,?,?,?,?)""", (c_id, date, name, mobile, data["SHIRT"], data["PANT"], data["SUIT"], data["KURTHA"], data["EXTRA"]))
            else:
                cursor.execute("""
                INSERT INTO Customers (Date, Name, Mobile, Shirt_Data, Pant_Data, Suit_Data, Kurtha_Data, Extra_Data)
                VALUES (?,?,?,?,?,?,?,?)""", (date, name, mobile, data["SHIRT"], data["PANT"], data["SUIT"], data["KURTHA"], data["EXTRA"]))
                c_id = cursor.lastrowid
            conn.commit()
            flash("Customer added successfully!", "success")
            return redirect(url_for('billing', cust_id=c_id))
        except sqlite3.IntegrityError:
            flash("Error: Identity Conflict! Custom ID or Mobile number already exists.", "error")
            return redirect(url_for('new_form'))
        finally:
            conn.close()

    today = datetime.now().strftime("%d-%m-%Y")
    return render_template('new_form.html', today=today)

@app.route('/billing')
@login_required
def billing():
    cust_id = request.args.get('cust_id', '').strip()
    load_bill_id = request.args.get('load_bill_id', '').strip()
    
    customer = None
    prev_balance = 0.0
    all_bills = []
    loaded_bill = None

    conn = get_db_connection()
    
    if cust_id:
        customer = conn.execute("SELECT CustID, Name, Mobile FROM Customers WHERE CustID=? OR Mobile=?", (cust_id, cust_id)).fetchone()
        
    if load_bill_id:
        loaded_bill = conn.execute("SELECT * FROM Bills WHERE BillID=?", (load_bill_id,)).fetchone()
        if loaded_bill and not customer:
            customer = conn.execute("SELECT CustID, Name, Mobile FROM Customers WHERE CustID=?", (loaded_bill['CustID'],)).fetchone()

    if customer:
        all_bills = conn.execute("SELECT * FROM Bills WHERE CustID=? ORDER BY BillID DESC", (customer['CustID'],)).fetchall()
        
        for bill in all_bills:
            if loaded_bill and int(bill['BillID']) == int(loaded_bill['BillID']):
                continue
            prev_balance += float(bill['Balance_Due'] or 0.0)

    conn.close()
    today = datetime.now().strftime("%d-%m-%Y")
    
    return render_template(
        'billing.html', 
        customer=customer, 
        prev_balance=prev_balance, 
        today=today, 
        search_val=cust_id, 
        all_bills=all_bills, 
        loaded_bill=loaded_bill
    )

@app.route('/save-bill', methods=['POST'])
@login_required
def save_bill():
    cust_id = request.form.get('cust_id')
    if not cust_id:
        flash("You must attach a loaded customer profile!", "error")
        return redirect(url_for('billing'))

    date = request.form.get('date')
    del_date = request.form.get('delivery_date')
    book = request.form.get('bill_book_no')
    status = request.form.get('status')
    
    sq = int(request.form.get('shirt_q') or 0)
    sp = float(request.form.get('shirt_p') or 0)
    pq = int(request.form.get('pant_q') or 0)
    pp = float(request.form.get('pant_p') or 0)
    suq = int(request.form.get('suit_q') or 0)
    sup = float(request.form.get('suit_p') or 0)
    kq = int(request.form.get('kurtha_q') or 0)
    kp = float(request.form.get('kurtha_p') or 0)
    
    tot = float(request.form.get('current_total') or 0)
    cloth = float(request.form.get('cloth_price') or 0)
    paid = float(request.form.get('paid_amount') or 0)
    due = float(request.form.get('net_balance_due') or 0)

    conn = get_db_connection()
    conn.execute("""
    INSERT INTO Bills (CustID, Date, Delivery_Date, Bill_Book_No, Status, Shirt_Q, Shirt_P, Pant_Q, Pant_P, Suit_Q, Suit_P, Kurtha_Q, Kurtha_P, Total_Amount, Cloth_Price, Paid_Amount, Balance_Due)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", 
    (cust_id, date, del_date, book, status, sq, sp, pq, pp, suq, sup, kq, kp, tot, cloth, paid, due))
    conn.commit()
    conn.close()

    flash("New bill saved successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/update-bill', methods=['POST'])
@login_required
def update_bill():
    bill_id = request.form.get('bill_id')
    cust_id = request.form.get('cust_id')
    
    if not bill_id:
        flash("No active bill found to update!", "error")
        return redirect(url_for('billing'))

    date = request.form.get('date')
    del_date = request.form.get('delivery_date')
    book = request.form.get('bill_book_no')
    status = request.form.get('status')
    
    sq = int(request.form.get('shirt_q') or 0)
    sp = float(request.form.get('shirt_p') or 0)
    pq = int(request.form.get('pant_q') or 0)
    pp = float(request.form.get('pant_p') or 0)
    suq = int(request.form.get('suit_q') or 0)
    sup = float(request.form.get('suit_p') or 0)
    kq = int(request.form.get('kurtha_q') or 0)
    kp = float(request.form.get('kurtha_p') or 0)
    
    tot = float(request.form.get('current_total') or 0)
    cloth = float(request.form.get('cloth_price') or 0)
    paid = float(request.form.get('paid_amount') or 0)
    due = float(request.form.get('net_balance_due') or 0)

    conn = get_db_connection()
    conn.execute("""
    UPDATE Bills SET Date=?, Delivery_Date=?, Bill_Book_No=?, Status=?, 
    Shirt_Q=?, Shirt_P=?, Pant_Q=?, Pant_P=?, Suit_Q=?, Suit_P=?, Kurtha_Q=?, Kurtha_P=?, 
    Total_Amount=?, Cloth_Price=?, Paid_Amount=?, Balance_Due=? WHERE BillID=? AND CustID=?""",
    (date, del_date, book, status, sq, sp, pq, pp, suq, sup, kq, kp, tot, cloth, paid, due, bill_id, cust_id))
    conn.commit()
    conn.close()

    flash(f"Bill #{bill_id} updated successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    customer_match = None
    customer_measurements = {}
    bills = []

    if query:
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM Customers WHERE CustID=? OR Mobile=? OR Name=?", (query, query, query)).fetchone()
        if row:
            customer_match = row
            categories = {
                "SHIRT": "Shirt_Data", 
                "PANT": "Pant_Data", 
                "SUIT": "Suit_Data", 
                "KURTHA": "Kurtha_Data", 
                "EXTRA": "Extra_Data"
            }
            for label, column_name in categories.items():
                customer_measurements[label] = str(row[column_name] or "").split(',')
            
            bills = conn.execute("SELECT BillID, Date, Total_Amount, Balance_Due, Status FROM Bills WHERE CustID=?", (row['CustID'],)).fetchall()
        conn.close()

    return render_template('search.html', customer=customer_match, measurements=customer_measurements, bills=bills, query=query)

@app.route('/update-customer', methods=['POST'])
@login_required
def update_customer():
    c_id = request.form.get('cust_id')
    name = request.form.get('name')
    mobile = request.form.get('mobile')
    date = request.form.get('date')

    data = {k: ",".join([request.form.get(f"{k.lower()}_{i}", "") for i in range(12)]) for k in ["SHIRT", "PANT", "SUIT", "KURTHA", "EXTRA"]}

    conn = get_db_connection()
    conn.execute("""
    UPDATE Customers SET Date=?, Name=?, Mobile=?, Shirt_Data=?, Pant_Data=?, Suit_Data=?, Kurtha_Data=?, Extra_Data=?
    WHERE CustID=?""", (date, name, mobile, data["SHIRT"], data["PANT"], data["SUIT"], data["KURTHA"], data["EXTRA"], c_id))
    conn.commit()
    conn.close()

    flash("Customer profile updated successfully!", "success")
    return redirect(url_for('search', q=c_id))

@app.route('/status-dashboard')
@login_required
def status_dashboard():
    conn = get_db_connection()
    query_string = """
        SELECT Bills.*, Customers.Name as CustomerName, Customers.Mobile 
        FROM Bills 
        JOIN Customers ON Bills.CustID = Customers.CustID
        ORDER BY Bills.BillID DESC
    """
    all_orders = conn.execute(query_string).fetchall()
    conn.close()

    pending_bills = []
    delivered_bills = []

    for order in all_orders:
        bill_dict = dict(order)
        if order['Status'] == 'Delivered':
            delivered_bills.append(bill_dict)
        else:
            pending_bills.append(bill_dict)

    return render_template(
        'status_dashboard.html', 
        pending_bills=pending_bills, 
        delivered_bills=delivered_bills
    )

@app.route('/upload-bill-pdf/<cust_id>', methods=['POST'])
@login_required
def upload_bill_pdf(cust_id):
    try:
        conn = get_db_connection()
        
        shirt_q = int(request.form.get('shirt_q') or 0)
        pant_q = int(request.form.get('pant_q') or 0)
        suit_q = int(request.form.get('suit_q') or 0)
        kurtha_q = int(request.form.get('kurtha_q') or 0)
        total_items = shirt_q + pant_q + suit_q + kurtha_q

        net_balance_due = float(request.form.get('balance_due') or 0.0)
        delivery_date = request.form.get('delivery_date', '').strip() or '—'
        
        whatsapp_text = (
            "✨ *REAL TAILORS* ✨\n\n"
            "Hello! Your customized tailoring invoice is ready.\n\n"
            "👤 *Cust ID:* #{}\n"
            "📦 *Total Items:* {}\n"
            "📅 *Delivery Date:* {}\n"
            "💰 *Net Balance Due:* ₹{Collapse:,.2f}\n\n"
            "Thank you for choosing Real Tailors! 🙏\n\n"
            "───────────────────\n\n"
            "నమస్కారం! మీ టైలరింగ్ ఇన్‌వాయిస్ సిద్ధంగా ఉంది.\n\n"
            "👤 *కస్టమర్ ఐడి:* #{}\n"
            "📦 *మొత్తం వస్తువులు:* {}\n"
            "📅 *డెలివరీ తేదీ:* {}\n"
            "💰 *నికర బ్యాలెన్స్ బకాయి:* ₹{Collapse:,.2f}\n\n"
            "రియల్ టైలర్స్ ని ఎంచుకున్నందుకు ధన్యవాదాలు! 🙏"
        ).format(cust_id, total_items, delivery_date, net_balance_due, cust_id, total_items, delivery_date, net_balance_due)
        
        conn.close()
        return jsonify({'status': 'success', 'whatsapp_text': whatsapp_text})

    except Exception as e:
        print(f"WhatsApp JSON generation error log: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ─────────────────────────────────────────────────────────────────
# STARTUP LIFECYCLE INITIALIZATION
# ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    setup_owners_db()  
    app.run(debug=True, host='0.0.0.0', port=5000)