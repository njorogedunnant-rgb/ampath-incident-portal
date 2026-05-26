from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import resend
from itsdangerous import URLSafeTimedSerializer
import bcrypt
import os
from datetime import timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'ampath_secret_change_this_in_production'
app.permanent_session_lifetime = timedelta(minutes=30)  # Session timeout after 30 min

# ── MySQL Configuration ───────────────────────────────────────────────────────

app.config['MYSQL_HOST'] = os.environ.get('MYSQLHOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQLUSER', 'portal_user')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQLPASSWORD', 'portal123')
app.config['MYSQL_DB'] = os.environ.get('MYSQLDATABASE', 'railway')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQLPORT', 3306))
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
# ── Mail Configuration ────────────────────────────────────────────────────────

resend.api_key = os.environ.get("RESEND_API_KEY")
s = URLSafeTimedSerializer(app.secret_key)
# ── Auth Decorators ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admins only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        dept     = request.form.get('department', '').strip()

        if not all([name, email, password, dept]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        # Check if email already exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            flash('An account with that email already exists.', 'danger')
            cur.close()
            return render_template('register.html')

        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cur.execute(
            "INSERT INTO users (name, email, password, department, role) VALUES (%s, %s, %s, %s, 'staff')",
            (name, email, hashed.decode('utf-8'), dept)
        )
        mysql.connection.commit()
        cur.close()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session.permanent = True
            session['user_id'] = user['id']
            session['name']    = user['name']
            session['role']    = user['role']
            flash(f"Welcome back, {user['name']}!", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()
    if session['role'] == 'admin':
        # Admin sees all reports
        severity = request.args.get('severity', '')
        status   = request.args.get('status', '')
        query    = "SELECT i.*, u.name AS reporter_name FROM incidents i JOIN users u ON i.user_id = u.id WHERE 1=1"
        params   = []
        if severity:
            query += " AND i.severity = %s"
            params.append(severity)
        if status:
            query += " AND i.status = %s"
            params.append(status)
        query += " ORDER BY i.created_at DESC"
        cur.execute(query, params)
    else:
        # Staff sees only their own reports
        cur.execute(
            "SELECT * FROM incidents WHERE user_id = %s ORDER BY created_at DESC",
            (session['user_id'],)
        )
    incidents = cur.fetchall()

    # Stats for admin
    stats = {}
    if session['role'] == 'admin':
        cur.execute("SELECT COUNT(*) AS total FROM incidents")
        stats['total'] = cur.fetchone()['total']
        cur.execute("SELECT COUNT(*) AS open FROM incidents WHERE status = 'Open'")
        stats['open'] = cur.fetchone()['open']
        cur.execute("SELECT COUNT(*) AS critical FROM incidents WHERE severity = 'Critical'")
        stats['critical'] = cur.fetchone()['critical']
        cur.execute("SELECT COUNT(*) AS resolved FROM incidents WHERE status = 'Resolved'")
        stats['resolved'] = cur.fetchone()['resolved']

    cur.close()
    return render_template('dashboard.html', incidents=incidents, stats=stats)

# ── Report Incident ───────────────────────────────────────────────────────────

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_incident():
    if request.method == 'POST':
        incident_type = request.form.get('incident_type', '').strip()
        description   = request.form.get('description', '').strip()
        severity      = request.form.get('severity', '')
        location      = request.form.get('location', '').strip()

        if not all([incident_type, description, severity]):
            flash('Please fill in all required fields.', 'danger')
            return render_template('report.html')

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO incidents (user_id, incident_type, description, severity, location, status) VALUES (%s, %s, %s, %s, %s, 'Open')",
            (session['user_id'], incident_type, description, severity, location)
        )
        mysql.connection.commit()
        cur.close()
        flash('Incident reported successfully! The ICT team has been notified.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# ── Update Incident (Admin) ───────────────────────────────────────────────────

@app.route('/incident/<int:id>/update', methods=['POST'])
@admin_required
def update_incident(id):
    status   = request.form.get('status', '')
    assignee = request.form.get('assignee', '').strip()
    notes    = request.form.get('admin_notes', '').strip()

    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE incidents SET status = %s, assigned_to = %s, admin_notes = %s WHERE id = %s",
        (status, assignee, notes, id)
    )
    mysql.connection.commit()
    cur.close()
    flash('Incident updated successfully.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/incident/<int:id>')
@login_required
def view_incident(id):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT i.*, u.name AS reporter_name, u.department FROM incidents i JOIN users u ON i.user_id = u.id WHERE i.id = %s",
        (id,)
    )
    incident = cur.fetchone()
    cur.close()

    if not incident:
        flash('Incident not found.', 'danger')
        return redirect(url_for('dashboard'))

    # Staff can only view their own
    if session['role'] != 'admin' and incident['user_id'] != session['user_id']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('view_incident.html', incident=incident)

# ── Forgot Password ───────────────────────────────────────────────────────────
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
            if user:
                token = s.dumps(email, salt='password-reset')
                reset_url = url_for('reset_password_page', token=token, _external=True)
                body = "Hello " + user['name'] + ",\n\nClick the link below to reset your password (valid for 30 minutes):\n" + reset_url + "\n\nAMPATH ICT Team"
                resend.Emails.send({
                    "from": "onboarding@resend.dev",
                    "to": email,
                    "subject": "Reset Your AMPATH Portal Password",
                    "text": body
                })
        except Exception as e:
            print(f"Error: {e}")
            flash(f'Error: {str(e)}', 'danger')
            return render_template('forgot_password.html')
        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_page(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=1800)
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('reset_password.html', token=token)
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password = %s WHERE email = %s",
                    (hashed.decode('utf-8'), email))
        mysql.connection.commit()
        cur.close()
        flash('Password reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/trends')
@admin_required
def trends():
    cur = mysql.connection.cursor()
    
    # Incidents per month
    cur.execute("""
        SELECT DATE_FORMAT(created_at, '%b %Y') as month, 
               COUNT(*) as count 
        FROM incidents 
        GROUP BY DATE_FORMAT(created_at, '%Y-%m')
        ORDER BY MIN(created_at) DESC
        LIMIT 6
    """)
    monthly = cur.fetchall()

    # Incidents by type
    cur.execute("""
        SELECT incident_type, COUNT(*) as count 
        FROM incidents 
        GROUP BY incident_type 
        ORDER BY count DESC
        LIMIT 8
    """)
    by_type = cur.fetchall()

    # Incidents by severity
    cur.execute("""
        SELECT severity, COUNT(*) as count 
        FROM incidents 
        GROUP BY severity
    """)
    by_severity = cur.fetchall()

    # Incidents by status
    cur.execute("""
        SELECT status, COUNT(*) as count 
        FROM incidents 
        GROUP BY status
    """)
    by_status = cur.fetchall()

    # Resolution rate
    cur.execute("SELECT COUNT(*) as total FROM incidents")
    total = cur.fetchone()['total']
    cur.execute("SELECT COUNT(*) as resolved FROM incidents WHERE status = 'Resolved'")
    resolved = cur.fetchone()['resolved']

    # Recent incidents
    cur.execute("""
        SELECT i.*, u.name AS reporter_name 
        FROM incidents i 
        JOIN users u ON i.user_id = u.id 
        ORDER BY i.created_at DESC LIMIT 5
    """)
    recent = cur.fetchall()

    cur.close()

    return render_template('trends.html',
        monthly=monthly,
        by_type=by_type,
        by_severity=by_severity,
        by_status=by_status,
        total=total,
        resolved=resolved,
        recent=recent
    )

if __name__ == '__main__':
    app.run(debug=True)
