# AMPATH Cybersecurity Incident Reporting Portal
### Developed by Dunnant Njoroge – Industrial Attachment Project

---

## Setup Instructions

### 1. Install Python dependencies
```
pip install -r requirements.txt
```

### 2. Set up the MySQL database
```
mysql -u root -p < schema.sql
```

### 3. Update database credentials in app.py
Open app.py and update:
```python
app.config['MYSQL_PASSWORD'] = 'your_mysql_password'
```

### 4. Run the application
```
python app.py
```
Then open your browser at: http://127.0.0.1:5000

---

## Default Admin Login
- Email: admin@ampath.org
- Password: Admin@1234
⚠️ Change this immediately after first login!

---

## Project Structure
```
incident_portal/
├── app.py              # Main Flask application
├── schema.sql          # Database setup
├── requirements.txt    # Python dependencies
├── static/
│   └── css/
│       └── style.css   # Stylesheet
└── templates/
    ├── base.html        # Base layout
    ├── login.html       # Login page
    ├── register.html    # Registration page
    ├── dashboard.html   # Main dashboard (staff + admin)
    ├── report.html      # Submit incident form
    └── view_incident.html  # View single incident
```

---

## Features
- Staff: Register, login, report incidents, track status
- Admin: View all reports, filter by severity/status, assign, update, add notes
- Security: bcrypt passwords, SQL injection protection, XSS protection, session timeout
