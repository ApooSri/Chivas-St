from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_mysqldb import MySQL
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import io
import sys
# Add your project directory to the sys.path


app = Flask(__name__)
app.secret_key = 'your_secret_key'  

app.config['MYSQL_HOST'] = 'yourusername.mysql.pythonanywhere-services.com'
app.config['MYSQL_USER'] = 'ApoorvBasher'
app.config['MYSQL_PASSWORD'] = 'ApoorvGRT@2024'
app.config['MYSQL_DB'] = 'chivas_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, username, email, password_hash, is_admin):
        self.id = id_
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = bool(is_admin)

    @staticmethod
    def get(user_id):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        if not user:
            return None
        return User(user['id'], user['username'], user['email'], user['password_hash'], user['is_admin'])

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing = cursor.fetchone()
        if existing:
            flash('Username already exists')
            cursor.close()
            return redirect(url_for('signup'))
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        mysql.connection.commit()
        cursor.close()
        flash('Account created successfully. Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data and check_password_hash(user_data['password_hash'], password):
            user_obj = User(user_data['id'], user_data['username'], user_data['email'],
                            user_data['password_hash'], user_data['is_admin'])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        prompt_text = request.form['prompt']
        response_text = request.form['response']
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO submissions (user_id, prompt, response) VALUES (%s, %s, %s)",
            (current_user.id, prompt_text, response_text)
        )
        mysql.connection.commit()
        cursor.close()
        flash('Submission saved successfully.')
        return redirect(url_for('dashboard'))
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM submissions WHERE user_id = %s", (current_user.id,))
    submissions = cursor.fetchall()
    cursor.close()
    return render_template('dashboard.html', submissions=submissions)

@app.route('/download')
@login_required
def download():
    if not current_user.is_admin:
        flash('Access denied: Admins only.')
        return redirect(url_for('dashboard'))
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM submissions")
    data = cursor.fetchall()
    cursor.close()
    
    df = pd.DataFrame(data)
    if not df.empty:
        for col in ['id', 'user_id']:
            if col in df.columns:
                df = df.drop(columns=[col])
    else:
        df = pd.DataFrame(columns=['prompt', 'response', 'timestamp'])
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Submissions')
    output.seek(0)
    
    return send_file(output, download_name="submissions.xlsx", as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    app.run(debug=True)
