from flask import Flask, request, redirect, url_for, render_template, session, jsonify, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send, emit
import os
import hashlib
import datetime
from werkzeug.utils import secure_filename
import html
import sys

LOGO = '''

████████▄  ████████▄     ▄████████ 
███   ▀███ ███   ▀███   ███    ███ 
███    ███ ███    ███   ███    █▀  
███    ███ ███    ███   ███        
███    ███ ███    ███ ▀███████████ 
███    ███ ███    ███          ███ 
███   ▄███ ███   ▄███    ▄█    ███ 
████████▀  ████████▀   ▄████████▀  
        (Deep Dark Sea) Version 1.0 S-H4CK13@Maptnh
'''

app = Flask(__name__)
app.secret_key = 'MAPTNH@SEC'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
socketio = SocketIO(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('403.html'), 200



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('register'))
        
        password_hash = hashlib.md5(password.encode()).hexdigest()

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose another one.", "error")
            return redirect(url_for('register'))

        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()

        user = User.query.filter_by(username=username).first()

        if user and user.password_hash == password_hash:
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('chat'))

        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        flash("You must be logged in to upload files.", "error")
        return redirect(url_for('login'))
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file:
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        socketio.emit('file_updated')  
        return 'File uploaded successfully', 200

@app.route('/files')
def list_files():
    if 'user_id' not in session:
        flash("You must be logged in to view files.", "error")
        return redirect(url_for('login'))
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return jsonify({'files': files})
 

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if 'user_id' not in session:
        flash("You must be logged in to download files.", "error")
        return redirect(url_for('login'))

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@socketio.on('send_message')
def handle_send_message(msg):
    if 'user_id' not in session:
        return

    username = session.get('username', 'Unknown')
    user_ip = request.remote_addr or 'Unknown IP'

    now = datetime.datetime.now()
    datetime_str = now.strftime("%Y-%m-%d %H:%M:%S")
    weekday_str = now.strftime("%A")

    safe_msg = html.escape(msg)

    msg_data = {
        'username': username,
        'ip': user_ip,
        'message': safe_msg,
        'datetime': datetime_str,
        'weekday': weekday_str
    }

    send(msg_data, broadcast=True)

if __name__ == '__main__':
    print(LOGO)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    socketio.run(app, host='0.0.0.0', port=port, debug=True, use_reloader=False)
