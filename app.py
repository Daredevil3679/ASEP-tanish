import os
import random
import string
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@127.0.0.1/personalized_learning_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    role = db.Column(db.String(10), nullable=False)  # "student" or "teacher"

class Doubt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=True)

class Notes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)

class StudentClassroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)

class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def generate_class_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@app.route('/create_classroom', methods=['GET', 'POST'])
@login_required
def create_classroom():
    if current_user.role != 'teacher':
        flash("Only teachers can create classrooms!", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        class_name = request.form['class_name']
        description = request.form['description']
        class_code = generate_class_code()

        new_classroom = Classroom(name=class_name, code=class_code, teacher_id=current_user.id)
        db.session.add(new_classroom)
        db.session.commit()

        return render_template('create_classroom.html', class_code=class_code)

    return render_template('create_classroom.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose another.', 'warning')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

def get_joined_classrooms(user_id):
    """Fetch all classrooms that a student has joined."""
    return Classroom.query.join(StudentClassroom).filter(StudentClassroom.student_id == user_id).all()

def get_created_classrooms(user_id):
    """Fetch all classrooms created by a teacher."""
    return Classroom.query.filter_by(teacher_id=user_id).all()

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        joined_classrooms = get_joined_classrooms(current_user.id)  
        return render_template('student_dashboard.html', joined_classrooms=joined_classrooms)

    elif current_user.role == 'teacher':
        created_classrooms = get_created_classrooms(current_user.id)  
        return render_template('teacher_dashboard.html', created_classrooms=created_classrooms)

@app.route('/upload_notes', methods=['POST'])
@login_required
def upload_notes():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_note = Notes(student_id=current_user.id, filename=filename)
            db.session.add(new_note)
            db.session.commit()
            flash('File uploaded successfully!', 'success')

    return redirect(url_for('dashboard'))

@app.route('/join_classroom', methods=['POST'])
@login_required
def join_classroom():
    class_code = request.form['class_code']
    classroom = Classroom.query.filter_by(code=class_code).first()

    if not classroom:
        flash("Invalid class code. Please try again!", "danger")
        return redirect(url_for('dashboard'))

    existing_entry = StudentClassroom.query.filter_by(student_id=current_user.id, classroom_id=classroom.id).first()
    if existing_entry:
        flash("You are already in this classroom!", "info")
    else:
        new_entry = StudentClassroom(student_id=current_user.id, classroom_id=classroom.id)
        db.session.add(new_entry)
        db.session.commit()
        flash(f"Successfully joined {classroom.name}!", "success")

    return redirect(url_for('dashboard'))

@app.route('/assignments/<int:class_id>')
@login_required
def assignments(class_id):
    if current_user.role == 'student':
        assignments = Assignment.query.filter_by(classroom_id=class_id).all()
        return render_template('assignments.html', assignments=assignments, class_id=class_id)
    else:
        return redirect(url_for('dashboard'))

@app.route('/resources')
@login_required
def resources():
    return render_template('resources.html')  

@app.route('/quizzes')
@login_required
def quizzes():
    return render_template('quizzes.html')  

@app.route('/students')
@login_required
def students():
    print(f"User {current_user.username} accessed the students page.")  # Debug log
    if current_user.role == 'teacher':  
        students_list = User.query.filter_by(role='student').all()  
        return render_template('students.html', students=students_list)
    else:
        flash("Only teachers can view the student list!", "danger")
        return redirect(url_for('dashboard'))

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/your_files', methods=['GET', 'POST'])
@login_required
def your_files():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(url_for('your_files'))

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(url_for('your_files'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Save file in database
            new_note = Notes(student_id=current_user.id, filename=filename)
            db.session.add(new_note)
            db.session.commit()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('your_files'))

    uploaded_files = Notes.query.filter_by(student_id=current_user.id).all()
    return render_template('your_files.html', uploaded_files=uploaded_files)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_entry = Notes.query.get(file_id)
    if file_entry and file_entry.student_id == current_user.id:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_entry.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(file_entry)
        db.session.commit()
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found!', 'danger')

    return redirect(url_for('your_files'))

@app.route('/doubt_forum')
@login_required
def doubt_forum():
    doubts = Doubt.query.all()
    return render_template('doubt_forum.html', doubts=doubts)

@app.route('/ask_doubt', methods=['POST'])
@login_required
def ask_doubt():
    question = request.form['question']
    new_doubt = Doubt(student_id=current_user.id, question=question)
    db.session.add(new_doubt)
    db.session.commit()
    flash('Doubt submitted!', 'success')
    return redirect(url_for('doubt_forum'))

@app.route('/answer_doubt/<int:doubt_id>', methods=['POST'])
@login_required
def answer_doubt(doubt_id):
    if current_user.role == 'teacher':
        doubt = Doubt.query.get(doubt_id)
        if doubt:
            doubt.answer = request.form['answer']
            db.session.commit()
            flash('Doubt answered!', 'success')
    return redirect(url_for('doubt_forum'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
