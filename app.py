from flask import Flask, render_template, request, redirect, flash, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.instance_path = "/tmp"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # For session management
db = SQLAlchemy(app)
os.makedirs(app.instance_path, exist_ok=True)

# User Model
class User(UserMixin, db.Model):
    _tablename_="user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Make sure this column exists
    

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if not authenticated

# Flask-WTF Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')  # Add this line
    submit = SubmitField('Login')

@app.route('/')
def home_page():
    return render_template('home.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        
        if existing_user is None:
            # Hash the password before storing
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'warning')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            # Log the user in
            login_user(user, remember=form.remember_me.data)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('dashboard'))  # Assuming 'dashboard' is your post-login page
        else:
            flash('Login unsuccessful. Check your credentials and try again.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'success')
    response = make_response(redirect(url_for('login')))  # Redirect to login
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'  # Prevent caching
    return response


# Todo Model
class Todo(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable = False)
    desc = db.Column(db.String(500), nullable = False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"{self.sno} - {self.title}"

# Routes
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    no_result = False

    if query:
        # Filter todos based on title or description matching the query
        results = Todo.query.filter(
            (Todo.title.contains(query)) | (Todo.desc.contains(query))
        ).all()
        if not results:
            no_result = True  # No results found for the search query
    else:
        # If no search query is provided, redirect to the home page to show all todos
        return redirect('/dashboard')
    
    return render_template('dashboard.html', allTodo=results, search_query=query, no_result=no_result)
    
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == "POST":
        title = request.form['title']
        desc = request.form['desc']
        if not title or not desc:
            flash('Title and description are required!', 'error')
            return redirect('/dashboard')

        todo = Todo(title=title, desc=desc)
        db.session.add(todo)
        db.session.commit()
        return redirect('/dashboard')

    allTodo = Todo.query.all()
    # Return response with no-cache headers
    response = make_response(render_template('dashboard.html', allTodo=allTodo))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/show')
def products():
    allTodo = Todo.query.all()
    print(allTodo)
    return 'this is products page!'

@app.route('/update/<int:sno>',methods=['GET','POST'])
def update(sno):
    if request.method == "POST":
        title = request.form['title']
        desc = request.form['desc']
        todo = Todo.query.filter_by(sno=sno).first()
        todo.title = title
        todo.desc = desc
        db.session.add(todo)
        db.session.commit()
        return redirect("/dashboard")
    
    todo = Todo.query.filter_by(sno=sno).first()
    return render_template('update.html',todo=todo)

@app.route('/delete/<int:sno>')
def delete(sno):
    todo = Todo.query.filter_by(sno=sno).first()
    db.session.delete(todo)
    db.session.commit() 
    return redirect("/dashboard")

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, port=8000)


