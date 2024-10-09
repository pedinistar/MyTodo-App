from flask import Flask, request, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask import make_response

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return "This email is already registered. Please use a different email."

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Automatically log in the user after registration
        session['email'] = new_user.email
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = request.form.get('remember')  # Get the remember me checkbox value

        user = User.query.filter_by(email=email).first()

        if not user:
            # If the user is not found, show an error message
            return render_template('login.html', error='Email not found. Please register first.')

        if user and user.check_password(password):
            session['email'] = user.email
            response = redirect('/dashboard')

            if remember:
                # Set a cookie to remember the user for a longer period
                response.set_cookie('email', user.email, max_age=30*24*60*60)  # 30 days
            else:
                response.set_cookie('email', '', expires=0)

            return response
        else:
            return render_template('login.html', error='Invalid email or password')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    email = session.get('email') or request.cookies.get('email')

    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('dashboard.html', user=user)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    response = redirect('/login')
    response.set_cookie('email', '', expires=0)  # Remove the remember me cookie
    return response

if __name__ == "__main__":
    app.run(debug=True)
