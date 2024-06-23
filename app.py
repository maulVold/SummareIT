from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

logging.basicConfig(level=logging.DEBUG)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Summary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    date_read = db.Column(db.String(100), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('profile'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        logging.debug('User is not logged in, redirecting to login page.')
        return redirect(url_for('login'))
    user_id = session['user_id']
    logging.debug(f'User ID from session: {user_id}')
    user = User.query.get(user_id)
    if not user:
        logging.debug('User not found, redirecting to login page.')
        return redirect(url_for('login'))
    summaries = Summary.query.filter_by(user_id=user_id).all()
    logging.debug(f'Found {len(summaries)} summaries for user ID {user_id}')
    return render_template('profile.html', user=user, summaries=summaries)

@app.route('/add_summary', methods=['GET', 'POST'])
def add_summary():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        date_read = request.form['date_read']
        summary = request.form['summary']
        new_summary = Summary(title=title, author=author, date_read=date_read, summary=summary, user_id=session['user_id'])
        db.session.add(new_summary)
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('add_summary.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
