# research
from flask import Flask, render_template_string, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app and configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a secure random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -------------------------------
# Database Model: User
# -------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    research_interests = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Create database tables (run this once)
with app.app_context():
    db.create_all()

# -------------------------------
# Helper Function: Interest Similarity
# -------------------------------
def get_similarity(interests1, interests2):
    """
    Compute the Jaccard similarity between two sets of interests.
    Expects comma-separated strings of interests.
    """
    # Split by comma, strip whitespace, and convert to lowercase
    set1 = set(map(lambda x: x.strip().lower(), interests1.split(',')))
    set2 = set(map(lambda x: x.strip().lower(), interests2.split(',')))
    
    # Compute intersection and union
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    
    return len(intersection) / len(union) if union else 0

# -------------------------------
# Routes
# -------------------------------

# Home: Redirect to login or profile page based on session
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    register_template = '''
    <h2>Register</h2>
    <form method="POST">
        Username:<br>
        <input type="text" name="username" required><br>
        Email:<br>
        <input type="email" name="email" required><br>
        Password:<br>
        <input type="password" name="password" required><br>
        Research Interests (comma separated):<br>
        <textarea name="research_interests" required></textarea><br>
        <input type="submit" value="Register">
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
    '''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        research_interests = request.form['research_interests']

        # Check if a user with the same username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("User with that username or email already exists.")
            return render_template_string(register_template)
        
        # Hash the password before storing it
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password, research_interests=research_interests)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))
    return render_template_string(register_template)

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_template = '''
    <h2>Login</h2>
    <form method="POST">
        Username:<br>
        <input type="text" name="username" required><br>
        Password:<br>
        <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>
    <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
    '''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Logged in successfully.")
            return redirect(url_for('profile'))
        else:
            flash("Invalid credentials. Please try again.")
            return render_template_string(login_template)
    return render_template_string(login_template)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out.")
    return redirect(url_for('login'))

# User Profile Route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Please log in to access your profile.")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    profile_template = '''
    <h2>Welcome, {{ user.username }}!</h2>
    <p>Email: {{ user.email }}</p>
    <p>Research Interests: {{ user.research_interests }}</p>
    <p><a href="{{ url_for('matches') }}">View Matches</a></p>
    <p><a href="{{ url_for('logout') }}">Logout</a></p>
    '''
    return render_template_string(profile_template, user=user)

# Matches Route: Connect users with overlapping research interests
@app.route('/matches')
def matches():
    if 'user_id' not in session:
        flash("Please log in to view matches.")
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    all_users = User.query.filter(User.id != current_user.id).all()
    
    matches_list = []
    for user in all_users:
        similarity = get_similarity(current_user.research_interests, user.research_interests)
        if similarity > 0:  # Only consider users with some overlapping interest
            matches_list.append((user, similarity))
    
    # Sort matches by similarity in descending order
    matches_list.sort(key=lambda x: x[1], reverse=True)

    matches_template = '''
    <h2>Matches for {{ current_user.username }}</h2>
    {% if matches %}
        <ul>
        {% for match, similarity in matches %}
            <li>
                <strong>{{ match.username }}</strong> (Similarity: {{ "%.2f" % (similarity * 100) }}%)<br>
                Research Interests: {{ match.research_interests }}
            </li>
        {% endfor %}
        </ul>
    {% else %}
        <p>No matches found. Consider updating your research interests.</p>
    {% endif %}
    <p><a href="{{ url_for('profile') }}">Back to Profile</a></p>
    '''
    return render_template_string(matches_template, current_user=current_user, matches=matches_list)

# -------------------------------
# Launching the Application
# -------------------------------
if __name__ == '__main__':
    app.run(debug=True)
