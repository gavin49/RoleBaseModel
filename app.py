import os
from flask import Flask, render_template, redirect, url_for, request, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Length, Email
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps

UPLOAD_FOLDER = 'static/uploads/logos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://DESKTOP-QHEQ4EK/achecker?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

limiter = Limiter(app=app, key_func=get_remote_address)

db = SQLAlchemy(app)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify the login route
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'org_admin', or 'user'
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Helper methods for role checking
    def is_admin(self):
        return self.role == 'admin'
    
    def is_org_admin(self):
        return self.role == 'org_admin'
    
    def can_manage_organization(self):
        return self.role in ['admin', 'org_admin']
        
    def can_manage_users(self):
        return self.role in ['admin', 'org_admin']
        
    def is_authenticated(self):
        return super().is_authenticated and self.is_active

# Add this helper function to generate RGB values from hex colors
def hex_to_rgb(hex_color):
    """Convert hex color to RGB values"""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

# Add this helper function to your app.py
def redirect_authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Organization Model
class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    website = db.Column(db.String(255))
    logo_url = db.Column(db.String(255))
    # Branding fields
    primary_color = db.Column(db.String(7))  # Hex color code
    secondary_color = db.Column(db.String(7))
    email_template = db.Column(db.String(20), default='default')
    custom_css = db.Column(db.Text)
    # Security fields
    enforce_2fa = db.Column(db.Boolean, default=False)
    session_timeout = db.Column(db.Integer, default=60)
    password_policy = db.Column(db.String(20), default='standard')
    ip_restriction = db.Column(db.Boolean, default=False)
    ip_whitelist = db.Column(db.Text)
    # Access control
    allow_invites = db.Column(db.Boolean, default=True)
    require_approval = db.Column(db.Boolean, default=False)
    # Relations
    users = db.relationship('User', backref='organization', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def primary_color_rgb(self):
        """Convert primary color hex to RGB values string for CSS"""
        if not self.primary_color:
            return "59, 130, 246"  # Default blue
        
        try:
            hex_color = self.primary_color.lstrip('#')
            if len(hex_color) != 6:
                return "59, 130, 246"  # Default if invalid format
                
            r = int(hex_color[0:2], 16)
            g = int(hex_color[2:4], 16)
            b = int(hex_color[4:6], 16)
            return f"{r}, {g}, {b}"
        except:
            return "59, 130, 246"  # Default on error

# Organizational Data Model
class OrganizationData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    organization = db.Column(db.String(100), nullable=False)

# User Settings Model
class UserSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    theme = db.Column(db.String(10), default='light')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='settings')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin', 'Main Admin'), ('org_admin', 'Organization Admin'), ('user', 'User')], validators=[DataRequired()])
    organization = StringField('Organization', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Form for user management
class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password')])
    role = SelectField('Role', choices=[
        ('admin', 'Administrator'), 
        ('org_admin', 'Organization Admin'), 
        ('user', 'Regular User')
    ], validators=[DataRequired()])
    organization_id = SelectField('Organization', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Save')
    
    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        # Populate organizations dropdown - this will be done in the route

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Add this function to ensure images exist
def ensure_images_exist():
    # Define the image paths
    images = [
        ('static/img/hero-illustration.svg', '''<svg width="600" height="400" viewBox="0 0 600 400" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="600" height="400" fill="#F0F9FF"/>
  <rect x="50" y="70" width="500" height="260" rx="10" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  
  <!-- Header -->
  <rect x="50" y="70" width="500" height="50" rx="10" fill="#3B82F6" stroke="#2563EB" stroke-width="2"/>
  <text x="80" y="103" font-family="Arial" font-size="18" font-weight="bold" fill="white">AChecker Dashboard</text>
  
  <!-- Sidebar -->
  <rect x="50" y="120" width="120" height="210" fill="#F9FAFB" stroke="#E5E7EB" stroke-width="2"/>
  <circle cx="85" cy="150" r="15" fill="#3B82F6"/>
  <rect x="70" y="180" width="80" height="8" rx="4" fill="#E5E7EB"/>
  <rect x="70" y="200" width="80" height="8" rx="4" fill="#E5E7EB"/>
  <rect x="70" y="220" width="80" height="8" rx="4" fill="#E5E7EB"/>
  <rect x="70" y="240" width="80" height="8" rx="4" fill="#E5E7EB"/>
  <rect x="70" y="260" width="80" height="8" rx="4" fill="#E5E7EB"/>
  
  <!-- Main Content -->
  <rect x="190" y="140" width="340" height="60" rx="8" fill="#F9FAFB" stroke="#E5E7EB" stroke-width="2"/>
  <rect x="210" y="160" width="200" height="10" rx="5" fill="#D1D5DB"/>
  <rect x="210" y="180" width="140" height="8" rx="4" fill="#E5E7EB"/>
  
  <rect x="190" y="220" width="160" height="90" rx="8" fill="#F9FAFB" stroke="#E5E7EB" stroke-width="2"/>
  <circle cx="270" cy="255" r="25" fill="#3B82F6" fill-opacity="0.2" stroke="#3B82F6" stroke-width="2"/>
  <text x="265" y="260" font-family="Arial" font-size="14" font-weight="bold" fill="#3B82F6">65%</text>
  <rect x="210" y="290" width="120" height="8" rx="4" fill="#E5E7EB"/>
  
  <rect x="370" y="220" width="160" height="90" rx="8" fill="#F9FAFB" stroke="#E5E7EB" stroke-width="2"/>
  <rect x="390" y="240" width="120" height="10" rx="5" fill="#D1D5DB"/>
  <rect x="390" y="260" width="120" height="8" rx="4" fill="#E5E7EB"/>
  <rect x="390" y="275" width="120" height="8" rx="4" fill="#E5E7EB"/>
  <rect x="390" y="290" width="80" height="8" rx="4" fill="#E5E7EB"/>
</svg>'''),
        ('static/img/about-image.svg', '''<svg width="500" height="400" viewBox="0 0 500 400" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="500" height="400" rx="10" fill="#F9FAFB"/>
  
  <!-- Top Section -->
  <rect x="50" y="50" width="400" height="100" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <rect x="70" y="70" width="140" height="14" rx="7" fill="#3B82F6"/>
  <rect x="70" y="94" width="360" height="10" rx="5" fill="#E5E7EB"/>
  <rect x="70" y="114" width="320" height="10" rx="5" fill="#E5E7EB"/>
  
  <!-- Middle Section - Stats -->
  <rect x="50" y="170" width="190" height="80" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <circle cx="100" cy="210" r="25" fill="#10B981" fill-opacity="0.2" stroke="#10B981" stroke-width="2"/>
  <text x="93" y="215" font-family="Arial" font-size="14" font-weight="bold" fill="#10B981">98%</text>
  <rect x="140" y="195" width="80" height="10" rx="5" fill="#D1D5DB"/>
  <rect x="140" y="215" width="60" height="8" rx="4" fill="#E5E7EB"/>
  
  <rect x="260" y="170" width="190" height="80" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <circle cx="310" cy="210" r="25" fill="#3B82F6" fill-opacity="0.2" stroke="#3B82F6" stroke-width="2"/>
  <text x="303" y="215" font-family="Arial" font-size="14" font-weight="bold" fill="#3B82F6">85%</text>
  <rect x="350" y="195" width="80" height="10" rx="5" fill="#D1D5DB"/>
  <rect x="350" y="215" width="60" height="8" rx="4" fill="#E5E7EB"/>
  
  <!-- Bottom Section - Security -->
  <rect x="50" y="270" width="400" height="80" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <circle cx="90" cy="310" r="20" fill="#3B82F6"/>
  <path d="M82 310L88 316L98 306" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
  <rect x="130" y="295" width="100" height="10" rx="5" fill="#D1D5DB"/>
  <rect x="130" y="315" width="280" height="8" rx="4" fill="#E5E7EB"/>
</svg>'''),
        ('static/img/favicon.png', '''<svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="32" height="32" rx="4" fill="#3B82F6"/>
  <path d="M10 16L14 20L22 12" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>'''),
    ]
    
    # Ensure directories exist
    os.makedirs('static/img', exist_ok=True)
    
    # Create each image file if it doesn't exist
    for path, content in images:
        file_path = os.path.join(app.root_path, path)
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(content)

# Routes
@app.route('/')
@redirect_authenticated
def home():
    organization = None
    return render_template('home.html', organization=organization)

@app.route('/about')
@redirect_authenticated
def about():
    return render_template('about.html')

@app.route('/contact')
@redirect_authenticated
def contact():
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    # Try to get organization from URL param
    org_name = request.args.get('org')
    organization = None
    if org_name:
        organization = Organization.query.filter_by(name=org_name).first()
    
    # If no org in URL, get first org (for demo purposes)
    if not organization:
        organization = Organization.query.first()
    
    if form.validate_on_submit():
        # Create or get organization
        org = Organization.query.filter_by(name=form.organization.data).first()
        if not org:
            org = Organization(name=form.organization.data)
            db.session.add(org)
            db.session.flush()  # Get the org ID
        
        # Create user
        hashed_pw = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user = User(
            username=form.username.data,
            password=hashed_pw,
            role=form.role.data,
            organization_id=org.id
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form, organization=organization)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
            # Check if user is active (either by is_active property or role != 'disabled')
            if (hasattr(user, 'is_active') and user.is_active) or (not hasattr(user, 'is_active') and user.role != 'disabled'):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Your account has been deactivated. Please contact your administrator.', 'danger')
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get organization data for the current user's organization
    organization_data = OrganizationData.query.filter_by(organization=current_user.organization.name).all()
    
    # Different stats for different roles
    if current_user.role == 'admin':
        # Main admin sees global stats
        organization_count = Organization.query.count()
        user_count = User.query.count()
        org_user_count = User.query.filter_by(organization_id=current_user.organization_id).count()
    else:
        # Org admin only sees their organization's stats
        organization_count = None
        user_count = None
        org_user_count = User.query.filter_by(organization_id=current_user.organization_id).count()
    
    return render_template(
        'dashboard.html', 
        active_page='dashboard', 
        organization_data=organization_data,
        organization_count=organization_count,
        user_count=user_count,
        org_user_count=org_user_count
    )

@app.route('/organization/settings')
@login_required
def organization_settings():
    # Only admins and org_admins can access organization settings
    if not current_user.can_manage_organization():
        flash("You don't have permission to access organization settings.", "error")
        return redirect(url_for('dashboard'))
    
    organization = Organization.query.get(current_user.organization_id)
    return render_template('organization_settings.html', 
                          active_page='org_settings', 
                          organization=organization)

@app.route('/organization/update', methods=['POST'])
@login_required
def update_organization():
    # Check permissions
    if not current_user.can_manage_organization():
        flash("You don't have permission to update organization settings.", "error")
        return redirect(url_for('dashboard'))
    
    organization = Organization.query.get(current_user.organization_id)
    
    if not organization:
        flash('Organization not found', 'error')
        return redirect(url_for('organization_settings'))
    
    organization.name = request.form.get('org_name')
    organization.website = request.form.get('website')
    organization.description = request.form.get('description')
    
    db.session.commit()
    flash('Organization details updated successfully', 'success')
    return redirect(url_for('organization_settings'))

@app.route('/organization/update-logo', methods=['POST'])
@login_required
def update_organization_logo():
    organization = Organization.query.get(current_user.organization_id)
    
    if not organization:
        flash('Organization not found', 'error')
        return redirect(url_for('organization_settings'))
    
    if 'logo' in request.files:
        file = request.files['logo']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"org_{organization.id}_{file.filename}")
            
            # Create directory if it doesn't exist
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            
            filepath = os.path.join(app.root_path, UPLOAD_FOLDER, filename)
            
            # Delete old logo if exists
            if organization.logo_url:
                old_filepath = os.path.join(app.root_path, organization.logo_url.lstrip('/'))
                if os.path.exists(old_filepath):
                    os.remove(old_filepath)
            
            # Save new logo
            file.save(filepath)
            organization.logo_url = f'/{UPLOAD_FOLDER}/{filename}'
            db.session.commit()
            
            flash('Logo updated successfully', 'success')
        else:
            flash('Invalid file format. Please upload a valid image file.', 'error')
    
    return redirect(url_for('organization_settings') + '#logo-tab')

@app.route('/organization/remove-logo', methods=['POST'])
@login_required
def remove_organization_logo():
    # Check permissions
    if not current_user.can_manage_organization():
        return jsonify({'success': False, 'error': 'Permission denied'}), 403
    
    organization = Organization.query.get(current_user.organization_id)
    
    if not organization:
        return jsonify({'success': False, 'error': 'Organization not found'}), 404
    
    if organization.logo_url:
        # Delete the logo file
        try:
            logo_path = os.path.join(app.root_path, organization.logo_url.lstrip('/'))
            if os.path.exists(logo_path):
                os.remove(logo_path)
                
            # Update database record
            organization.logo_url = None
            db.session.commit()
            return jsonify({'success': True}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({'success': False, 'error': 'No logo to remove'}), 400

@app.route('/organization/update-branding', methods=['POST'])
@login_required
def update_organization_branding():
    # Check permissions
    if not current_user.can_manage_organization():
        flash("You don't have permission to update organization settings.", "error")
        return redirect(url_for('dashboard'))
    
    organization = Organization.query.get(current_user.organization_id)
    
    if not organization:
        flash('Organization not found', 'error')
        return redirect(url_for('organization_settings'))
    
    # Get color values from form - use the hex input as the primary source
    primary_color = request.form.get('primary_color_hex', '#3B82F6')
    secondary_color = request.form.get('secondary_color_hex', '#6B7280')
    
    # Validate hex color format
    def is_valid_hex_color(color):
        import re
        return bool(re.match(r'^#[0-9A-Fa-f]{6}$', color))
    
    if not is_valid_hex_color(primary_color) or not is_valid_hex_color(secondary_color):
        flash('Invalid color format. Please use valid hex colors (e.g., #3B82F6).', 'error')
        return redirect(url_for('organization_settings') + '#branding')
    
    # Update organization branding
    organization.primary_color = primary_color
    organization.secondary_color = secondary_color
    
    try:
        db.session.commit()
        flash('Branding settings updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to update branding: {str(e)}', 'error')
        
    return redirect(url_for('organization_settings') + '#branding')

@app.route('/organization/update-security', methods=['POST'])
@login_required
def update_organization_security():
    organization = Organization.query.get(current_user.organization_id)
    
    if not organization:
        flash('Organization not found', 'error')
        return redirect(url_for('organization_settings'))
    
    organization.enforce_2fa = 'enforce_2fa' in request.form
    organization.password_policy = request.form.get('password_policy')
    
    db.session.commit()
    flash('Security settings updated successfully', 'success')
    return redirect(url_for('organization_settings') + '#security-tab')

@app.route('/api/settings/theme', methods=['POST'])
@login_required
def update_theme():
    data = request.get_json()
    theme = data.get('theme')
    
    if theme not in ['light', 'dark']:
        return jsonify({'error': 'Invalid theme'}), 400
        
    # Get or create user settings
    user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not user_settings:
        user_settings = UserSettings(user_id=current_user.id)
        db.session.add(user_settings)
    
    # Update theme
    user_settings.theme = theme
    user_settings.updated_at = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({'message': 'Theme updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update theme'}), 500

# User CRUD routes
@app.route('/users')
@login_required
def list_users():
    # Regular users shouldn't be able to access the user management page
    if not current_user.can_manage_users():
        flash('You do not have permission to manage users.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Get users from current organization or all users if admin
    if current_user.is_admin():
        # Admin can see all users
        users = User.query.all()
    else:
        # Org admins can only see users in their organization
        users = User.query.filter_by(organization_id=current_user.organization_id).all()
        
    return render_template('users.html', users=users, active_page='users')

@app.route('/users/new', methods=['GET', 'POST'])
@login_required
def new_user():
    # Check basic permissions - only admins and org admins can create users
    if not current_user.can_manage_users():
        flash('You do not have permission to create users.', 'danger')
        return redirect(url_for('dashboard'))
        
    form = UserForm()
    
    # Populate organizations dropdown based on permissions
    if current_user.is_admin():
        # Admin can see all organizations
        orgs = Organization.query.all()
        # Admin can create users with any role
        form.role.choices = [
            ('admin', 'Administrator'), 
            ('org_admin', 'Organization Admin'), 
            ('user', 'Regular User')
        ]
    else:
        # Org admins can only see their organization
        orgs = Organization.query.filter_by(id=current_user.organization_id).all()
        # Org admins can only create org_admin or regular users
        form.role.choices = [
            ('org_admin', 'Organization Admin'), 
            ('user', 'Regular User')
        ]
        
    form.organization_id.choices = [(org.id, org.name) for org in orgs]
    
    if request.method == 'POST' and not form.password.data:
        form.password.errors = ['Password is required for new users']
        return render_template('user_form.html', form=form, title='Create New User')
    
    if form.validate_on_submit():
        # Additional security check - prevent org admins from creating admin users
        if not current_user.is_admin() and form.role.data == 'admin':
            flash('You do not have permission to create administrator users.', 'danger')
            return render_template('user_form.html', form=form, title='Create New User')
            
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
        else:
            # Hash password
            hashed_pw = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Create user
            user = User(
                username=form.username.data,
                password=hashed_pw,
                role=form.role.data,
                organization_id=form.organization_id.data
            )
            
            db.session.add(user)
            db.session.commit()
            
            flash('User created successfully!', 'success')
            return redirect(url_for('list_users'))
            
    return render_template('user_form.html', form=form, title='Create New User')

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Check permissions
    if not current_user.can_manage_users():
        flash('You do not have permission to edit users.', 'danger')
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(user_id)
    
    # Check if user belongs to current organization (unless admin)
    if not current_user.is_admin() and user.organization_id != current_user.organization_id:
        flash('You do not have permission to edit this user.', 'danger')
        return redirect(url_for('list_users'))
        
    form = UserForm(obj=user)
    
    # Populate organizations dropdown based on permissions
    if current_user.is_admin():
        # Admin can see all organizations
        orgs = Organization.query.all()
        # Admin can assign any role
        form.role.choices = [
            ('admin', 'Administrator'), 
            ('org_admin', 'Organization Admin'), 
            ('user', 'Regular User')
        ]
    else:
        # Org admins can only see their organization
        orgs = Organization.query.filter_by(id=current_user.organization_id).all()
        # Org admins can only assign org_admin or regular user roles
        form.role.choices = [
            ('org_admin', 'Organization Admin'), 
            ('user', 'Regular User')
        ]
        
    form.organization_id.choices = [(org.id, org.name) for org in orgs]
    
    # Prevent org admins from editing admin users
    if not current_user.is_admin() and user.role == 'admin':
        flash('You do not have permission to edit administrator users.', 'danger')
        return redirect(url_for('list_users'))
    
    if form.validate_on_submit():
        # Additional security check - prevent org admins from setting admin role
        if not current_user.is_admin() and form.role.data == 'admin':
            flash('You do not have permission to create administrator users.', 'danger')
            return render_template('user_form.html', form=form, title='Edit User', user=user)
            
        user.username = form.username.data
        user.role = form.role.data
        user.organization_id = form.organization_id.data
        
        # Only update password if provided
        if form.password.data:
            user.password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('list_users'))
        
    # Clear password fields for security
    form.password.data = ''
    form.confirm_password.data = ''
    
    return render_template('user_form.html', form=form, title='Edit User', user=user)

@app.route('/users/<int:user_id>/view')
@login_required
def view_user(user_id):
    # Check permissions
    if not current_user.can_manage_users():
        flash('You do not have permission to view user details.', 'danger')
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(user_id)
    
    # Check if user belongs to current organization (unless admin)
    if not current_user.is_admin() and user.organization_id != current_user.organization_id:
        flash('You do not have permission to view this user.', 'danger')
        return redirect(url_for('list_users'))
        
    return render_template('user_detail.html', user=user)

@app.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user(user_id):
    # Check basic permissions
    if not current_user.can_manage_users():
        return jsonify({'success': False, 'message': 'You do not have permission to manage users.'}), 403
        
    user = User.query.get_or_404(user_id)
    
    # Check if user belongs to current organization (unless admin)
    if not current_user.is_admin() and user.organization_id != current_user.organization_id:
        return jsonify({'success': False, 'message': 'You do not have permission to manage this user.'}), 403
        
    # Prevent deactivating yourself
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'You cannot deactivate your own account.'}), 400
    
    # Prevent org admins from toggling admin users
    if not current_user.is_admin() and user.role == 'admin':
        return jsonify({'success': False, 'message': 'Organization admins cannot modify administrator accounts.'}), 403
        
    # Toggle status
    try:
        if user.is_active == False or user.role == 'disabled':
            # Reactivate user
            user.is_active = True
            if user.role == 'disabled':  
                user.role = 'user'  # Default to regular user when reactivating
            status = 'active'
            message = f"User {user.username} has been activated."
        else:
            # Deactivate user
            user.is_active = False
            status = 'inactive'
            message = f"User {user.username} has been deactivated."
            
        db.session.commit()
        return jsonify({'success': True, 'status': status, 'message': message})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# Add this new route

@app.route('/users/batch-action', methods=['POST'])
@login_required
def batch_user_action():
    # Check admin permissions
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Only administrators can perform batch actions.'}), 403
        
    # Get request data
    data = request.json
    if not data or 'action' not in data or 'user_ids' not in data:
        return jsonify({'success': False, 'message': 'Invalid request data.'}), 400
        
    action = data['action']
    user_ids = data['user_ids']
    
    if not user_ids:
        return jsonify({'success': False, 'message': 'No users selected.'}), 400
        
    try:
        # Convert ids to integers and filter out current user
        user_ids = [int(id) for id in user_ids if int(id) != current_user.id]
        
        # Get users
        users = User.query.filter(User.id.in_(user_ids)).all()
        
        # Apply action
        if action == 'activate':
            for user in users:
                user.is_active = True
                if user.role == 'disabled':  
                    user.role = 'user'
            message = f'Successfully activated {len(users)} users.'
        elif action == 'deactivate':
            for user in users:
                user.is_active = False
            message = f'Successfully deactivated {len(users)} users.'
        else:
            return jsonify({'success': False, 'message': 'Invalid action.'}), 400
            
        db.session.commit()
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', active_page='profile')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_images_exist()
    app.run(debug=True)
