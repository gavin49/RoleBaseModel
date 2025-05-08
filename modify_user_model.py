from app import app, db, User

def modify_user_model():
    # Drop the existing User model from SQLAlchemy's registry (not the database)
    with app.app_context():
        # Backup the important parts of the User model
        try:
            # Create a new version of the User model
            class CompatUser(db.Model):
                __tablename__ = 'user'
                id = db.Column(db.Integer, primary_key=True)
                username = db.Column(db.String(80), unique=True, nullable=False)
                password = db.Column(db.String(120), nullable=False)
                role = db.Column(db.String(20), nullable=False)
                organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
                
                # Relations should remain intact
                organization = db.relationship('Organization', back_populates='users')
            
            # Replace the User model in app.py with suggestions for changes
            print("""
Please update your User model in app.py to match the database:

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    
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
        return self.is_authenticated
""")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    modify_user_model()