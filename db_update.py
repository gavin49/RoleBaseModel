from app import app, db
import sqlalchemy as sa
from sqlalchemy import text
import os

def run_migration():
    with app.app_context():
        # Check if we need to add columns to organization table
        with db.engine.connect() as conn:
            try:
                # Check if columns exist first
                inspector = sa.inspect(db.engine)
                existing_columns = inspector.get_columns('organization')
                existing_column_names = [col['name'] for col in existing_columns]
                
                print("Existing columns in organization table:", existing_column_names)
                
                # List of columns to add with their definitions
                columns_to_add = {
                    'description': 'NVARCHAR(MAX)',
                    'website': 'NVARCHAR(255)',
                    'logo_url': 'NVARCHAR(255)',
                    'primary_color': 'NVARCHAR(7)',
                    'secondary_color': 'NVARCHAR(7)',
                    'email_template': 'NVARCHAR(20) DEFAULT \'default\'',
                    'custom_css': 'NVARCHAR(MAX)',
                    'enforce_2fa': 'BIT DEFAULT 0',
                    'session_timeout': 'INT DEFAULT 60',
                    'password_policy': 'NVARCHAR(20) DEFAULT \'standard\'',
                    'ip_restriction': 'BIT DEFAULT 0',
                    'ip_whitelist': 'NVARCHAR(MAX)',
                    'allow_invites': 'BIT DEFAULT 1',
                    'require_approval': 'BIT DEFAULT 0',
                    'created_at': 'DATETIME DEFAULT GETDATE()',
                    'updated_at': 'DATETIME DEFAULT GETDATE()'
                }
                
                # Add each missing column
                for column_name, column_type in columns_to_add.items():
                    if column_name not in existing_column_names:
                        print(f"Adding column {column_name} to organization table")
                        conn.execute(text(f"ALTER TABLE organization ADD {column_name} {column_type}"))
                
                print("Database schema updated successfully!")
                
                # Create uploads directory if it doesn't exist
                os.makedirs('static/uploads/logos', exist_ok=True)
                print("Upload directories created")
                
            except Exception as e:
                print(f"Error updating database schema: {e}")
                raise

if __name__ == "__main__":
    run_migration()