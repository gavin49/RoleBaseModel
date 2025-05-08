from app import app, db
from sqlalchemy import text
import os

def fix_database():
    with app.app_context():
        try:
            # Direct SQL approach for SQL Server
            with db.engine.connect() as conn:
                # Check if table exists first
                conn.execute(text("IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'organization') BEGIN CREATE TABLE organization (id INT IDENTITY(1,1) PRIMARY KEY, name NVARCHAR(100) NOT NULL) END"))
                
                # List of columns to add - SQL Server specific syntax
                columns = [
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'description' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD description NVARCHAR(MAX) NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'website' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD website NVARCHAR(255) NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'logo_url' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD logo_url NVARCHAR(255) NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'primary_color' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD primary_color NVARCHAR(7) NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'secondary_color' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD secondary_color NVARCHAR(7) NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'email_template' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD email_template NVARCHAR(20) DEFAULT 'default' NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'custom_css' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD custom_css NVARCHAR(MAX) NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'enforce_2fa' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD enforce_2fa BIT DEFAULT 0 NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'session_timeout' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD session_timeout INT DEFAULT 60 NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'password_policy' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD password_policy NVARCHAR(20) DEFAULT 'standard' NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'ip_restriction' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD ip_restriction BIT DEFAULT 0 NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'ip_whitelist' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD ip_whitelist NVARCHAR(MAX) NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'allow_invites' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD allow_invites BIT DEFAULT 1 NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'require_approval' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD require_approval BIT DEFAULT 0 NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'created_at' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD created_at DATETIME DEFAULT GETDATE() NULL END",
                    "IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name = 'updated_at' AND Object_ID = Object_ID('organization')) BEGIN ALTER TABLE organization ADD updated_at DATETIME DEFAULT GETDATE() NULL END"
                ]
                
                # Execute each SQL statement
                for sql in columns:
                    conn.execute(text(sql))
                
                print("SQL Server table structure updated successfully.")
                
                # Verify if there's at least one organization
                result = conn.execute(text("SELECT COUNT(*) FROM organization")).scalar()
                if result == 0:
                    # Insert a default organization if none exists
                    conn.execute(text("INSERT INTO organization (name) VALUES ('Default Organization')"))
                    print("Default organization created.")
                
                # Create upload directory
                os.makedirs('static/uploads/logos', exist_ok=True)
                print("Upload directories created.")
                
                # Commit transaction
                conn.commit()
                
        except Exception as e:
            print(f"Error updating database: {e}")
            raise

if __name__ == "__main__":
    fix_database()