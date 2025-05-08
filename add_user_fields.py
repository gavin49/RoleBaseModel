from sqlalchemy import Column, String, Boolean, DateTime, text
from app import db, app

def upgrade_user_table():
    with app.app_context():
        # Use a transaction to ensure all changes are committed properly
        with db.engine.begin() as conn:
            try:
                # Add email column
                conn.execute(text("IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'email') BEGIN ALTER TABLE [user] ADD email NVARCHAR(120) END"))
                print("Email column check completed")
                
                # Add is_active column
                conn.execute(text("IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'is_active') BEGIN ALTER TABLE [user] ADD is_active BIT DEFAULT 1 END"))
                print("Is_active column check completed")
                
                # Add created_at column
                conn.execute(text("IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'created_at') BEGIN ALTER TABLE [user] ADD created_at DATETIME DEFAULT GETDATE() END"))
                print("Created_at column check completed")
                
                # Add updated_at column
                conn.execute(text("IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'updated_at') BEGIN ALTER TABLE [user] ADD updated_at DATETIME DEFAULT GETDATE() END"))
                print("Updated_at column check completed")
                
                # Add last_login column
                conn.execute(text("IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'last_login') BEGIN ALTER TABLE [user] ADD last_login DATETIME NULL END"))
                print("Last_login column check completed")
                
                print("Migration completed successfully!")
            except Exception as e:
                print(f"Error during migration: {e}")
                raise

if __name__ == "__main__":
    upgrade_user_table()