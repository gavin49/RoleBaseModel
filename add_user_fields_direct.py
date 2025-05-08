import pyodbc
from app import app

def upgrade_user_table_direct():
    # Get connection string from Flask app config
    # Parse the SQLAlchemy connection string to extract components
    connection_parts = app.config['SQLALCHEMY_DATABASE_URI'].split('://')[-1]
    server = connection_parts.split('/')[0].split('@')[-1]
    database = connection_parts.split('/')[1].split('?')[0]
    
    # Connect directly using trusted connection
    conn_string = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};Trusted_Connection=yes;"
    
    try:
        # Connect to the database
        print(f"Connecting to {server} database {database}...")
        conn = pyodbc.connect(conn_string, autocommit=True)
        cursor = conn.cursor()
        
        # Add columns one by one
        sql_commands = [
            "IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'email') BEGIN ALTER TABLE [user] ADD email NVARCHAR(120) END",
            "IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'is_active') BEGIN ALTER TABLE [user] ADD is_active BIT DEFAULT 1 END",
            "IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'created_at') BEGIN ALTER TABLE [user] ADD created_at DATETIME DEFAULT GETDATE() END",
            "IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'updated_at') BEGIN ALTER TABLE [user] ADD updated_at DATETIME DEFAULT GETDATE() END",
            "IF NOT EXISTS(SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[user]') AND name = 'last_login') BEGIN ALTER TABLE [user] ADD last_login DATETIME NULL END"
        ]
        
        for i, sql in enumerate(sql_commands):
            try:
                cursor.execute(sql)
                print(f"Command {i+1} executed successfully")
            except Exception as e:
                print(f"Error executing command {i+1}: {e}")
        
        # Close connections
        cursor.close()
        conn.close()
        print("Migration completed successfully!")
        
    except Exception as e:
        print(f"Migration failed: {e}")

if __name__ == "__main__":
    upgrade_user_table_direct()