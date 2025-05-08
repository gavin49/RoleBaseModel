from app import app, db
import os

def main():
    with app.app_context():
        # First check if table exists
        try:
            # Drop and recreate all tables (WARNING: This will delete all your data!)
            db.drop_all()
            db.create_all()
            print("Database schema updated successfully!")
            
            # Create uploads directory if it doesn't exist
            os.makedirs('static/uploads/logos', exist_ok=True)
            print("Upload directories created")
            
        except Exception as e:
            print(f"Error updating database schema: {e}")

if __name__ == "__main__":
    main()