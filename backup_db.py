import os
import shutil
from datetime import datetime

def backup_database():
    """Create a timestamped backup of the database."""
    # Ensure backup directory exists
    backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    
    # Source database path
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'app.db')
    
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        return
    
    # Create backup filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(backup_dir, f'app_{timestamp}.db')
    
    try:
        shutil.copy2(db_path, backup_path)
        print(f"Backup created: {backup_path}")
        
        # Keep only the last 5 backups
        backups = sorted(
            [f for f in os.listdir(backup_dir) if f.startswith('app_') and f.endswith('.db')],
            reverse=True
        )
        
        for old_backup in backups[5:]:
            os.remove(os.path.join(backup_dir, old_backup))
            print(f"Removed old backup: {old_backup}")
            
    except Exception as e:
        print(f"Error creating backup: {e}")

if __name__ == '__main__':
    backup_database()
