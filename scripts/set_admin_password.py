"""
Set a known password for the admin@tmalert.com user.
Run this script to reset the admin password after a fresh database setup.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.database import SessionLocal
from app.models import User
from app.core.security import hash_password

# Default credentials
ADMIN_EMAIL = "admin@tmalert.com"
ADMIN_PASSWORD = "Admin@123456"  # Change this after first login!

def set_admin_password():
    db = SessionLocal()
    try:
        # Check if admin user exists
        admin = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        
        if not admin:
            # Create admin user
            from app.models import UserRole
            admin = User(
                email=ADMIN_EMAIL,
                hashed_password=hash_password(ADMIN_PASSWORD),
                first_name="Super",
                last_name="Admin",
                role=UserRole.SUPER_ADMIN,
                is_active=True,
                force_password_change=True
            )
            db.add(admin)
            db.commit()
            print(f"✓ Admin user created: {ADMIN_EMAIL}")
        else:
            # Update password
            admin.hashed_password = hash_password(ADMIN_PASSWORD)
            admin.force_password_change = True
            db.commit()
            print(f"✓ Admin password updated for: {ADMIN_EMAIL}")
        
        print(f"\n{'='*50}")
        print(f"Email:    {ADMIN_EMAIL}")
        print(f"Password: {ADMIN_PASSWORD}")
        print(f"{'='*50}")
        print("\n⚠️  IMPORTANT: Change this password after first login!")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    set_admin_password()
