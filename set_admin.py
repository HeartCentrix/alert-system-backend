from app.database import SessionLocal
from app.models import User
from app.core.security import hash_password

db = SessionLocal()
try:
    admin = db.query(User).filter(User.email == 'admin@tmalert.com').first()
    pw = 'Admin@123456'
    
    if not admin:
        admin = User(
            email='admin@tmalert.com',
            hashed_password=hash_password(pw),
            first_name='Super',
            last_name='Admin',
            role='super_admin',  # Use lowercase string instead of enum
            is_active=True,
            force_password_change=True
        )
        db.add(admin)
        db.commit()
        print('Admin user created')
    else:
        admin.hashed_password = hash_password(pw)
        admin.force_password_change = True
        db.commit()
        print('Password updated')
    
    print('Email: admin@tmalert.com')
    print('Password: Admin@123456')
    print('Note: You will be forced to change password on first login')
finally:
    db.close()
