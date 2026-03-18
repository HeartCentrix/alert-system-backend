from app.database import SessionLocal
from app.models import User
from app.core.security import hash_password

db = SessionLocal()
try:
    admin = db.query(User).filter(User.email == 'admin@tmalert.com').first()
    pw = 'Admin@123456'
    
    if admin:
        admin.hashed_password = hash_password(pw)
        admin.force_password_change = True
        db.commit()
        print('Password updated successfully')
        print('Email: admin@tmalert.com')
        print('Password: Admin@123456')
    else:
        print('Admin user not found')
finally:
    db.close()
