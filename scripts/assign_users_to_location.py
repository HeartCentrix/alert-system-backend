#!/usr/bin/env python3
"""
Assign all unassigned users to the first active location.
Useful for testing dashboard map visibility.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal
from app.models import User, Location, UserLocation, UserLocationStatus, UserLocationAssignmentType
from datetime import datetime, timezone

def assign_users_to_location():
    db = SessionLocal()
    
    try:
        # Get first active location
        location = db.query(Location).filter(
            Location.is_active == True
        ).first()
        
        if not location:
            print("❌ No active locations found!")
            return
        
        print(f"✅ Found location: {location.name}")
        
        # Get all users without location assignment
        unassigned_users = db.query(User).filter(
            User.location_id == None,
            User.role == UserRole.VIEWER
        ).all()
        
        if not unassigned_users:
            print("✅ All viewer users already have location assignments")
            return
        
        print(f"\n📋 Found {len(unassigned_users)} unassigned viewer user(s):")
        for user in unassigned_users:
            print(f"  - {user.email} (id={user.id})")
        
        print(f"\n⏳ Assigning {len(unassigned_users)} user(s) to '{location.name}'...")
        
        assigned_count = 0
        for user in unassigned_users:
            # Check if assignment already exists
            existing = db.query(UserLocation).filter(
                UserLocation.user_id == user.id,
                UserLocation.location_id == location.id
            ).first()
            
            if existing:
                print(f"  ⚠️  {user.email} already has an assignment (reactivating)")
                existing.status = UserLocationStatus.ACTIVE
                existing.assignment_type = UserLocationAssignmentType.MANUAL
                assigned_count += 1
            else:
                # Create new assignment
                assignment = UserLocation(
                    user_id=user.id,
                    location_id=location.id,
                    assignment_type=UserLocationAssignmentType.MANUAL,
                    status=UserLocationStatus.ACTIVE,
                    assigned_at=datetime.now(timezone.utc),
                    notes="Assigned via fix script for testing"
                )
                db.add(assignment)
                assigned_count += 1
                print(f"  ✅ {user.email} assigned")
        
        db.commit()
        
        print(f"\n🎉 Successfully assigned {assigned_count} user(s)!")
        print("\n📊 Verification:")
        
        # Verify assignments
        for user in unassigned_users:
            user_loc = db.query(UserLocation).filter(
                UserLocation.user_id == user.id,
                UserLocation.location_id == location.id
            ).first()
            if user_loc:
                print(f"  ✅ {user.email}: {user_loc.status}")
            else:
                print(f"  ❌ {user.email}: NOT ASSIGNED (something went wrong)")
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    from app.models import UserRole
    assign_users_to_location()
