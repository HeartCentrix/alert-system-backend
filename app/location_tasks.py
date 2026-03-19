"""
Celery Tasks for Location Audience Management

Handles:
- Background geofence checking
- Automatic user assignment/removal based on location
- Redis GEO index synchronization
- Batch processing for performance
"""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, or_

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import (
    User, Location, UserLocation, UserLocationHistory,
    UserLocationAssignmentType, UserLocationStatus
)
from app.core.geofence import (
    check_geofence, check_geofences_batch, haversine_distance,
    get_geo_service, validate_coordinates
)
from app.config import settings

logger = logging.getLogger(__name__)


def _scrub_user_id(user_id: Optional[int]) -> str:
    """Scrub user ID for safe logging (shows only last 4 chars)."""
    if user_id is None:
        return "[REDACTED]"
    user_str = str(user_id)
    if len(user_str) <= 4:
        return "[USER]"
    return f"[USER_...{user_str[-4:]}]"


def _scrub_coordinates(lat: Optional[float], lon: Optional[float]) -> str:
    """Scrub coordinates for safe logging (shows only quadrant)."""
    if lat is None or lon is None:
        return "[REDACTED]"
    lat_q = "N" if lat >= 0 else "S"
    lon_q = "E" if lon >= 0 else "W"
    return f"[{lat_q}{lon_q}_APPROX]"


# ─── GEOFENCE CHECKING TASKS ──────────────────────────────────────────────────

@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def check_user_geofence_task(self, user_id: int, latitude: float, longitude: float) -> Dict[str, Any]:
    """
    Check user's location against all active geofences and update memberships.
    
    This is the main entry point for geofence-based assignment.
    
    Flow:
    1. Validate coordinates
    2. Get all active locations
    3. Check geofences (batch)
    4. Update user_locations table
    5. Record history
    6. Sync Redis GEO index
    
    Args:
        user_id: Database user ID
        latitude: User's current latitude
        longitude: User's current longitude
    
    Returns:
        Dict with assignment results
    """
    db = SessionLocal()
    try:
        # Validate coordinates
        is_valid, error = validate_coordinates(latitude, longitude)
        if not is_valid:
            return {"success": False, "error": error}
        
        # Get user
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "User not found"}
        
        # Get all active locations
        locations = db.query(Location).filter(
            Location.is_active == True,
            Location.latitude.isnot(None),
            Location.longitude.isnot(None)
        ).all()
        
        if not locations:
            return {"success": True, "message": "No active locations to check"}
        
        # Batch geofence check
        results = check_geofences_batch(latitude, longitude, locations)
        
        # Track changes
        assignments_changed = []
        
        # Process each location
        for result in results:
            if result.is_inside:
                # User is inside geofence - assign if not already
                changed = _assign_user_to_location(
                    db=db,
                    user_id=user_id,
                    location_id=result.location_id,
                    assignment_type=UserLocationAssignmentType.GEOFENCE,
                    detected_latitude=latitude,
                    detected_longitude=longitude,
                    distance_miles=result.distance_miles,
                    action="entered_geofence"
                )
                if changed:
                    assignments_changed.append({
                        "location_id": result.location_id,
                        "location_name": result.location_name,
                        "action": "assigned",
                        "distance_miles": result.distance_miles
                    })
            else:
                # User is outside geofence - remove if was inside
                changed = _remove_user_from_location(
                    db=db,
                    user_id=user_id,
                    location_id=result.location_id,
                    reason=f"User exited geofence (distance: {result.distance_miles:.2f} miles)",
                    detected_latitude=latitude,
                    detected_longitude=longitude,
                    distance_miles=result.distance_miles,
                    action="exited_geofence"
                )
                if changed:
                    assignments_changed.append({
                        "location_id": result.location_id,
                        "location_name": result.location_name,
                        "action": "removed",
                        "distance_miles": result.distance_miles
                    })
        
        # Update user's primary location if changed
        _update_primary_location(db, user_id, results)
        
        db.commit()
        
        # Sync to Redis GEO (async, don't block)
        _sync_user_to_redis.delay(user_id, latitude, longitude)

        inside_count = len([r for r in results if r.is_inside])
        logger.info(
            f"Geofence check for user {_scrub_user_id(user_id)}: "
            f"{inside_count} locations inside, "
            f"{len(assignments_changed)} changes"
        )
        
        return {
            "success": True,
            "user_id": user_id,
            "latitude": latitude,
            "longitude": longitude,
            "locations_inside": len([r for r in results if r.is_inside]),
            "locations_outside": len([r for r in results if not r.is_inside]),
            "assignments_changed": assignments_changed
        }
        
    except Exception as e:
        logger.error(f"Geofence check failed for user {_scrub_user_id(user_id)}: {type(e).__name__}")
        db.rollback()
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=10)
def batch_geofence_check_task(
    self,
    user_locations: List[Dict[str, float]]
) -> Dict[str, Any]:
    """
    Process geofence checks for multiple users in batch.

    Optimized for processing many users efficiently.

    Args:
        user_locations: List of {user_id, latitude, longitude} dicts

    Returns:
        Summary of changes
    """
    db = SessionLocal()
    results_summary = {
        "processed": 0,
        "success": 0,
        "failed": 0,
        "total_changes": 0
    }

    try:
        # Get all active locations once (shared across all users)
        locations = _get_active_locations(db)

        for user_loc in user_locations:
            user_id = user_loc.get("user_id")
            try:
                latitude = user_loc["latitude"]
                longitude = user_loc["longitude"]

                # Validate
                is_valid, _ = validate_coordinates(latitude, longitude)
                if not is_valid:
                    results_summary["failed"] += 1
                    continue

                # Batch check and process assignments
                changes = _process_user_geofence_batch(
                    db=db,
                    user_id=user_id,
                    latitude=latitude,
                    longitude=longitude,
                    locations=locations
                )
                results_summary["total_changes"] += changes
                results_summary["success"] += 1

            except Exception as e:
                logger.error(f"Batch geofence failed for user {_scrub_user_id(user_id)}: {type(e).__name__}")
                results_summary["failed"] += 1

        results_summary["processed"] = len(user_locations)

        db.commit()

        return results_summary

    except Exception as e:
        logger.error(f"Batch geofence check failed: {e}")
        db.rollback()
        raise self.retry(exc=e)
    finally:
        db.close()


def _get_active_locations(db: Session) -> List[Location]:
    """Get all active locations with valid coordinates."""
    return db.query(Location).filter(
        Location.is_active == True,
        Location.latitude.isnot(None),
        Location.longitude.isnot(None)
    ).all()


def _process_user_geofence_batch(
    db: Session,
    user_id: int,
    latitude: float,
    longitude: float,
    locations: List[Location]
) -> int:
    """
    Process geofence check for a single user.

    Returns the number of changes made.
    """
    total_changes = 0
    results = check_geofences_batch(latitude, longitude, locations)

    for result in results:
        if result.is_inside:
            if _assign_user_to_location(
                db=db,
                user_id=user_id,
                location_id=result.location_id,
                assignment_type=UserLocationAssignmentType.GEOFENCE,
                detected_latitude=latitude,
                detected_longitude=longitude,
                distance_miles=result.distance_miles,
                action="entered_geofence"
            ):
                total_changes += 1
        else:
            if _remove_user_from_location(
                db=db,
                user_id=user_id,
                location_id=result.location_id,
                reason="User exited geofence",
                action="exited_geofence"
            ):
                total_changes += 1

    return total_changes


# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def _assign_user_to_location(
    db: Session,
    user_id: int,
    location_id: int,
    assignment_type: UserLocationAssignmentType,
    detected_latitude: Optional[float] = None,
    detected_longitude: Optional[float] = None,
    distance_miles: Optional[float] = None,
    action: str = "assigned"
) -> bool:
    """
    Assign user to location if not already assigned.

    Returns True if assignment was created/updated.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.exc import IntegrityError
    
    # Check for existing active assignment
    existing = db.query(UserLocation).filter(
        UserLocation.user_id == user_id,
        UserLocation.location_id == location_id,
        UserLocation.status == UserLocationStatus.ACTIVE
    ).first()

    if existing:
        # Already assigned - update location data if geofence
        if assignment_type == UserLocationAssignmentType.GEOFENCE:
            existing.detected_latitude = detected_latitude
            existing.detected_longitude = detected_longitude
            existing.distance_from_center_miles = distance_miles
            existing.updated_at = datetime.now(timezone.utc)
            return False  # No change needed
        return False

    # Try to create new assignment with PostgreSQL ON CONFLICT
    try:
        # Use PostgreSQL's INSERT ... ON CONFLICT DO NOTHING
        stmt = pg_insert(UserLocation.__table__).values(
            user_id=user_id,
            location_id=location_id,
            assignment_type=assignment_type,
            status=UserLocationStatus.ACTIVE,
            detected_latitude=detected_latitude,
            detected_longitude=detected_longitude,
            distance_from_center_miles=distance_miles
        ).on_conflict_do_nothing(
            index_elements=['user_id', 'location_id', 'status']
        )
        
        result = db.execute(stmt)
        
        # If row was inserted, get the ID and create history
        if result.rowcount > 0:
            # Get the inserted row's ID
            new_assignment = db.query(UserLocation).filter(
                UserLocation.user_id == user_id,
                UserLocation.location_id == location_id,
                UserLocation.status == UserLocationStatus.ACTIVE
            ).first()
            
            if new_assignment:
                # Record history
                history = UserLocationHistory(
                    user_id=user_id,
                    location_id=location_id,
                    user_location_id=new_assignment.id,
                    action=action,
                    assignment_type=assignment_type,
                    new_status=UserLocationStatus.ACTIVE,
                    detected_latitude=detected_latitude,
                    detected_longitude=detected_longitude,
                    distance_from_center_miles=distance_miles
                )
                db.add(history)
            
            return True
        else:
            # Conflict occurred - another transaction created the assignment
            return False
            
    except IntegrityError:
        # Fallback: constraint violation means already assigned
        db.rollback()
        return False


def _remove_user_from_location(
    db: Session,
    user_id: int,
    location_id: int,
    reason: Optional[str] = None,
    detected_latitude: Optional[float] = None,
    detected_longitude: Optional[float] = None,
    distance_miles: Optional[float] = None,
    action: str = "removed"
) -> bool:
    """
    Remove user from location (set status to inactive).
    
    Returns True if status was changed.
    """
    existing = db.query(UserLocation).filter(
        UserLocation.user_id == user_id,
        UserLocation.location_id == location_id,
        UserLocation.status == UserLocationStatus.ACTIVE
    ).first()
    
    if not existing:
        return False  # Not assigned
    
    # Don't remove manual assignments via geofence exit
    if existing.assignment_type == UserLocationAssignmentType.MANUAL:
        # Just update location data
        existing.detected_latitude = detected_latitude
        existing.detected_longitude = detected_longitude
        existing.distance_from_center_miles = distance_miles
        return False
    
    # Update status
    previous_status = existing.status
    existing.status = UserLocationStatus.INACTIVE
    existing.updated_at = datetime.now(timezone.utc)
    db.flush()
    
    # Record history
    history = UserLocationHistory(
        user_id=user_id,
        location_id=location_id,
        user_location_id=existing.id,
        action=action,
        assignment_type=existing.assignment_type,
        previous_status=previous_status,
        new_status=UserLocationStatus.INACTIVE,
        reason=reason,
        detected_latitude=detected_latitude,
        detected_longitude=detected_longitude,
        distance_from_center_miles=distance_miles
    )
    db.add(history)
    
    return True


def _update_primary_location(
    db: Session,
    user_id: int,
    geofence_results: List[Any]
) -> None:
    """
    Update user's primary location_id based on geofence results.

    Sets to the closest location if inside any, or None if outside all.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return

    # Find closest location user is inside
    inside_locations = [r for r in geofence_results if r.is_inside]

    if inside_locations:
        # Sort by distance, pick closest
        closest = min(inside_locations, key=lambda r: r.distance_miles)
        user.location_id = closest.location_id
    else:
        # Not inside any geofence - clear primary location
        user.location_id = None


# ─── PERIODIC GEOFENCE HELPERS ────────────────────────────────────────────────

def _get_users_with_location(db: Session) -> List[Dict[str, Any]]:
    """
    Get all active users with known coordinates.

    Returns a list of dicts with user_id, latitude, longitude, and location_id.
    """
    users_with_location = db.query(
        User.id,
        User.latitude,
        User.longitude,
        User.location_id
    ).filter(
        User.is_active == True,
        User.latitude.isnot(None),
        User.longitude.isnot(None)
    ).all()

    if not users_with_location:
        logger.info("No users with known coordinates for geofence check")
        return []

    return [
        {"user_id": u.id, "latitude": u.latitude, "longitude": u.longitude, "location_id": u.location_id}
        for u in users_with_location
    ]


def _get_active_geofence_locations(db: Session) -> List[Location]:
    """Get all active locations with valid coordinates for geofence checking."""
    return db.query(Location).filter(
        Location.is_active == True,
        Location.latitude.isnot(None),
        Location.longitude.isnot(None)
    ).all()


def _process_single_user_geofence(
    db: Session,
    user_loc: Dict[str, Any],
    locations: List[Location]
) -> int:
    """
    Process geofence check for a single user.

    Args:
        db: Database session
        user_loc: Dict with user_id, latitude, longitude
        locations: List of active locations to check against

    Returns:
        Number of assignment changes made
    """
    uid = user_loc["user_id"]
    lat = user_loc["latitude"]
    lng = user_loc["longitude"]

    # Validate coordinates
    is_valid, error = validate_coordinates(lat, lng)
    if not is_valid:
        logger.debug(f"Invalid coordinates for user {_scrub_user_id(uid)}: {error}")
        return 0

    # Batch geofence check
    results = check_geofences_batch(lat, lng, locations)

    total_changes = 0

    # Process each geofence result
    for result in results:
        if result.is_inside:
            if _assign_user_to_location(
                db=db,
                user_id=uid,
                location_id=result.location_id,
                assignment_type=UserLocationAssignmentType.GEOFENCE,
                detected_latitude=lat,
                detected_longitude=lng,
                distance_miles=result.distance_miles,
                action="entered_geofence"
            ):
                total_changes += 1
        else:
            if _remove_user_from_location(
                db=db,
                user_id=uid,
                location_id=result.location_id,
                reason="User exited geofence",
                action="exited_geofence"
            ):
                total_changes += 1

    # Update user's primary location
    _update_primary_location(db, uid, results)

    return total_changes


# ─── REDIS SYNC TASKS ─────────────────────────────────────────────────────────

@celery_app.task(bind=True, max_retries=3, default_retry_delay=5)
def _sync_user_to_redis(self, user_id: int, latitude: float, longitude: float) -> bool:
    """
    Sync user location to Redis for fast lookups.

    Stores user's current location with TTL for automatic cleanup.
    
    Security: Redis connections use TLS with full certificate verification
    when using rediss:// scheme (ssl_cert_reqs=CERT_REQUIRED).
    """
    try:
        import redis
        import ssl
        from app.config import settings

        # Build SSL options for TLS connections
        ssl_opts = {}
        if settings.REDIS_URL.startswith("rediss://"):
            ssl_opts = {
                "ssl_cert_reqs": ssl.CERT_REQUIRED,
                "ssl_check_hostname": True,
            }

        # Use synchronous Redis client for Celery task
        r = redis.from_url(settings.REDIS_URL, decode_responses=True, **ssl_opts)

        # Store user location with 24 hour TTL
        key = f"user:location:{user_id}"
        r.setex(
            key,
            86400,  # 24 hours
            f"{latitude},{longitude}"
        )

        return True
    except Exception as e:
        logger.error(f"Redis user sync failed: {e}")
        return False


@celery_app.task
def sync_all_locations_to_redis() -> Dict[str, Any]:
    """
    Sync all active locations to Redis GEO index.

    Run this periodically or after bulk location changes.
    
    Security: Redis connections use TLS with full certificate verification
    when using rediss:// scheme (ssl_cert_reqs=CERT_REQUIRED).
    """
    db = SessionLocal()
    try:
        import redis
        import ssl
        from app.config import settings

        # Build SSL options for TLS connections
        ssl_opts = {}
        if settings.REDIS_URL.startswith("rediss://"):
            ssl_opts = {
                "ssl_cert_reqs": ssl.CERT_REQUIRED,
                "ssl_check_hostname": True,
            }

        # Use synchronous Redis client for Celery task
        r = redis.from_url(settings.REDIS_URL, decode_responses=True, **ssl_opts)
        
        locations = db.query(Location).filter(
            Location.is_active == True,
            Location.latitude.isnot(None),
            Location.longitude.isnot(None)
        ).all()
        
        GEO_INDEX_KEY = "geo:locations:index"
        synced = 0
        failed = 0
        
        for loc in locations:
            try:
                # Add location to GEO index
                r.geoadd(
                    GEO_INDEX_KEY,
                    (loc.longitude, loc.latitude, str(loc.id)),
                    xx=True  # Only update if exists
                )
                synced += 1
            except Exception:
                failed += 1
        
        return {
            "synced": synced,
            "failed": failed,
            "total": len(locations)
        }
        
    except Exception as e:
        logger.error(f"Redis location sync failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


# ─── SCHEDULED TASKS ──────────────────────────────────────────────────────────

@celery_app.task
def cleanup_expired_assignments() -> Dict[str, Any]:
    """
    Clean up expired location assignments.
    
    Run daily to remove assignments past their expiration date.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        
        # Find expired assignments
        expired = db.query(UserLocation).filter(
            UserLocation.status == UserLocationStatus.ACTIVE,
            UserLocation.expires_at.isnot(None),
            UserLocation.expires_at < now
        ).all()
        
        count = 0
        for assignment in expired:
            assignment.status = UserLocationStatus.INACTIVE
            assignment.updated_at = now
            
            # Record history
            history = UserLocationHistory(
                user_id=assignment.user_id,
                location_id=assignment.location_id,
                user_location_id=assignment.id,
                action="expired",
                assignment_type=assignment.assignment_type,
                previous_status=UserLocationStatus.ACTIVE,
                new_status=UserLocationStatus.INACTIVE,
                reason="Assignment expired"
            )
            db.add(history)
            count += 1
        
        db.commit()
        
        logger.info(f"Cleaned up {count} expired location assignments")
        
        return {
            "cleaned": count,
            "timestamp": now.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Expired assignment cleanup failed: {e}")
        db.rollback()
        return {"error": str(e)}
    finally:
        db.close()


@celery_app.task
def periodic_geofence_check() -> Dict[str, Any]:
    """
    Periodic task (no arguments) for Celery beat.

    Queries all users with known lat/lon and runs geofence checks for each.
    This enables fully automatic geofence-based location assignment.
    """
    db = SessionLocal()
    try:
        # Get users with locations
        user_locations = _get_users_with_location(db)
        if not user_locations:
            return {"processed": 0, "message": "No users with coordinates"}

        logger.info(f"Running periodic geofence check for {len(user_locations)} users")

        # Get active geofence locations
        locations = _get_active_geofence_locations(db)
        if not locations:
            return {"processed": len(user_locations), "message": "No active locations"}

        # Process each user's geofence
        total_changes = _process_user_batch(db, user_locations, locations)

        db.commit()
        logger.info(
            f"Periodic geofence check complete: {len(user_locations)} users processed, "
            f"{total_changes} assignment changes"
        )

        return {
            "processed": len(user_locations),
            "total_changes": total_changes
        }
    except Exception as e:
        logger.error(f"Periodic geofence check failed: {e}")
        db.rollback()
        return {"error": str(e)}
    finally:
        db.close()


def _process_user_batch(
    db: Session,
    user_locations: List[Dict[str, Any]],
    locations: List[Location]
) -> int:
    """
    Process geofence checks for a batch of users.

    Args:
        db: Database session
        user_locations: List of user location dicts
        locations: List of active locations to check against

    Returns:
        Total number of assignment changes made
    """
    total_changes = 0

    for user_loc in user_locations:
        try:
            changes = _process_single_user_geofence(db, user_loc, locations)
            total_changes += changes
        except Exception as e:
            logger.error(
                f"Periodic geofence failed for user {_scrub_user_id(user_loc.get('user_id'))}: "
                f"{type(e).__name__}"
            )

    return total_changes


@celery_app.task
def refresh_redis_geo_index() -> Dict[str, Any]:
    """
    Periodic task to ensure Redis GEO index is up to date.
    
    Run every hour to catch any missed updates.
    """
    return sync_all_locations_to_redis()
