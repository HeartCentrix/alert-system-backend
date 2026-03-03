"""
Geofence Engine with Haversine Distance Calculation

Production-ready geofencing system with:
- Haversine formula for accurate distance calculation
- Support for miles and kilometers
- Optimized for batch processing
- Redis GEO integration for fast proximity checks
"""
import math
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import redis.asyncio as redis
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models import Location, User, UserLocation, UserLocationAssignmentType, UserLocationStatus, UserLocationHistory
from app.config import settings


# ─── CONSTANTS ────────────────────────────────────────────────────────────────

EARTH_RADIUS_MILES = 3958.8
EARTH_RADIUS_KM = 6371.0
MIN_COORDINATE = -90.0
MAX_COORDINATE = 90.0
MIN_LONGITUDE = -180.0
MAX_LONGITUDE = 180.0

# Validation thresholds
MAX_GEOFENCE_RADIUS_MILES = 50.0  # Maximum allowed radius
MIN_GEOFENCE_RADIUS_MILES = 0.1  # Minimum allowed radius


# ─── DATA CLASSES ─────────────────────────────────────────────────────────────

@dataclass
class GeoPoint:
    """Represents a geographic point."""
    latitude: float
    longitude: float
    
    def validate(self) -> Tuple[bool, Optional[str]]:
        """Validate coordinates are within valid ranges."""
        if not (MIN_COORDINATE <= self.latitude <= MAX_COORDINATE):
            return False, f"Latitude must be between {MIN_COORDINATE} and {MAX_COORDINATE}"
        if not (MIN_LONGITUDE <= self.longitude <= MAX_LONGITUDE):
            return False, f"Longitude must be between {MIN_LONGITUDE} and {MAX_LONGITUDE}"
        return True, None


@dataclass
class GeofenceResult:
    """Result of a geofence check."""
    location_id: int
    location_name: str
    is_inside: bool
    distance_miles: float
    distance_km: float
    radius_miles: float
    margin_miles: float  # How far inside/outside (positive = inside, negative = outside)


@dataclass
class GeofenceAssignment:
    """Result of geofence assignment check."""
    user_id: int
    location_id: int
    action: str  # "enter", "exit", "stay_inside", "stay_outside"
    distance_miles: float
    assignment_type: UserLocationAssignmentType
    previous_status: Optional[UserLocationStatus] = None
    new_status: Optional[UserLocationStatus] = None


# ─── HAVERSINE DISTANCE CALCULATION ───────────────────────────────────────────

def haversine_distance(
    lat1: float, lon1: float,
    lat2: float, lon2: float,
    unit: str = "miles"
) -> float:
    """
    Calculate the great-circle distance between two points using the Haversine formula.
    
    Args:
        lat1, lon1: Coordinates of point 1
        lat2, lon2: Coordinates of point 2
        unit: "miles" or "km"
    
    Returns:
        Distance between the two points
    
    Formula:
        a = sin²(Δlat/2) + cos(lat1) × cos(lat2) × sin²(Δlon/2)
        c = 2 × atan2(√a, √(1−a))
        d = R × c
    
    Where R is Earth's radius
    """
    # Convert to radians
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    # Haversine formula
    a = (
        math.sin(delta_lat / 2) ** 2 +
        math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    # Calculate distance
    radius = EARTH_RADIUS_MILES if unit == "miles" else EARTH_RADIUS_KM
    distance = radius * c
    
    return distance


def calculate_distance_batch(
    user_coords: GeoPoint,
    locations: List[Tuple[int, str, float, float, float]]  # (id, name, lat, lon, radius)
) -> List[GeofenceResult]:
    """
    Calculate distances from a user point to multiple locations.
    
    Optimized for batch processing with minimal object creation.
    
    Args:
        user_coords: User's current location
        locations: List of (location_id, name, latitude, longitude, radius_miles)
    
    Returns:
        List of GeofenceResult objects
    """
    results = []
    user_lat_rad = math.radians(user_coords.latitude)
    user_lon_rad = math.radians(user_coords.longitude)
    
    for loc_id, loc_name, loc_lat, loc_lon, radius in locations:
        # Convert location coords to radians
        loc_lat_rad = math.radians(loc_lat)
        loc_lon_rad = math.radians(loc_lon)
        
        # Calculate deltas
        delta_lat = math.radians(loc_lat - user_coords.latitude)
        delta_lon = math.radians(loc_lon - user_coords.longitude)
        
        # Haversine formula (optimized - no function call overhead)
        a = (
            math.sin(delta_lat / 2) ** 2 +
            math.cos(user_lat_rad) * math.cos(loc_lat_rad) * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance_miles = EARTH_RADIUS_MILES * c
        distance_km = EARTH_RADIUS_KM * c
        
        is_inside = distance_miles <= radius
        margin = radius - distance_miles  # Positive = inside, negative = outside
        
        results.append(GeofenceResult(
            location_id=loc_id,
            location_name=loc_name,
            is_inside=is_inside,
            distance_miles=round(distance_miles, 4),
            distance_km=round(distance_km, 4),
            radius_miles=radius,
            margin_miles=round(margin, 4)
        ))
    
    return results


# ─── VALIDATION ───────────────────────────────────────────────────────────────

def validate_coordinates(latitude: float, longitude: float) -> Tuple[bool, Optional[str]]:
    """Validate geographic coordinates."""
    point = GeoPoint(latitude=latitude, longitude=longitude)
    return point.validate()


def validate_geofence_radius(radius_miles: float) -> Tuple[bool, Optional[str]]:
    """
    Validate geofence radius is within acceptable limits.
    
    Prevents:
    - Too small radius (< 0.1 miles) - impractical
    - Too large radius (> 50 miles) - performance and accuracy concerns
    """
    if radius_miles < MIN_GEOFENCE_RADIUS_MILES:
        return False, f"Geofence radius must be at least {MIN_GEOFENCE_RADIUS_MILES} miles"
    if radius_miles > MAX_GEOFENCE_RADIUS_MILES:
        return False, f"Geofence radius must not exceed {MAX_GEOFENCE_RADIUS_MILES} miles"
    return True, None


def validate_location_input(
    name: str,
    latitude: Optional[float],
    longitude: Optional[float],
    radius_miles: float
) -> Dict[str, Any]:
    """
    Validate and sanitize location creation/update input.

    Returns dict with:
    - is_valid: bool
    - errors: list of error messages
    - sanitized: dict of sanitized values
    """
    errors = []
    sanitized = {}

    # Validate name
    if not name or not name.strip():
        errors.append("Location name is required")
    else:
        # Sanitize and truncate name - allow alphanumeric, spaces, and common chars
        sanitized["name"] = name.strip()[:200]

    # Validate coordinates
    if latitude is None or longitude is None:
        errors.append("Both latitude and longitude are required")
    else:
        lat_valid, lat_error = validate_coordinates(latitude, longitude)
        if lat_valid:
            sanitized["latitude"] = round(latitude, 6)  # ~6 inch precision
            sanitized["longitude"] = round(longitude, 6)
        else:
            errors.append(lat_error)

    # Validate radius
    radius_valid, radius_error = validate_geofence_radius(radius_miles)
    if radius_valid:
        sanitized["geofence_radius_miles"] = round(radius_miles, 2)
    else:
        errors.append(radius_error)

    return {
        "is_valid": len(errors) == 0,
        "errors": errors,
        "sanitized": sanitized
    }


# ─── REDIS GEO INTEGRATION ────────────────────────────────────────────────────

class RedisGeoService:
    """
    Redis GEO service for fast proximity checks.
    
    Uses Redis GEO commands for O(log N) proximity searches.
    Ideal for checking thousands of users against multiple locations.
    
    Redis GEO commands used:
    - GEOADD: Add location coordinates
    - GEORADIUS: Find locations within radius
    - GEODIST: Get distance between points
    - GEOPOS: Get coordinates
    """
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._redis: Optional[redis.Redis] = None
        self.GEO_INDEX_KEY = "geo:locations:index"
    
    async def connect(self) -> None:
        """Initialize Redis connection."""
        if not self._redis:
            self._redis = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None
    
    async def add_location(self, location_id: int, latitude: float, longitude: float) -> bool:
        """
        Add location to Redis GEO index.
        
        Args:
            location_id: Database ID of the location
            latitude: Location latitude
            longitude: Location longitude
        
        Returns:
            True if successful
        """
        if not self._redis:
            await self.connect()
        
        try:
            # Use GEOADD with NX (only add if not exists) to prevent overwriting
            result = await self._redis.geoadd(
                self.GEO_INDEX_KEY,
                (longitude, latitude, str(location_id)),
                nx=True  # Only add if member doesn't exist
            )
            # If NX prevented update, do a regular update
            if result == 0:
                await self._redis.geoadd(
                    self.GEO_INDEX_KEY,
                    (longitude, latitude, str(location_id)),
                    xx=True  # Only update if exists
                )
            return True
        except Exception as e:
            # Log error but don't fail - Redis is cache/index, not source of truth
            print(f"Redis GEO add failed: {e}")
            return False
    
    async def remove_location(self, location_id: int) -> bool:
        """Remove location from Redis GEO index."""
        if not self._redis:
            await self.connect()
        
        try:
            await self._redis.zrem(self.GEO_INDEX_KEY, str(location_id))
            return True
        except Exception as e:
            print(f"Redis GEO remove failed: {e}")
            return False
    
    async def find_locations_in_radius(
        self,
        latitude: float,
        longitude: float,
        radius_miles: float
    ) -> List[Dict[str, Any]]:
        """
        Find all locations within radius of a point.
        
        Uses Redis GEORADIUS for O(log N) performance.
        
        Args:
            latitude: Center point latitude
            longitude: Center point longitude
            radius_miles: Search radius in miles
        
        Returns:
            List of {location_id, distance} dicts
        """
        if not self._redis:
            await self.connect()
        
        try:
            # Redis GEORADIUS returns [member, distance, coords]
            results = await self._redis.georadius(
                self.GEO_INDEX_KEY,
                longitude,
                latitude,
                radius=radius_miles,
                unit="mi",
                withdist=True,
                withcoord=True
            )
            
            return [
                {
                    "location_id": int(member),
                    "distance_miles": round(dist, 4),
                    "longitude": coords[0],
                    "latitude": coords[1]
                }
                for member, dist, coords in results
            ]
        except Exception as e:
            print(f"Redis GEO radius search failed: {e}")
            return []
    
    async def get_distance(
        self,
        latitude: float,
        longitude: float,
        location_id: int
    ) -> Optional[float]:
        """
        Get distance from point to a specific location.
        
        Args:
            latitude: Point latitude
            longitude: Point longitude
            location_id: Location database ID
        
        Returns:
            Distance in miles or None if location not found
        """
        if not self._redis:
            await self.connect()
        
        try:
            distance = await self._redis.geodist(
                self.GEO_INDEX_KEY,
                (longitude, latitude),
                str(location_id),
                unit="mi"
            )
            return float(distance) if distance else None
        except Exception as e:
            print(f"Redis GEO distance failed: {e}")
            return None
    
    async def get_all_locations(self) -> List[Dict[str, Any]]:
        """
        Get all indexed locations with their coordinates.
        
        Used for batch geofence checks.
        """
        if not self._redis:
            await self.connect()
        
        try:
            # Get all members with their scores and coordinates
            all_members = await self._redis.zrange(
                self.GEO_INDEX_KEY,
                0,
                -1,
                withscores=False
            )
            
            results = []
            for member in all_members:
                coords = await self._redis.geopos(
                    self.GEO_INDEX_KEY,
                    member
                )
                if coords and coords[0]:
                    results.append({
                        "location_id": int(member),
                        "longitude": coords[0][0],
                        "latitude": coords[0][1]
                    })
            
            return results
        except Exception as e:
            print(f"Redis GEO get all failed: {e}")
            return []
    
    async def clear_index(self) -> bool:
        """Clear the entire GEO index. Use with caution."""
        if not self._redis:
            await self.connect()
        
        try:
            await self._redis.delete(self.GEO_INDEX_KEY)
            return True
        except Exception as e:
            print(f"Redis GEO clear failed: {e}")
            return False


# Global Redis GEO service instance
_geo_service: Optional[RedisGeoService] = None


def get_geo_service() -> RedisGeoService:
    """Get or create the Redis GEO service instance."""
    global _geo_service
    if _geo_service is None:
        _geo_service = RedisGeoService(settings.REDIS_URL)
    return _geo_service


async def init_geo_service() -> None:
    """Initialize the Redis GEO service."""
    service = get_geo_service()
    await service.connect()


async def close_geo_service() -> None:
    """Close the Redis GEO service."""
    global _geo_service
    if _geo_service:
        await _geo_service.close()
        _geo_service = None


# ─── GEOFENCE CHECKING ────────────────────────────────────────────────────────

def check_geofence(
    user_latitude: float,
    user_longitude: float,
    location: Location
) -> GeofenceResult:
    """
    Check if a user is within a location's geofence.
    
    Args:
        user_latitude: User's latitude
        user_longitude: User's longitude
        location: Location object with coordinates and radius
    
    Returns:
        GeofenceResult with distance and inside/outside status
    """
    if not location.latitude or not location.longitude:
        return GeofenceResult(
            location_id=location.id,
            location_name=location.name,
            is_inside=False,
            distance_miles=float('inf'),
            distance_km=float('inf'),
            radius_miles=location.geofence_radius_miles or 0,
            margin_miles=float('-inf')
        )
    
    distance = haversine_distance(
        user_latitude, user_longitude,
        location.latitude, location.longitude,
        unit="miles"
    )
    
    radius = location.geofence_radius_miles or 0
    is_inside = distance <= radius
    
    return GeofenceResult(
        location_id=location.id,
        location_name=location.name,
        is_inside=is_inside,
        distance_miles=round(distance, 4),
        distance_km=round(distance * 1.60934, 4),
        radius_miles=radius,
        margin_miles=round(radius - distance, 4)
    )


def check_geofences_batch(
    user_latitude: float,
    user_longitude: float,
    locations: List[Location]
) -> List[GeofenceResult]:
    """
    Check user against multiple locations efficiently.
    
    Args:
        user_latitude: User's latitude
        user_longitude: User's longitude
        locations: List of Location objects
    
    Returns:
        List of GeofenceResult for each location
    """
    if not locations:
        return []
    
    # Prepare batch data
    location_data = [
        (loc.id, loc.name, loc.latitude, loc.longitude, loc.geofence_radius_miles or 0)
        for loc in locations
        if loc.latitude and loc.longitude
    ]
    
    user_point = GeoPoint(latitude=user_latitude, longitude=user_longitude)
    return calculate_distance_batch(user_point, location_data)


# ─── OVERLAP DETECTION ────────────────────────────────────────────────────────

def check_location_overlap(
    new_latitude: float,
    new_longitude: float,
    new_radius: float,
    existing_locations: List[Location],
    exclude_location_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Check if a new/updated location overlaps with existing locations.
    
    Overlap occurs when:
    distance(center1, center2) < radius1 + radius2
    
    Args:
        new_latitude: New location latitude
        new_longitude: New location longitude
        new_radius: New location radius in miles
        existing_locations: List of existing Location objects
        exclude_location_id: Location ID to exclude (for updates)
    
    Returns:
        List of overlap details
    """
    overlaps = []
    
    for loc in existing_locations:
        if exclude_location_id and loc.id == exclude_location_id:
            continue
        
        if not loc.latitude or not loc.longitude:
            continue
        
        distance = haversine_distance(
            new_latitude, new_longitude,
            loc.latitude, loc.longitude,
            unit="miles"
        )
        
        combined_radius = new_radius + (loc.geofence_radius_miles or 0)
        
        if distance < combined_radius:
            overlap_percentage = (combined_radius - distance) / combined_radius * 100
            overlaps.append({
                "location_id": loc.id,
                "location_name": loc.name,
                "distance_miles": round(distance, 2),
                "overlap_miles": round(combined_radius - distance, 2),
                "overlap_percentage": round(overlap_percentage, 1)
            })
    
    return overlaps
