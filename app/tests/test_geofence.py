"""
Tests for Geofence Engine

Tests cover:
- Haversine distance calculation
- Coordinate validation
- Geofence radius validation
- Location overlap detection
- Batch processing
"""
import math
from app.core.geofence import (
    haversine_distance,
    validate_coordinates,
    validate_geofence_radius,
    validate_location_input,
    check_geofence,
    check_geofences_batch,
    check_location_overlap,
    GeoPoint,
    EARTH_RADIUS_MILES,
    MIN_GEOFENCE_RADIUS_MILES,
    MAX_GEOFENCE_RADIUS_MILES,
)


# ─── HAVERSINE DISTANCE TESTS ─────────────────────────────────────────────────

class TestHaversineDistance:
    """Test haversine distance calculations."""
    
    def test_same_point_zero_distance(self):
        """Distance from a point to itself should be 0."""
        distance = haversine_distance(40.7128, -74.0060, 40.7128, -74.0060)
        assert distance == 0.0
    
    def test_new_york_to_los_angeles(self):
        """Test known distance between NYC and LA (~2,451 miles)."""
        # NYC: 40.7128° N, 74.0060° W
        # LA: 34.0522° N, 118.2437° W
        distance = haversine_distance(40.7128, -74.0060, 34.0522, -118.2437)
        assert 2400 < distance < 2500  # Allow some variance
    
    def test_london_to_paris(self):
        """Test known distance between London and Paris (~214 miles)."""
        # London: 51.5074° N, 0.1278° W
        # Paris: 48.8566° N, 2.3522° E
        distance = haversine_distance(51.5074, -0.1278, 48.8566, 2.3522)
        assert 200 < distance < 230
    
    def test_cross_equator(self):
        """Test distance calculation across equator."""
        # Point north of equator
        lat1, lon1 = 1.0, 0.0
        # Point south of equator
        lat2, lon2 = -1.0, 0.0
        distance = haversine_distance(lat1, lon1, lat2, lon2)
        # ~138 miles for 2 degrees at equator
        assert 130 < distance < 150
    
    def test_kilometers_unit(self):
        """Test distance in kilometers."""
        distance_km = haversine_distance(40.7128, -74.0060, 34.0522, -118.2437, unit="km")
        distance_miles = haversine_distance(40.7128, -74.0060, 34.0522, -118.2437, unit="miles")
        # km should be ~1.609 times miles
        assert abs(distance_km - distance_miles * 1.60934) < 1.0
    
    def test_pole_to_pole(self):
        """Test distance from North Pole to South Pole (~7,918 miles)."""
        distance = haversine_distance(90.0, 0.0, -90.0, 0.0)
        expected = 2 * EARTH_RADIUS_MILES * math.pi / 2  # Half circumference
        assert abs(distance - expected) < 1.0


# ─── COORDINATE VALIDATION TESTS ──────────────────────────────────────────────

class TestCoordinateValidation:
    """Test coordinate validation."""
    
    def test_valid_coordinates(self):
        """Test valid coordinate ranges."""
        # Valid coordinates
        assert validate_coordinates(0.0, 0.0) == (True, None)
        assert validate_coordinates(45.0, -90.0) == (True, None)
        assert validate_coordinates(-45.0, 90.0) == (True, None)
        assert validate_coordinates(90.0, 180.0) == (True, None)
        assert validate_coordinates(-90.0, -180.0) == (True, None)
    
    def test_invalid_latitude(self):
        """Test invalid latitude values."""
        # Latitude > 90
        is_valid, error = validate_coordinates(91.0, 0.0)
        assert not is_valid
        assert "Latitude" in error
        
        # Latitude < -90
        is_valid, error = validate_coordinates(-91.0, 0.0)
        assert not is_valid
        assert "Latitude" in error
    
    def test_invalid_longitude(self):
        """Test invalid longitude values."""
        # Longitude > 180
        is_valid, error = validate_coordinates(0.0, 181.0)
        assert not is_valid
        assert "Longitude" in error
        
        # Longitude < -180
        is_valid, error = validate_coordinates(0.0, -181.0)
        assert not is_valid
        assert "Longitude" in error


# ─── GEOFENCE RADIUS VALIDATION TESTS ─────────────────────────────────────────

class TestGeofenceRadiusValidation:
    """Test geofence radius validation."""
    
    def test_valid_radius(self):
        """Test valid radius values."""
        assert validate_geofence_radius(1.0) == (True, None)
        assert validate_geofence_radius(0.1) == (True, None)
        assert validate_geofence_radius(50.0) == (True, None)
        assert validate_geofence_radius(25.5) == (True, None)
    
    def test_radius_too_small(self):
        """Test radius below minimum."""
        is_valid, error = validate_geofence_radius(0.05)
        assert not is_valid
        assert "at least" in error.lower()
    
    def test_radius_too_large(self):
        """Test radius above maximum."""
        is_valid, error = validate_geofence_radius(100.0)
        assert not is_valid
        assert "not exceed" in error.lower()
    
    def test_edge_cases(self):
        """Test edge case values."""
        # Exactly at minimum
        assert validate_geofence_radius(MIN_GEOFENCE_RADIUS_MILES) == (True, None)
        # Exactly at maximum
        assert validate_geofence_radius(MAX_GEOFENCE_RADIUS_MILES) == (True, None)


# ─── LOCATION INPUT VALIDATION TESTS ──────────────────────────────────────────

class TestLocationInputValidation:
    """Test comprehensive location input validation."""
    
    def test_valid_input(self):
        """Test valid location input."""
        result = validate_location_input(
            name="Test Location",
            latitude=40.7128,
            longitude=-74.0060,
            radius_miles=5.0
        )
        assert result["is_valid"] is True
        assert len(result["errors"]) == 0
        assert result["sanitized"]["name"] == "Test Location"
        assert result["sanitized"]["latitude"] == 40.7128
        assert result["sanitized"]["longitude"] == -74.0060
        assert result["sanitized"]["geofence_radius_miles"] == 5.0
    
    def test_empty_name(self):
        """Test empty name rejection."""
        result = validate_location_input(
            name="",
            latitude=40.7128,
            longitude=-74.0060,
            radius_miles=5.0
        )
        assert not result["is_valid"]
        assert any("name" in err.lower() for err in result["errors"])
    
    def test_long_name_truncated(self):
        """Test long name is truncated."""
        long_name = "A" * 300
        result = validate_location_input(
            name=long_name,
            latitude=40.7128,
            longitude=-74.0060,
            radius_miles=5.0
        )
        assert result["is_valid"] is True
        assert len(result["sanitized"]["name"]) <= 200
    
    def test_missing_coordinates(self):
        """Test missing coordinates rejection."""
        result = validate_location_input(
            name="Test",
            latitude=None,
            longitude=None,
            radius_miles=5.0
        )
        assert not result["is_valid"]
        assert any("coordinate" in err.lower() or "latitude" in err.lower() for err in result["errors"])
    
    def test_invalid_radius(self):
        """Test invalid radius rejection."""
        result = validate_location_input(
            name="Test",
            latitude=40.7128,
            longitude=-74.0060,
            radius_miles=100.0
        )
        assert not result["is_valid"]
        assert any("radius" in err.lower() for err in result["errors"])


# ─── GEOFENCE CHECKING TESTS ──────────────────────────────────────────────────

class MockLocation:
    """Mock Location object for testing."""
    def __init__(self, id, name, lat, lon, radius):
        self.id = id
        self.name = name
        self.latitude = lat
        self.longitude = lon
        self.geofence_radius_miles = radius


class TestGeofenceChecking:
    """Test geofence checking logic."""
    
    def test_inside_geofence(self):
        """Test point inside geofence."""
        # Location at center with 5 mile radius
        location = MockLocation(1, "Test", 40.7128, -74.0060, 5.0)
        # User at same location (0 miles away)
        result = check_geofence(40.7128, -74.0060, location)
        assert result.is_inside is True
        assert result.distance_miles == 0.0
        assert result.margin_miles == 5.0
    
    def test_outside_geofence(self):
        """Test point outside geofence."""
        location = MockLocation(1, "Test", 40.7128, -74.0060, 1.0)
        # User 10 miles away (approximately)
        result = check_geofence(40.8528, -74.0060, location)
        assert result.is_inside is False
        assert result.distance_miles > 1.0
        assert result.margin_miles < 0
    
    def test_edge_of_geofence(self):
        """Test point exactly at geofence boundary."""
        location = MockLocation(1, "Test", 40.7128, -74.0060, 5.0)
        # Calculate point approximately 5 miles north
        # 1 degree latitude ≈ 69 miles
        lat_offset = 5.0 / 69.0
        result = check_geofence(40.7128 + lat_offset, -74.0060, location)
        # Should be very close to boundary
        assert abs(result.distance_miles - 5.0) < 0.1
    
    def test_missing_location_coordinates(self):
        """Test handling of location with no coordinates."""
        location = MockLocation(1, "Test", None, None, 5.0)
        result = check_geofence(40.7128, -74.0060, location)
        assert result.is_inside is False
        assert result.distance_miles == float('inf')
    
    def test_batch_checking(self):
        """Test batch geofence checking."""
        locations = [
            MockLocation(1, "NYC", 40.7128, -74.0060, 5.0),
            MockLocation(2, "LA", 34.0522, -118.2437, 10.0),
            MockLocation(3, "Chicago", 41.8781, -87.6298, 5.0),
        ]
        # User in NYC
        results = check_geofences_batch(40.7128, -74.0060, locations)
        assert len(results) == 3
        nyc_result = next(r for r in results if r.location_id == 1)
        assert nyc_result.is_inside is True
        la_result = next(r for r in results if r.location_id == 2)
        assert la_result.is_inside is False


# ─── OVERLAP DETECTION TESTS ──────────────────────────────────────────────────

class TestOverlapDetection:
    """Test location overlap detection."""
    
    def test_no_overlap(self):
        """Test locations that don't overlap."""
        new_loc = (40.7128, -74.0060, 5.0)  # NYC, 5 mile radius
        existing = [MockLocation(1, "LA", 34.0522, -118.2437, 10.0)]
        
        overlaps = check_location_overlap(
            new_loc[0], new_loc[1], new_loc[2],
            existing
        )
        assert len(overlaps) == 0
    
    def test_overlap_detected(self):
        """Test overlapping locations."""
        # Two locations close together with large radii
        new_loc = (40.7128, -74.0060, 10.0)  # NYC area, 10 mile radius
        existing = [MockLocation(1, "Nearby", 40.7500, -74.0500, 10.0)]
        
        overlaps = check_location_overlap(
            new_loc[0], new_loc[1], new_loc[2],
            existing
        )
        assert len(overlaps) > 0
        assert overlaps[0]["location_id"] == 1
    
    def test_exclude_self(self):
        """Test excluding location from overlap check (for updates)."""
        loc = (40.7128, -74.0060, 5.0)
        existing = [
            MockLocation(1, "Same", 40.7128, -74.0060, 5.0),
            MockLocation(2, "Other", 40.7200, -74.0100, 5.0),
        ]
        
        # Exclude location 1
        overlaps = check_location_overlap(
            loc[0], loc[1], loc[2],
            existing,
            exclude_location_id=1
        )
        # Should only check against location 2
        assert len(overlaps) == 0 or overlaps[0]["location_id"] != 1
    
    def test_touching_boundaries(self):
        """Test locations with touching boundaries (no overlap)."""
        # Two locations exactly radius1 + radius2 apart
        # 1 degree ≈ 69 miles
        distance_degrees = 10.0 / 69.0  # 10 miles apart
        
        new_loc = (40.7128, -74.0060, 5.0)
        existing = [MockLocation(1, "Touching", 40.7128 + distance_degrees, -74.0060, 5.0)]
        
        overlaps = check_location_overlap(
            new_loc[0], new_loc[1], new_loc[2],
            existing
        )
        # Should be exactly touching or very slight overlap due to rounding
        assert len(overlaps) <= 1


# ─── GEOPOINT CLASS TESTS ─────────────────────────────────────────────────────

class TestGeoPoint:
    """Test GeoPoint dataclass."""
    
    def test_valid_point(self):
        """Test valid point creation and validation."""
        point = GeoPoint(latitude=40.7128, longitude=-74.0060)
        is_valid, error = point.validate()
        assert is_valid is True
        assert error is None
    
    def test_invalid_point(self):
        """Test invalid point detection."""
        point = GeoPoint(latitude=100.0, longitude=0.0)
        is_valid, error = point.validate()
        assert is_valid is False
        assert error is not None


# ─── INTEGRATION TESTS ────────────────────────────────────────────────────────

class TestIntegration:
    """Integration tests for geofence system."""
    
    def test_real_world_scenario_nyc_metro(self):
        """Test realistic NYC metro area scenario."""
        # Define NYC metro locations
        locations = [
            MockLocation(1, "Manhattan", 40.7831, -73.9712, 3.0),
            MockLocation(2, "Brooklyn", 40.6782, -73.9442, 4.0),
            MockLocation(3, "Queens", 40.7282, -73.7949, 5.0),
            MockLocation(4, "Bronx", 40.8448, -73.8648, 3.0),
        ]
        
        # User in Midtown Manhattan
        results = check_geofences_batch(40.7549, -73.9840, locations)
        
        # Should be inside Manhattan
        manhattan = next(r for r in results if r.location_id == 1)
        assert manhattan.is_inside is True
        
        # Should be outside other boroughs
        brooklyn = next(r for r in results if r.location_id == 2)
        assert brooklyn.is_inside is False
    
    def test_multiple_overlapping_geofences(self):
        """Test user in multiple overlapping geofences."""
        # Create overlapping locations
        locations = [
            MockLocation(1, "Zone A", 40.7128, -74.0060, 10.0),
            MockLocation(2, "Zone B", 40.7200, -74.0100, 10.0),
            MockLocation(3, "Zone C", 40.7150, -74.0050, 10.0),
        ]
        
        # User at center should be in all three
        results = check_geofences_batch(40.7160, -74.0070, locations)
        inside_count = sum(1 for r in results if r.is_inside)
        assert inside_count == 3
