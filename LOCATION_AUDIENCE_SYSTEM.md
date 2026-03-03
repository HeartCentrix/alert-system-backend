# Location Audience Management System with Geofencing

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOCATION AUDIENCE SYSTEM                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │   Frontend   │────▶│   FastAPI    │────▶│  PostgreSQL  │                │
│  │  (React +    │◀────│   Backend    │◀────│   Database   │                │
│  │   Leaflet)   │     │              │     │              │                │
│  └──────────────┘     └──────┬───────┘     └──────────────┘                │
│                              │                                               │
│                              ├──────────────▶  Redis GEO Index              │
│                              │                                               │
│                              ├──────────────▶  Celery Workers               │
│                              │                   └── Geofence Tasks         │
│                              │                                               │
│                              └──────────────▶  LocationIQ API               │
│                                                  (Autocomplete)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Features Implemented

### 1. Location Management
- Create/update/delete locations with geofence radius
- Coordinate validation and sanitization
- Overlap detection between locations
- Redis GEO index synchronization

### 2. Manual User Assignment
- Admin dashboard for assigning users to locations
- Remove users from locations
- Assignment type tracking (manual vs geofence)
- Expiration support for temporary assignments

### 3. Automatic Geofence Assignment
- Background Celery workers for geofence checking
- Haversine distance calculation
- Automatic entry/exit detection
- Primary location tracking

### 4. Audit & History
- Complete audit trail for membership changes
- IP address and user agent logging
- Action history per location
- Compliance reporting

### 5. Security
- RBAC validation (Admin/Manager roles)
- IDOR prevention
- Rate limiting (30 geofence updates/min, 100 assignments/min)
- Input validation and sanitization
- SQL injection prevention (SQLAlchemy ORM)

---

## Database Schema

### Tables

#### `user_locations`
Many-to-many relationship between users and locations.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| user_id | Integer | Foreign key to users |
| location_id | Integer | Foreign key to locations |
| assignment_type | Enum | MANUAL or GEOFENCE |
| status | Enum | ACTIVE or INACTIVE |
| detected_latitude | Float | GPS coordinates when assigned |
| detected_longitude | Float | GPS coordinates when assigned |
| distance_from_center_miles | Float | Distance from location center |
| assigned_by_id | Integer | Admin who manually assigned |
| notes | Text | Assignment notes |
| assigned_at | DateTime | Assignment timestamp |
| expires_at | DateTime | Optional expiration |
| updated_at | DateTime | Last update |

#### `user_location_history`
Audit trail for all membership changes.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| user_id | Integer | User involved |
| location_id | Integer | Location involved |
| user_location_id | Integer | Reference to current record |
| action | String | assigned, removed, entered_geofence, etc. |
| assignment_type | Enum | MANUAL or GEOFENCE |
| previous_status | Enum | Status before change |
| new_status | Enum | Status after change |
| triggered_by_user_id | Integer | Admin who triggered (if manual) |
| reason | Text | Reason for change |
| detected_latitude | Float | GPS coordinates |
| detected_longitude | Float | GPS coordinates |
| ip_address | String | IP address of requester |
| user_agent | String | User agent string |
| metadata | JSON | Additional context |
| created_at | DateTime | Event timestamp |

---

## API Endpoints

### Location Audience Management

#### Assign User to Location
```http
POST /api/v1/location-audience/assign
Authorization: Bearer <token>
Content-Type: application/json

{
  "user_id": 123,
  "location_id": 456,
  "notes": "Assigned by admin",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

**Requirements:** Admin role

#### Remove User from Location
```http
POST /api/v1/location-audience/remove?user_id=123&location_id=456
Authorization: Bearer <token>
Content-Type: application/json

{
  "reason": "User transferred"
}
```

**Requirements:** Admin role

#### Update User Geofence Location
```http
POST /api/v1/location-audience/geofence/update
Authorization: Bearer <token>
Content-Type: application/json

{
  "latitude": 40.7128,
  "longitude": -74.0060
}
```

**Rate Limit:** 30 requests/minute

#### Get Location Members
```http
GET /api/v1/location-audience/location/{location_id}/members?page=1&page_size=20&status=active
Authorization: Bearer <token>
```

**Requirements:** Manager role or higher

#### Get User Locations
```http
GET /api/v1/location-audience/user/{user_id}/locations?include_inactive=false
Authorization: Bearer <token>
```

**Security:** Users can only view their own locations (IDOR prevention)

#### Get Location History
```http
GET /api/v1/location-audience/location/{location_id}/history?page=1&page_size=50
Authorization: Bearer <token>
```

**Requirements:** Admin role

#### Get Statistics
```http
GET /api/v1/location-audience/stats
Authorization: Bearer <token>
```

**Requirements:** Manager role or higher

---

## Geofence Engine

### Haversine Distance Calculation

```python
from app.core.geofence import haversine_distance

# Calculate distance between two points
distance = haversine_distance(
    lat1=40.7128, lon1=-74.0060,  # NYC
    lat2=34.0522, lon2=-118.2437,  # LA
    unit="miles"  # or "km"
)
# Returns: ~2451 miles
```

### Geofence Checking

```python
from app.core.geofence import check_geofence, check_geofences_batch

# Check single location
result = check_geofence(
    user_latitude=40.7128,
    user_longitude=-74.0060,
    location=location_object
)

if result.is_inside:
    print(f"Inside {result.location_name}")
    print(f"Distance: {result.distance_miles} miles")
    print(f"Margin: {result.margin_miles} miles from edge")

# Batch check multiple locations
results = check_geofences_batch(
    user_latitude=40.7128,
    user_longitude=-74.0060,
    locations=[location1, location2, location3]
)
```

### Redis GEO Integration

```python
from app.core.geofence import get_geo_service

geo = get_geo_service()
await geo.connect()

# Add location to index
await geo.add_location(location_id=1, latitude=40.7128, longitude=-74.0060)

# Find locations within radius
nearby = await geo.find_locations_in_radius(
    latitude=40.7128,
    longitude=-74.0060,
    radius_miles=10.0
)

# Get distance to specific location
distance = await geo.get_distance(
    latitude=40.7128,
    longitude=-74.0060,
    location_id=1
)
```

---

## Celery Tasks

### Check User Geofence
```python
from app.location_tasks import check_user_geofence_task

# Trigger async geofence check
result = check_user_geofence_task.delay(
    user_id=123,
    latitude=40.7128,
    longitude=-74.0060
)

# Returns:
# {
#   "success": True,
#   "user_id": 123,
#   "locations_inside": 2,
#   "locations_outside": 5,
#   "assignments_changed": [...]
# }
```

### Batch Geofence Check
```python
from app.location_tasks import batch_geofence_check_task

# Process multiple users efficiently
result = batch_geofence_check_task.delay(
    user_locations=[
        {"user_id": 1, "latitude": 40.7128, "longitude": -74.0060},
        {"user_id": 2, "latitude": 34.0522, "longitude": -118.2437},
    ]
)
```

### Sync Locations to Redis
```python
from app.location_tasks import sync_all_locations_to_redis

# Sync all active locations to Redis GEO index
result = sync_all_locations_to_redis.delay()
```

### Cleanup Expired Assignments
```python
from app.location_tasks import cleanup_expired_assignments

# Run daily to remove expired assignments
result = cleanup_expired_assignments.delay()
```

---

## Frontend Components

### LocationAudienceMap Component

```jsx
import LocationAudienceMap from '@/components/LocationAudienceMap'

function MyComponent() {
  return (
    <LocationAudienceMap
      adminMode={true}
      height={600}
      showGeofences={true}
      showUsers={false}
      onLocationSelect={(location) => {
        console.log('Selected:', location)
      }}
      isCreating={false}
      onMapCreateClick={(coords) => {
        console.log('Map clicked at:', coords)
      }}
    />
  )
}
```

**Props:**
- `adminMode` (boolean): Enable admin features
- `height` (number): Map height in pixels
- `showGeofences` (boolean): Show geofence radius circles
- `showUsers` (boolean): Show individual user markers
- `onLocationSelect` (function): Callback when location clicked
- `isCreating` (boolean): In location creation mode
- `onMapCreateClick` (function): Callback when map clicked in create mode

### API Service

```javascript
import { locationAudienceAPI } from '@/services/api'

// Assign user to location
await locationAudienceAPI.assignUser({
  user_id: 123,
  location_id: 456,
  notes: 'Manual assignment'
})

// Remove user from location
await locationAudienceAPI.removeUser(123, 456, 'Transferred')

// Update user geofence location
await locationAudienceAPI.updateGeofence(40.7128, -74.0060)

// Get location members
const members = await locationAudienceAPI.getLocationMembers(456, {
  page: 1,
  page_size: 20,
  status: 'active'
})

// Get user locations
const locations = await locationAudienceAPI.getUserLocations(123)

// Get history
const history = await locationAudienceAPI.getLocationHistory(456)

// Get stats
const stats = await locationAudienceAPI.getStats()
```

---

## Security Checklist

### ✅ Implemented Security Measures

| Threat | Mitigation |
|--------|------------|
| **IDOR** | Users can only view their own location data; admin check for others |
| **Privilege Escalation** | RBAC validation on all modification endpoints |
| **SQL Injection** | SQLAlchemy ORM with parameterized queries |
| **XSS** | React escapes output; no user input rendered without sanitization |
| **API Abuse** | Rate limiting (30/min geofence, 100/min assignments) |
| **Mass Assignment** | Pydantic schemas with explicit field definitions |
| **Location Spoofing** | Coordinate validation; server-side verification |
| **Replay Attacks** | JWT tokens with expiration; timestamps in audit logs |
| **Data Leakage** | Soft deletes; filtered queries exclude deleted records |

### Input Validation

```python
# Coordinate validation
is_valid, error = validate_coordinates(latitude, longitude)
# Returns: (True, None) or (False, "Error message")

# Radius validation
is_valid, error = validate_geofence_radius(radius_miles)
# Ensures 0.1 <= radius <= 50.0

# Full location validation
validation = validate_location_input(name, latitude, longitude, radius)
# Returns: {
#   "is_valid": bool,
#   "errors": [],
#   "sanitized": {...}
# }
```

---

## Performance Optimization

### Redis GEO Index
- O(log N) proximity searches
- Caches all active locations
- Synced on create/update/delete

### Batch Processing
```python
# Process 1000 users in single Celery task
from app.location_tasks import batch_geofence_check_task

users = [{"user_id": i, "latitude": lat, "longitude": lon} for i in range(1000)]
result = batch_geofence_check_task.delay(users)
```

### Database Indexes
- `user_locations.user_id` - Fast user lookups
- `user_locations.location_id` - Fast location member lookups
- `user_location_history.created_at` - Fast history queries

### Caching Strategy
- Location data cached in Redis (15 min TTL)
- Geofence results not cached (real-time requirement)
- Request deduplication for concurrent identical requests

---

## Testing

### Run Geofence Tests
```bash
cd Alert-system-backend
source venv/bin/activate
pytest app/tests/test_geofence.py -v
```

### Test Coverage
- Haversine distance calculation
- Coordinate validation
- Radius validation
- Geofence checking (single and batch)
- Overlap detection
- Edge cases (poles, equator, international date line)

---

## Deployment

### Railway Configuration

1. **Environment Variables:**
```bash
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
SECRET_KEY=your-secret-key-32-chars-min
```

2. **Run Migrations:**
```bash
alembic upgrade head
```

3. **Start Workers:**
```bash
celery -A app.celery_app worker --loglevel=info
celery -A app.celery_app beat --loglevel=info
```

4. **Sync Redis GEO Index:**
```python
from app.location_tasks import sync_all_locations_to_redis
sync_all_locations_to_redis.delay()
```

---

## Monitoring

### Key Metrics to Track

1. **Geofence Processing:**
   - Average processing time per user
   - Queue depth for geofence tasks
   - Error rate

2. **Assignment Changes:**
   - Daily assignment count
   - Manual vs geofence ratio
   - Entry/exit frequency

3. **System Health:**
   - Redis connection status
   - Celery worker availability
   - Database query performance

### Logging

All actions are logged to `AuditLog` table:
```python
# Example audit log entry
{
  "user_id": 123,
  "action": "assign_user_to_location",
  "resource_type": "user_location",
  "resource_id": 456,
  "details": {"user_id": 789, "location_id": 456},
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "created_at": "2026-03-04T10:30:00Z"
}
```

---

## Cost Analysis

All tools used are **FREE** and **OPEN SOURCE**:

| Component | Tool | Cost |
|-----------|------|------|
| Backend Framework | FastAPI | Free (MIT) |
| Database | PostgreSQL 16 | Free (PostgreSQL License) |
| Cache/Queue | Redis 7 | Free (BSD) |
| Task Queue | Celery | Free (BSD) |
| Map Library | Leaflet | Free (BSD-2) |
| Map Tiles | OpenStreetMap/CARTO | Free (ODbL) |
| Location Autocomplete | LocationIQ Free Tier | 5,000 req/day free |
| Geofencing | Custom Haversine | Free |
| Hosting | Railway | Free tier available |

**Total Monthly Cost: $0** (within free tier limits)

---

## Troubleshooting

### Common Issues

**1. Geofence not triggering:**
- Check Celery worker is running
- Verify Redis connection
- Ensure location coordinates are valid

**2. Redis GEO index out of sync:**
```python
from app.location_tasks import sync_all_locations_to_redis
sync_all_locations_to_redis.delay()
```

**3. Rate limit errors:**
- Geofence updates: 30/minute
- Assignments: 100/minute
- Implement exponential backoff in client

**4. Overlap warnings:**
- Overlaps are logged but don't prevent creation
- Review overlap percentage in logs
- Adjust radius if needed

---

## Future Enhancements

1. **Dynamic Geofences:** Adjust radius based on time of day
2. **Predictive Entry:** Notify before user enters geofence
3. **Heat Maps:** Visualize user density across locations
4. **Geofence Templates:** Pre-defined radii for common scenarios
5. **Multi-Point Geofences:** Polygon-based boundaries (not just circles)
