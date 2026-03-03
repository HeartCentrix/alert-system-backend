"""
Load Testing Script using Locust

Simulates:
- 1000 concurrent users
- Burst traffic (100 req/sec spike)
- Location update storms
- Notification broadcast to 10,000 recipients

Usage:
    locust -f load_test.py --host=http://localhost:8000
    
    # Run headless (no web UI)
    locust -f load_test.py --host=http://localhost:8000 --headless -u 1000 -r 100 -t 300s
    
    # Run with specific scenario
    locust -f load_test.py --host=http://localhost:8000 --headless -u 500 -r 50 -t 180s --tags auth,api
"""

from locust import HttpUser, task, between, events
from locust.runners import MasterRunner, WorkerRunner
import random
import json
import time
from datetime import datetime


# =============================================================================
# USER BEHAVIOR SIMULATION
# =============================================================================

class AlertSystemUser(HttpUser):
    """
    Simulates a typical TM Alert user.
    
    Behavior patterns:
    - Login
    - View dashboard
    - Check notifications
    - View users/locations
    - Send notifications (for managers/admins)
    """
    
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    
    # Test data
    test_credentials = [
        {"email": "admin@tmalert.com", "password": "Admin@123456"},
        {"email": "manager@tmalert.com", "password": "Manager@123456"},
        {"email": "viewer@tmalert.com", "password": "Viewer@123456"},
    ]
    
    access_token = None
    user_role = "viewer"
    
    def on_start(self):
        """Called when a simulated user starts."""
        self.login()
    
    def login(self):
        """Authenticate and get access token."""
        credentials = random.choice(self.test_credentials)
        
        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": credentials["email"],
                "password": credentials["password"]
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.access_token = data["access_token"]
            self.user_role = data["user"]["role"]
            self.client.headers["Authorization"] = f"Bearer {self.access_token}"
        else:
            print(f"Login failed: {response.status_code}")
    
    @task(10)
    def view_dashboard(self):
        """View dashboard stats."""
        self.client.get("/api/v1/dashboard/stats")
        self.client.get("/api/v1/dashboard/map-data")
        self.client.get("/api/v1/dashboard/notification-activity")
    
    @task(8)
    def list_notifications(self):
        """View notification list."""
        self.client.get("/api/v1/notifications?page=1&page_size=20")
    
    @task(5)
    def view_notification_detail(self):
        """View a specific notification."""
        notification_id = random.randint(1, 100)
        self.client.get(f"/api/v1/notifications/{notification_id}")
    
    @task(7)
    def list_users(self):
        """View user list."""
        self.client.get("/api/v1/users?page=1&page_size=20")
    
    @task(6)
    def list_locations(self):
        """View location list."""
        self.client.get("/api/v1/locations")
    
    @task(3)
    def list_groups(self):
        """View group list."""
        self.client.get("/api/v1/groups")
    
    @task(2)
    def list_incidents(self):
        """View incident list."""
        self.client.get("/api/v1/incidents")
    
    @task(1)
    def send_notification(self):
        """Send a notification (only for managers/admins)."""
        if self.user_role in ["admin", "manager", "super_admin"]:
            self.client.post(
                "/api/v1/notifications",
                json={
                    "title": f"Load Test Notification {int(time.time())}",
                    "message": "This is a simulated notification for load testing purposes.",
                    "subject": "Load Test Alert",
                    "channels": ["sms", "email"],
                    "target_all": True,
                    "response_required": False,
                }
            )
    
    @task(4)
    def get_current_user(self):
        """Get current user profile."""
        self.client.get("/api/v1/auth/me")


# =============================================================================
# AUTHENTICATION LOAD TEST
# =============================================================================

class AuthLoadTest(HttpUser):
    """
    Specialized load test for authentication endpoints.
    
    Simulates:
    - Login storms
    - Token refresh
    - Password reset requests
    """
    
    wait_time = between(0.5, 2)
    
    @task(5)
    def login(self):
        """Simulate login requests."""
        user_id = random.randint(1, 1000)
        self.client.post(
            "/api/v1/auth/login",
            json={
                "email": f"user{user_id}@example.com",
                "password": "TestPassword123!"
            }
        )
    
    @task(3)
    def refresh_token(self):
        """Simulate token refresh."""
        # First login to get refresh token
        login_response = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@tmalert.com",
                "password": "Admin@123456"
            }
        )
        
        if login_response.status_code == 200:
            refresh_token = login_response.json()["refresh_token"]
            self.client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": refresh_token}
            )
    
    @task(1)
    def forgot_password(self):
        """Simulate password reset requests."""
        self.client.post(
            "/api/v1/auth/forgot-password",
            json={"email": f"user{random.randint(1, 1000)}@example.com"}
        )


# =============================================================================
# NOTIFICATION BROADCAST LOAD TEST
# =============================================================================

class NotificationBroadcastTest(HttpUser):
    """
    Load test for notification broadcasting.
    
    Simulates:
    - Emergency broadcast to all users
    - High-volume notification creation
    """
    
    wait_time = between(2, 5)
    access_token = None
    
    def on_start(self):
        """Login as admin."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@tmalert.com",
                "password": "Admin@123456"
            }
        )
        if response.status_code == 200:
            self.access_token = response.json()["access_token"]
            self.client.headers["Authorization"] = f"Bearer {self.access_token}"
    
    @task(10)
    def send_emergency_notification(self):
        """Send emergency notification."""
        self.client.post(
            "/api/v1/notifications",
            json={
                "title": f"🚨 EMERGENCY: Load Test {int(time.time())}",
                "message": "This is a simulated emergency alert for load testing. Please disregard.",
                "subject": "EMERGENCY ALERT",
                "channels": ["sms", "email", "voice"],
                "target_all": True,
                "response_required": True,
                "response_deadline_minutes": 30,
            }
        )
    
    @task(5)
    def send_routine_notification(self):
        """Send routine notification."""
        self.client.post(
            "/api/v1/notifications",
            json={
                "title": f"Routine Update {int(time.time())}",
                "message": "This is a routine notification for load testing.",
                "subject": "Routine Update",
                "channels": ["email"],
                "target_all": False,
                "target_group_ids": [1],
            }
        )


# =============================================================================
# LOCATION UPDATE STORM TEST
# =============================================================================

class LocationUpdateStormTest(HttpUser):
    """
    Simulates location update storms (geofence updates).
    
    Simulates:
    - Bulk location updates
    - Geofence recalculation
    - User-location assignment changes
    """
    
    wait_time = between(0.5, 1)
    access_token = None
    
    def on_start(self):
        """Login as admin."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@tmalert.com",
                "password": "Admin@123456"
            }
        )
        if response.status_code == 200:
            self.access_token = response.json()["access_token"]
            self.client.headers["Authorization"] = f"Bearer {self.access_token}"
    
    @task(10)
    def create_location(self):
        """Create new location."""
        lat = random.uniform(25.0, 48.0)  # Continental US
        lon = random.uniform(-125.0, -70.0)
        
        self.client.post(
            "/api/v1/locations",
            json={
                "name": f"Load Test Location {int(time.time())}_{random.randint(1, 1000)}",
                "address": f"{random.randint(1, 999)} Test Street",
                "city": "Test City",
                "state": "TS",
                "zip_code": "12345",
                "latitude": lat,
                "longitude": lon,
                "geofence_radius_miles": random.uniform(1.0, 10.0),
            }
        )
    
    @task(5)
    def update_location(self):
        """Update existing location."""
        location_id = random.randint(1, 100)
        
        self.client.put(
            f"/api/v1/locations/{location_id}",
            json={
                "name": f"Updated Location {int(time.time())}",
                "geofence_radius_miles": random.uniform(1.0, 10.0),
            }
        )
    
    @task(3)
    def list_locations_with_filters(self):
        """List locations with various filters."""
        self.client.get("/api/v1/locations?city=Test&state=TS")
        self.client.get("/api/v1/locations?country=USA")
        self.client.get("/api/v1/locations?is_active=true")


# =============================================================================
# BURST TRAFFIC SIMULATION
# =============================================================================

class BurstTrafficTest(HttpUser):
    """
    Simulates burst traffic patterns.
    
    Characteristics:
    - Sudden spike in requests
    - Short duration high load
    - Multiple endpoints hit simultaneously
    """
    
    wait_time = between(0.1, 0.5)  # Very short wait for burst
    
    @task
    def burst_request(self):
        """Make rapid requests to various endpoints."""
        endpoints = [
            "/health",
            "/api/v1/auth/me",
            "/api/v1/dashboard/stats",
            "/api/v1/notifications?page=1",
            "/api/v1/users?page=1",
            "/api/v1/locations",
        ]
        
        endpoint = random.choice(endpoints)
        self.client.get(endpoint)


# =============================================================================
# LOCUST EVENT HANDLERS
# =============================================================================

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when load test starts."""
    print("=" * 80)
    print("TM Alert Load Test Starting...")
    print("=" * 80)
    print(f"Target Host: {environment.host}")
    print(f"Start Time: {datetime.now()}")
    print("=" * 80)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when load test stops."""
    print("=" * 80)
    print("TM Alert Load Test Complete")
    print("=" * 80)
    print(f"End Time: {datetime.now()}")
    
    # Print statistics
    stats = environment.stats
    print(f"\nTotal Requests: {stats.total.num_requests}")
    print(f"Total Failures: {stats.total.num_failures}")
    print(f"Failure Rate: {stats.total.num_failures / max(stats.total.num_requests, 1) * 100:.2f}%")
    print(f"Average Response Time: {stats.total.avg_response_time:.2f}ms")
    print(f"Requests/sec: {stats.total.current_rps:.2f}")
    print("=" * 80)


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    """Called on each request."""
    # Log slow requests
    if response_time > 2000:  # > 2 seconds
        print(f"SLOW REQUEST: {name} took {response_time:.2f}ms")


# =============================================================================
# RUN CONFIGURATION
# =============================================================================

if __name__ == "__main__":
    import os
    
    # Default configuration
    config = {
        "host": "http://localhost:8000",
        "users": 100,
        "spawn_rate": 10,
        "run_time": "60s",
    }
    
    # Run headless
    os.system(
        f"locust -f {__file__} "
        f"--host={config['host']} "
        f"--headless "
        f"-u {config['users']} "
        f"-r {config['spawn_rate']} "
        f"-t {config['run_time']}"
    )
