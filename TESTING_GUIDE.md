# TM Alert - Testing & Security System Documentation

## Table of Contents

1. [Quick Start](#quick-start)
2. [Test Structure](#test-structure)
3. [Running Tests](#running-tests)
4. [CI/CD Pipeline](#cicd-pipeline)
5. [Security Scanning](#security-scanning)
6. [Coverage Requirements](#coverage-requirements)
7. [Test Categories](#test-categories)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

```bash
# Python 3.11+
python --version

# Install dependencies
pip install -r requirements.txt

# Install test dependencies
pip install pytest pytest-cov pytest-asyncio pytest-mock hypothesis bandit safety ruff mypy
```

### Run All Tests

```bash
# Quick test run
pytest

# With coverage
pytest --cov=app --cov-report=html

# Open coverage report
open htmlcov/index.html
```

### Run Security Scans

```bash
# Bandit security scan
bandit -r app/ -ll

# Dependency check
safety check

# Linting
ruff check app/

# Type checking
mypy app/
```

---

## Test Structure

```
app/tests/
├── conftest.py              # Shared fixtures
├── unit/                    # Unit tests (fast, isolated)
│   ├── test_security.py     # JWT, password hashing
│   ├── test_messaging.py    # Twilio, SES, webhooks
│   ├── test_tasks.py        # Celery tasks
│   └── test_schemas.py      # Pydantic validation
├── integration/             # Integration tests
│   ├── test_database.py     # PostgreSQL operations
│   ├── test_redis.py        # Redis caching
│   └── test_celery.py       # Celery integration
├── api/                     # API endpoint tests
│   ├── test_auth_endpoints.py
│   ├── test_users_endpoints.py
│   └── test_notifications_endpoints.py
├── security/                # Security tests
│   ├── test_jwt_security.py
│   └── test_injection.py    # OWASP Top 10
├── property/                # Property-based tests
│   └── test_properties.py   # Hypothesis tests
└── fuzz/                    # Fuzz tests
    └── test_input_fuzzing.py
```

---

## Running Tests

### By Category

```bash
# Unit tests only
pytest -m unit

# Integration tests only
pytest -m integration

# API tests only
pytest -m api

# Security tests only
pytest -m security

# Property-based tests
pytest app/tests/property/

# Fuzz tests
pytest app/tests/fuzz/
```

### By File

```bash
# Specific test file
pytest app/tests/unit/test_security.py -v

# Specific test class
pytest app/tests/unit/test_security.py::TestPasswordHashing -v

# Specific test function
pytest app/tests/unit/test_security.py::TestPasswordHashing::test_verify_password_correct -v
```

### With Options

```bash
# Stop on first failure
pytest -x

# Show local variables on failure
pytest -l

# Show print statements
pytest -s

# Parallel execution (faster)
pytest -n auto

# Rerun failed tests first
pytest --lf

# Run tests that failed last time, then all others
pytest --ff
```

### Coverage Options

```bash
# HTML report
pytest --cov=app --cov-report=html
open htmlcov/index.html

# Terminal report with missing lines
pytest --cov=app --cov-report=term-missing

# XML report (for CI)
pytest --cov=app --cov-report=xml

# Fail if coverage below threshold
pytest --cov=app --cov-fail-under=85
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

The pipeline runs automatically on:
- Push to `main` or `develop` branches
- Pull requests
- Manual dispatch

### Pipeline Stages

```yaml
1. Lint & Type Check
   - ruff (linting)
   - mypy (type checking)

2. Security Scan
   - bandit (code security)
   - safety (dependency vulnerabilities)
   - gitleaks (secret detection)

3. Test Suite
   - Unit tests
   - Integration tests
   - API tests
   - Security tests

4. Coverage Verification
   - Must achieve ≥85% coverage

5. Docker Build
   - Build and push image
   - Trivy vulnerability scan

6. Deploy (main branch only)
   - Deploy to Railway
   - Run smoke tests
```

### Pipeline Status Badges

Add to README.md:

```markdown
[![CI/CD](https://github.com/your-org/tm-alert/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/your-org/tm-alert/actions/workflows/ci-cd.yml)
[![Coverage](https://codecov.io/gh/your-org/tm-alert/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/tm-alert)
```

---

## Security Scanning

### Bandit (Code Security)

```bash
# Full scan
bandit -r app/ -f json -o bandit-report.json

# High severity only
bandit -r app/ --severity-level high

# Skip test files
bandit -r app/ --skip B101  # Skip assert_used
```

### Safety (Dependency Check)

```bash
# Check installed packages
safety check

# Check requirements file
safety check -r requirements.txt

# Full report
safety check --full-report

# JSON output
safety check --json
```

### Secret Detection

```bash
# Gitleaks (pre-commit)
gitleaks detect

# Pre-commit hook
pre-commit install
pre-commit run --all-files
```

### OWASP Tests

Security tests cover:
- SQL Injection
- XSS (Cross-Site Scripting)
- IDOR (Insecure Direct Object Reference)
- JWT Security
- CSRF Protection
- Rate Limiting

Run with:
```bash
pytest app/tests/security/ -v
```

---

## Coverage Requirements

### Minimum Coverage

| Component | Minimum |
|-----------|---------|
| Core (security, geofence) | 95% |
| Services (messaging) | 90% |
| API endpoints | 85% |
| Models/Schemas | 80% |
| **Overall** | **85%** |

### Check Coverage

```bash
# Terminal report
pytest --cov=app --cov-report=term-missing

# HTML report
pytest --cov=app --cov-report=html
open htmlcov/index.html

# Fail if below threshold
pytest --cov=app --cov-fail-under=85
```

### Exclude from Coverage

Some code is excluded from coverage:
- Test files
- Configuration
- Startup code
- Debug/development code
- Abstract methods

---

## Test Categories

### Unit Tests (`@pytest.mark.unit`)

**Purpose:** Test individual functions/classes in isolation.

**Characteristics:**
- Fast (< 100ms per test)
- No external dependencies
- Mock databases, APIs, Redis

**Example:**
```python
def test_password_hashing():
    hashed = hash_password("TestPassword123!")
    assert verify_password("TestPassword123!", hashed) is True
```

### Integration Tests (`@pytest.mark.integration`)

**Purpose:** Test component interactions.

**Characteristics:**
- Use test database
- Test Redis connections
- Test Celery tasks

**Example:**
```python
def test_database_user_creation(db_session):
    user = User(email="test@example.com", ...)
    db_session.add(user)
    db_session.commit()
    assert user.id is not None
```

### API Tests (`@pytest.mark.api`)

**Purpose:** Test HTTP endpoints.

**Characteristics:**
- Use TestClient
- Test authentication
- Test authorization
- Test validation

**Example:**
```python
def test_login_success(client, test_user):
    response = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPassword123!"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()
```

### Security Tests (`@pytest.mark.security`)

**Purpose:** Test security controls.

**Characteristics:**
- Test JWT security
- Test injection prevention
- Test authorization bypass
- Test rate limiting

**Example:**
```python
def test_sql_injection_prevention(client):
    response = client.post("/api/v1/auth/login", json={
        "email": "' OR '1'='1",
        "password": "Password123!"
    })
    assert response.status_code == 401
```

### Property-Based Tests

**Purpose:** Test invariants with generated inputs.

**Characteristics:**
- Use Hypothesis library
- Generate random inputs
- Test mathematical properties

**Example:**
```python
@given(st.floats(), st.floats())
def test_distance_symmetric(lat1, lon1):
    distance = haversine_distance(lat1, lon1, lat1, lon1)
    assert distance == 0.0
```

### Fuzz Tests

**Purpose:** Find edge cases with random inputs.

**Characteristics:**
- Use Hypothesis
- Generate invalid inputs
- Test error handling

**Example:**
```python
@given(st.text(min_size=0, max_size=1000))
def test_login_email_fuzz(email):
    try:
        LoginRequest(email=email, password="Password123!")
    except ValidationError:
        pass  # Expected for invalid emails
```

---

## Load Testing

### Locust Setup

```bash
# Install locust
pip install locust

# Run with web UI
locust -f tests/load_test.py --host=http://localhost:8000

# Run headless
locust -f tests/load_test.py --host=http://localhost:8000 \
    --headless -u 1000 -r 100 -t 300s
```

### Load Test Scenarios

1. **Normal Load:** 100 users, 10 users/sec spawn
2. **Burst Traffic:** 500 users, 50 users/sec spawn
3. **Emergency Broadcast:** 1000 users, notification storm
4. **Location Update Storm:** Rapid location updates

---

## Mutation Testing

### Setup

```bash
# Install mutmut
pip install mutmut

# Run mutation testing
mutmut run

# Show results
mutmut results

# Generate report
mutmut junitxml
```

### Interpret Results

```
- ☠️   Killed (good - tests caught the mutation)
- 🤷     Survived (bad - tests didn't catch it)
- 🤪     Timeout (test took too long)
- 🤔     Suspicious (tests passed but output changed)
```

---

## Troubleshooting

### Common Issues

#### Tests Hang

```bash
# Run with timeout
pytest --timeout=300

# Check for database locks
lsof | grep postgres
```

#### Coverage Too Low

```bash
# Find uncovered files
pytest --cov=app --cov-report=term-missing

# Check specific file
coverage report -m app/core/security.py
```

#### Tests Fail Locally but Pass in CI

```bash
# Ensure test database is clean
DROP DATABASE IF EXISTS tm_alert_test;
CREATE DATABASE tm_alert_test;

# Run migrations
alembic upgrade head
```

#### Import Errors

```bash
# Ensure in project root
cd /path/to/Alert-system-backend

# Add to PYTHONPATH
export PYTHONPATH=$PYTHONPATH:$(pwd)

# Install in development mode
pip install -e .
```

### Database Issues

#### Connection Refused

```bash
# Check PostgreSQL is running
pg_isready

# Check connection string
echo $TEST_DATABASE_URL
```

#### Permission Denied

```bash
# Grant permissions
psql -c "GRANT ALL PRIVILEGES ON DATABASE tm_alert_test TO postgres;"
```

### Redis Issues

#### Connection Refused

```bash
# Check Redis is running
redis-cli ping

# Should return: PONG
```

---

## Best Practices

### Writing Tests

1. **Use fixtures** for common setup
2. **Test one thing** per test function
3. **Use descriptive names** (`test_login_with_invalid_password`)
4. **Arrange-Act-Assert** pattern
5. **Don't test implementation**, test behavior

### Test Data

1. **Use factories** for creating test data
2. **Clean up after tests** (transactions handle this)
3. **Don't share state** between tests
4. **Use realistic data** but anonymized

### Security Testing

1. **Test authentication** on every endpoint
2. **Test authorization** for every role
3. **Test input validation** for every field
4. **Test error messages** don't leak info
5. **Test rate limiting** on sensitive endpoints

### CI/CD

1. **Keep tests fast** (< 10 minutes total)
2. **Fail fast** on critical issues
3. **Cache dependencies** for speed
4. **Use matrix builds** for parallel testing
5. **Upload artifacts** for debugging

---

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [Hypothesis documentation](https://hypothesis.readthedocs.io/)
- [Bandit documentation](https://bandit.readthedocs.io/)
- [Locust documentation](https://docs.locust.io/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## Support

For questions or issues:
1. Check existing documentation
2. Review test examples
3. Consult the testing strategy document
4. Reach out to the QA team
