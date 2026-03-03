# TM Alert - Automated Testing & Security Strategy

## Executive Summary

This document outlines the comprehensive automated testing and security system for the TM Alert emergency notification platform. The system ensures code quality, security compliance, and prevents regressions through multi-layered testing strategies integrated with GitHub CI/CD.

---

## Testing Pyramid

```
                    ┌─────────────┐
                    │   E2E/Load  │     5%
                   ─├─────────────┤─
                  │ │ Integration │ │   15%
                 ──├─────────────├──
                │ │  Functional  │ │   20%
               ───├──────────────├───
              │ │    Unit Tests   │ │  60%
             ────┴────────────────┴────
```

---

## Test Categories

### 1. Unit Tests (60% coverage)
**Purpose:** Test individual functions, classes, and modules in isolation.

**Coverage:**
- `app/core/security.py` - JWT token creation/validation, password hashing
- `app/core/geofence.py` - Haversine calculations, coordinate validation
- `app/core/deps.py` - Auth dependency injection
- `app/services/messaging.py` - Twilio, SES, webhook services
- `app/tasks.py` - Celery notification tasks
- `app/schemas.py` - Pydantic validation

**Test Types:**
- Positive tests (valid inputs)
- Negative tests (invalid inputs)
- Edge cases (boundary conditions)
- Property-based tests (invariants)
- Fuzz tests (random inputs)

### 2. Integration Tests (20% coverage)
**Purpose:** Test interactions between components.

**Coverage:**
- Database operations (CRUD, transactions, constraints)
- Redis caching (hit/miss, TTL, GEO operations)
- Celery task execution (retry logic, error handling)
- API endpoint chains (auth → resource access)
- External service mocks (Twilio, SES)

### 3. API/Functional Tests (15% coverage)
**Purpose:** Test complete API endpoints and business logic.

**Coverage:**
- All authentication endpoints
- All CRUD operations
- Role-based access control
- Input validation
- Error responses
- Rate limiting

### 4. Security Tests (Integrated throughout)
**Purpose:** Detect and prevent security vulnerabilities.

**Coverage:**
- OWASP Top 10 scanning
- JWT security (expired, malformed, tampered tokens)
- SQL injection prevention
- XSS prevention
- IDOR (Insecure Direct Object Reference)
- Privilege escalation attempts
- Rate limiting bypass attempts
- Secret detection

### 5. Load/Performance Tests (5% coverage)
**Purpose:** Ensure system handles production load.

**Scenarios:**
- 1000 concurrent users
- Burst traffic (100 req/sec spike)
- Location update storms
- Notification broadcast to 10,000 recipients

---

## Security Testing Strategy

### Static Analysis
| Tool | Purpose | Threshold |
|------|---------|-----------|
| `bandit` | Python security scanner | 0 high/critical issues |
| `safety` | Dependency vulnerabilities | 0 known vulnerabilities |
| `ruff` | Linting + security rules | 0 errors |
| `mypy` | Type checking | 0 type errors |

### Dynamic Security Tests
- JWT token manipulation tests
- SQL injection attempt tests
- XSS payload tests
- IDOR enumeration tests
- CSRF protection tests
- Rate limiting tests
- Input boundary tests

### Secret Detection
- Pre-commit hooks for secret detection
- CI scanning for exposed credentials
- Environment variable validation

---

## Coverage Requirements

| Component | Minimum Coverage |
|-----------|-----------------|
| Core modules (security, geofence) | 95% |
| Services (messaging) | 90% |
| API endpoints | 85% |
| Models/Schemas | 80% |
| **Overall Project** | **85%** |

---

## Test Data Management

### Fixtures
- Factory functions for creating test data
- Database transactions (rollback after each test)
- Mock Redis/Celery for unit tests
- Real Redis/PostgreSQL for integration tests

### Test Databases
- Unit tests: In-memory SQLite / mocked
- Integration tests: Isolated PostgreSQL (docker)
- CI: Ephemeral PostgreSQL container

---

## CI/CD Integration

### GitHub Actions Pipeline

```yaml
stages:
  1. lint        → ruff, mypy
  2. security    → bandit, safety, secret-scan
  3. test        → pytest (unit, integration, api)
  4. coverage    → Verify ≥85%
  5. build       → Docker build
  6. deploy      → Railway (main branch only)
```

### Branch Protection Rules
- Require PR reviews
- Require status checks to pass
- Require linear history
- Block force pushes

---

## Test Execution

### Local Development
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run security scans
bandit -r app/
safety check

# Run type checking
mypy app/

# Run linting
ruff check app/
```

### CI Execution
```bash
# Full CI pipeline
./scripts/ci-test.sh
```

---

## Mutation Testing

**Tool:** `mutmut` or `cosmic-ray`

**Purpose:** Verify test effectiveness by introducing bugs.

**Process:**
1. Run mutation testing on core modules
2. Identify uncaught mutations
3. Add tests to catch missed mutations
4. Target: ≥80% mutation score

---

## Fuzz Testing

**Tool:** `hypothesis`

**Purpose:** Generate random inputs to find edge cases.

**Coverage:**
- API input schemas
- Geofence calculations
- Token validation
- Database queries

---

## Property-Based Testing

**Tool:** `hypothesis`

**Properties Tested:**
- Distance is always non-negative
- Token decode of encoded token returns original data
- Hash verification is deterministic
- Geofence radius validation is consistent

---

## Regression Prevention

### Strategies
1. **Test-all modified files** - Any code change triggers related tests
2. **Coverage gating** - PRs cannot reduce overall coverage
3. **Security regression** - Fixed vulnerabilities get permanent tests
4. **Performance budgets** - API response time thresholds

### Monitoring
- Track test execution time
- Monitor flaky tests
- Alert on coverage drops
- Log security scan findings

---

## Frontend Testing (Vitest)

### Component Tests
- React component rendering
- Props validation
- Event handlers
- State management

### Integration Tests
- Form submissions
- API hook integration
- Auth flow
- Navigation

### E2E Tests (Future)
- Playwright for critical user journeys
- Login → Send notification → View responses

---

## Maintenance

### Weekly Tasks
- Review failing tests
- Update dependency vulnerabilities
- Check for flaky tests

### Monthly Tasks
- Review coverage reports
- Update security scan rules
- Audit test effectiveness

### Quarterly Tasks
- Full security audit
- Load test review
- Test strategy update

---

## Responsibilities

| Role | Responsibility |
|------|----------------|
| Developers | Write unit tests, fix security issues |
| QA | Integration/API tests, security testing |
| DevOps | CI/CD pipeline, monitoring |
| Security | Vulnerability scans, audits |

---

## Appendix: Test File Structure

```
app/tests/
├── conftest.py              # Shared fixtures
├── __init__.py
├── unit/
│   ├── test_security.py
│   ├── test_geofence.py
│   ├── test_messaging.py
│   ├── test_tasks.py
│   └── test_schemas.py
├── integration/
│   ├── test_database.py
│   ├── test_redis.py
│   ├── test_celery.py
│   └── test_auth_flow.py
├── api/
│   ├── test_auth_endpoints.py
│   ├── test_users_endpoints.py
│   ├── test_notifications_endpoints.py
│   ├── test_locations_endpoints.py
│   └── test_webhooks.py
├── security/
│   ├── test_jwt_security.py
│   ├── test_injection.py
│   ├── test_idor.py
│   └── test_rate_limiting.py
├── property/
│   ├── test_geofence_properties.py
│   └── test_token_properties.py
└── fuzz/
    ├── test_input_fuzzing.py
    └── test_api_fuzzing.py
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-04 | QA Team | Initial comprehensive strategy |
