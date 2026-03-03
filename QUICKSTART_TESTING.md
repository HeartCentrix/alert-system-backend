# =============================================================================
# TM Alert - Quick Start Testing Guide
# 
# Get up and running with tests in 5 minutes
# =============================================================================

## Step 1: Install Dependencies

```bash
cd Alert-system-backend

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install all dependencies including test tools
pip install -r requirements.txt
pip install -r requirements-test.txt
```

## Step 2: Verify Installation

```bash
# Check pytest is installed
pytest --version

# Check security tools
bandit --version
safety --version
```

## Step 3: Run Your First Test

```bash
# Run a single test file
pytest app/tests/unit/test_security.py -v

# Expected output: All tests should PASS
```

## Step 4: Run All Tests

```bash
# Quick test run (no coverage)
pytest

# With coverage
pytest --cov=app --cov-report=term-missing

# Open HTML coverage report
open htmlcov/index.html  # On Windows: start htmlcov/index.html
```

## Step 5: Run Security Scans

```bash
# Bandit security scan
bandit -r app/ --severity-level high

# Dependency check
safety check

# Linting
ruff check app/
```

## Step 6: Set Up Pre-commit Hooks (Optional)

```bash
# Install pre-commit
pip install pre-commit

# Install git hooks
pre-commit install

# Run on all files
pre-commit run --all-files
```

## Step 7: Configure CI/CD

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Add comprehensive testing system"
   git push origin main
   ```

2. **GitHub Actions will automatically:**
   - Run all tests
   - Perform security scans
   - Check coverage
   - Build Docker image

3. **Add Repository Secrets** (for deployment):
   - `RAILWAY_TOKEN` - Railway deployment token
   - `CODECOV_TOKEN` - Codecov upload token (optional)

## Common Commands

```bash
# Run unit tests only
pytest -m unit -v

# Run integration tests only
pytest -m integration -v

# Run security tests only
pytest -m security -v

# Run tests in parallel (faster)
pytest -n auto

# Stop on first failure
pytest -x

# Rerun failed tests
pytest --lf

# Show slowest tests
pytest --durations=10

# Load testing
locust -f tests/load_test.py --host=http://localhost:8000
```

## Troubleshooting

### Tests Fail with "Database Connection Error"

```bash
# Ensure PostgreSQL is running
pg_isready

# Create test database
psql -U postgres -c "CREATE DATABASE tm_alert_test;"
```

### Tests Fail with "Redis Connection Error"

```bash
# Ensure Redis is running
redis-cli ping  # Should return: PONG

# Start Redis (macOS)
brew services start redis

# Start Redis (Linux)
sudo systemctl start redis
```

### Coverage is Below 85%

```bash
# Find uncovered files
pytest --cov=app --cov-report=term-missing

# Check specific file
coverage report -m app/core/security.py
```

### Import Errors

```bash
# Ensure you're in the project root
cd /path/to/Alert-system-backend

# Add to PYTHONPATH
export PYTHONPATH=$PYTHONPATH:$(pwd)
```

## Next Steps

1. **Read Full Documentation:**
   - `TESTING_STRATEGY.md` - Complete strategy
   - `TESTING_GUIDE.md` - Detailed how-to

2. **Add More Tests:**
   - Extend API tests to all endpoints
   - Add frontend tests
   - Create E2E tests with Playwright

3. **Monitor Quality:**
   - Set up Codecov integration
   - Review test coverage weekly
   - Run mutation testing monthly

## Get Help

- Check `TESTING_GUIDE.md` for detailed instructions
- Review test examples in `app/tests/`
- Run `./scripts/test.sh help` for test runner options

---

**Happy Testing! 🧪**
