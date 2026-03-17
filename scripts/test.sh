#!/bin/bash
# =============================================================================
# TM Alert - Test Runner Script
# 
# Usage:
#   ./scripts/test.sh                    # Run all tests
#   ./scripts/test.sh unit              # Run unit tests only
#   ./scripts/test.sh integration       # Run integration tests only
#   ./scripts/test.sh security          # Run security tests only
#   ./scripts/test.sh coverage          # Run with coverage report
#   ./scripts/test.sh ci                # Run in CI mode
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Default values
TEST_TYPE="${1:-all}"
COVERAGE="${2:-false}"
PARALLEL="${3:-false}"
VERBOSE="${4:-false}"

# Functions
print_header() {
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=================================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

check_python() {
    if ! command -v python &> /dev/null; then
        print_error "Python is not installed or not in PATH"
        exit 1
    fi
    print_success "Python found: $(python --version)"
}

check_dependencies() {
    print_info "Checking dependencies..."
    if [ ! -d "venv" ]; then
        print_error "Virtual environment not found. Run: python -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
    print_success "Dependencies OK"
}

setup_test_database() {
    print_info "Setting up test database..."
    # Create test database if it doesn't exist
    psql -U postgres -c "CREATE DATABASE tm_alert_test;" 2>/dev/null || true
    print_success "Test database ready"
}

run_unit_tests() {
    print_header "Running Unit Tests"
    
    if [ "$COVERAGE" = "true" ]; then
        pytest app/tests/unit \
            --cov=app \
            --cov-report=term-missing \
            --cov-report=html:htmlcov/unit \
            -v \
            -m unit \
            ${VERBOSE:+-vv} \
            ${PARALLEL:+-n auto}
    else
        pytest app/tests/unit \
            -v \
            -m unit \
            ${VERBOSE:+-vv} \
            ${PARALLEL:+-n auto}
    fi
    
    print_success "Unit Tests Complete"
}

run_integration_tests() {
    print_header "Running Integration Tests"
    
    export USE_POSTGRES_FOR_TESTS=true
    export TEST_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/tm_alert_test"
    
    if [ "$COVERAGE" = "true" ]; then
        pytest app/tests/integration \
            --cov=app \
            --cov-report=term-missing \
            --cov-report=html:htmlcov/integration \
            -v \
            -m integration \
            ${VERBOSE:+-vv}
    else
        pytest app/tests/integration \
            -v \
            -m integration \
            ${VERBOSE:+-vv}
    fi
    
    print_success "Integration Tests Complete"
}

run_api_tests() {
    print_header "Running API Tests"
    
    if [ "$COVERAGE" = "true" ]; then
        pytest app/tests/api \
            --cov=app \
            --cov-report=term-missing \
            --cov-report=html:htmlcov/api \
            -v \
            -m api \
            ${VERBOSE:+-vv}
    else
        pytest app/tests/api \
            -v \
            -m api \
            ${VERBOSE:+-vv}
    fi
    
    print_success "API Tests Complete"
}

run_security_tests() {
    print_header "Running Security Tests"
    
    if [ "$COVERAGE" = "true" ]; then
        pytest app/tests/security \
            --cov=app \
            --cov-report=term-missing \
            --cov-report=html:htmlcov/security \
            -v \
            -m security \
            ${VERBOSE:+-vv}
    else
        pytest app/tests/security \
            -v \
            -m security \
            ${VERBOSE:+-vv}
    fi
    
    print_success "Security Tests Complete"
}

run_property_tests() {
    print_header "Running Property-Based Tests"
    
    pytest app/tests/property \
        -v \
        --hypothesis-examples=100 \
        ${VERBOSE:+-vv}
    
    print_success "Property Tests Complete"
}

run_fuzz_tests() {
    print_header "Running Fuzz Tests"
    
    pytest app/tests/fuzz \
        -v \
        --hypothesis-examples=200 \
        ${VERBOSE:+-vv}
    
    print_success "Fuzz Tests Complete"
}

run_security_scan() {
    print_header "Running Security Scans"
    
    print_info "Running Bandit..."
    bandit -r app/ --severity-level high --confidence-level high || true
    
    print_info "Running Safety..."
    safety check || true
    
    print_info "Running Ruff..."
    ruff check app/
    
    print_success "Security Scans Complete"
}

generate_coverage_report() {
    print_header "Generating Coverage Report"
    
    # Combine all coverage reports
    coverage combine || true
    coverage html -d htmlcov
    coverage xml -o coverage.xml
    
    print_success "Coverage Report: htmlcov/index.html"
    print_info "Open with: open htmlcov/index.html"
}

run_all_tests() {
    print_header "Running All Tests"
    
    start_time=$(date +%s)
    
    # Run tests in order
    run_unit_tests
    run_integration_tests
    run_api_tests
    run_security_tests
    run_property_tests
    run_fuzz_tests
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    print_success "All Tests Complete (${duration}s)"
    
    if [ "$COVERAGE" = "true" ]; then
        generate_coverage_report
    fi
}

run_ci_mode() {
    print_header "CI Mode"
    
    # Fail-fast mode
    set -e
    
    # Run security scans first
    run_security_scan
    
    # Run all tests with coverage
    run_all_tests
    
    # Check coverage threshold
    print_info "Checking coverage threshold..."
    coverage report --fail-under=85 || {
        print_error "Coverage below 85% threshold!"
        exit 1
    }
    
    print_success "CI Checks Passed"
}

show_help() {
    echo "TM Alert Test Runner"
    echo ""
    echo "Usage: ./scripts/test.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  unit          Run unit tests only"
    echo "  integration   Run integration tests only"
    echo "  api           Run API tests only"
    echo "  security      Run security tests only"
    echo "  property      Run property-based tests"
    echo "  fuzz          Run fuzz tests"
    echo "  scan          Run security scans"
    echo "  coverage      Generate coverage report"
    echo "  ci            Run in CI mode (fail-fast)"
    echo "  all           Run all tests (default)"
    echo "  help          Show this help"
    echo ""
    echo "Examples:"
    echo "  ./scripts/test.sh                    # Run all tests"
    echo "  ./scripts/test.sh unit coverage      # Run unit tests with coverage"
    echo "  ./scripts/test.sh ci                 # Run in CI mode"
    echo ""
}

# Main execution
main() {
    print_header "TM Alert Test Suite"
    
    check_python
    check_dependencies
    
    case "$TEST_TYPE" in
        unit)
            run_unit_tests
            ;;
        integration)
            setup_test_database
            run_integration_tests
            ;;
        api)
            run_api_tests
            ;;
        security)
            run_security_tests
            ;;
        property)
            run_property_tests
            ;;
        fuzz)
            run_fuzz_tests
            ;;
        scan)
            run_security_scan
            ;;
        coverage)
            run_all_tests
            generate_coverage_report
            ;;
        ci)
            run_ci_mode
            ;;
        all)
            run_all_tests
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown option: $TEST_TYPE"
            show_help
            exit 1
            ;;
    esac
    
    print_header "Done"
}

# Run main function
main
