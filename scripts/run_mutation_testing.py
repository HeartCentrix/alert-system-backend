"""
Mutation Testing Script

This script runs mutation testing on the codebase to verify test effectiveness.

Mutation testing works by:
1. Making small changes (mutations) to the code
2. Running tests against mutated code
3. If tests fail, mutation is "killed" (good)
4. If tests pass, mutation "survived" (bad - tests need improvement)

Usage:
    python scripts/run_mutation_testing.py
"""

import subprocess
import sys
import os
from pathlib import Path


def run_command(command, cwd=None):
    """Run shell command and return output."""
    print(f"Running: {command}")
    result = subprocess.run(
        command,
        shell=True,
        cwd=cwd,
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode, result.stdout


def check_mutmut_installed():
    """Check if mutmut is installed."""
    returncode, _ = run_command("mutmut --version")
    return returncode == 0


def install_mutmut():
    """Install mutmut."""
    print("Installing mutmut...")
    returncode, output = run_command("pip install mutmut")
    return returncode == 0


def run_mutation_testing(target_dir=None):
    """Run mutation testing."""
    print("=" * 80)
    print("Starting Mutation Testing")
    print("=" * 80)
    
    # Check/install mutmut
    if not check_mutmut_installed():
        if not install_mutmut():
            print("Failed to install mutmut")
            return False
    
    # Run mutation testing
    cmd = "mutmut run"
    if target_dir:
        cmd += f" --paths-to-mutate={target_dir}"
    
    returncode, output = run_command(cmd)
    
    if returncode != 0:
        print("Mutation testing completed with errors")
        return False
    
    return True


def show_mutation_results():
    """Show mutation testing results."""
    print("=" * 80)
    print("Mutation Testing Results")
    print("=" * 80)
    
    returncode, output = run_command("mutmut results")
    
    if returncode == 0:
        print(output)
    else:
        print("No mutation results found. Run 'mutmut run' first.")


def generate_mutation_report():
    """Generate mutation testing report."""
    print("=" * 80)
    print("Generating Mutation Report")
    print("=" * 80)
    
    # Run html report
    returncode, _ = run_command("mutmut junitxml --suspicious-policy=ignore --untested-policy=ignore")
    
    if returncode == 0:
        print("Mutation report generated: mutmut-results.xml")
    else:
        print("Failed to generate mutation report")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run mutation testing on TM Alert codebase")
    parser.add_argument(
        "--action",
        choices=["run", "results", "report", "all"],
        default="all",
        help="Action to perform"
    )
    parser.add_argument(
        "--target",
        type=str,
        default="app/core,app/services",
        help="Target modules to mutate (comma-separated)"
    )
    
    args = parser.parse_args()
    
    if args.action in ["run", "all"]:
        success = run_mutation_testing(args.target)
        if not success:
            sys.exit(1)
    
    if args.action in ["results", "all"]:
        show_mutation_results()
    
    if args.action in ["report", "all"]:
        generate_mutation_report()
    
    print("=" * 80)
    print("Mutation Testing Complete")
    print("=" * 80)


if __name__ == "__main__":
    main()
