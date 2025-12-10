#!/usr/bin/env python3
"""
AI Firewall System Validation Script

Checks that all components integrate correctly without breaking existing functionality.
Run this before deploying to production.
"""

import sys
import importlib
import logging
from pathlib import Path
from typing import List, Tuple

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("validator")


class SystemValidator:
    """Validates AI Firewall system integrity"""

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.successes: List[str] = []

    def validate_all(self) -> bool:
        """Run all validation checks"""
        print("\n" + "=" * 70)
        print("  AI FIREWALL SYSTEM VALIDATION")
        print("=" * 70 + "\n")

        # Core checks
        self._check_python_version()
        self._check_file_structure()
        self._check_imports()
        self._check_env_file()
        self._check_dependencies()
        self._check_backward_compatibility()

        # Print results
        self._print_results()

        return len(self.errors) == 0

    def _check_python_version(self):
        """Verify Python 3.8+"""
        version = sys.version_info
        if version.major >= 3 and version.minor >= 8:
            self.successes.append(f"Python version: {version.major}.{version.minor}")
        else:
            self.errors.append(f"Python 3.8+ required, found {version.major}.{version.minor}")

    def _check_file_structure(self):
        """Verify all required files exist"""
        required_files = [
            "ai_firewall_updater.py",
            "soar_ai_integration.py",
            "requirements.txt",
            ".env.example",
            "start.sh",
            "stop.sh",
            "setup_linux.sh",
            "README.md",
        ]

        for file in required_files:
            path = Path(file)
            if path.exists():
                self.successes.append(f"File found: {file}")
            else:
                self.errors.append(f"Missing required file: {file}")

    def _check_imports(self):
        """Verify Python modules can be imported"""
        modules = [
            ("ai_firewall_updater", "AI Firewall Updater"),
            ("soar_ai_integration", "SOAR-AI Integration"),
            ("unified_logger", "Unified Logger (existing)"),
            ("soar_engine", "SOAR Engine (existing)"),
        ]

        for module_name, display_name in modules:
            try:
                spec = importlib.util.find_spec(module_name)
                if spec and spec.origin:
                    self.successes.append(f"Import OK: {display_name}")
                else:
                    self.warnings.append(f"Import warning: {display_name} not found in standard paths")
            except Exception as e:
                self.warnings.append(f"Import check failed for {display_name}: {e}")

    def _check_env_file(self):
        """Verify .env configuration"""
        env_file = Path(".env")
        env_example = Path(".env.example")

        if env_example.exists():
            self.successes.append("File found: .env.example")
        else:
            self.errors.append("Missing: .env.example")

        if env_file.exists():
            content = env_file.read_text()
            if "GOOGLE_API_KEY=" in content:
                self.successes.append("API key configuration found in .env")
            else:
                self.warnings.append(".env file exists but missing GOOGLE_API_KEY")

            # Check permissions
            import stat

            mode = env_file.stat().st_mode
            if mode & stat.S_IROTH:
                self.warnings.append(".env has world-readable permissions (should be 600)")
        else:
            self.warnings.append(".env file not found (copy from .env.example)")

    def _check_dependencies(self):
        """Verify required Python packages can be imported"""
        packages = [
            ("google.generativeai", "Google Generative AI (Gemini)"),
            ("confluent_kafka", "Confluent Kafka"),
            ("numpy", "NumPy"),
            ("sklearn", "scikit-learn"),
            ("joblib", "joblib"),
            ("yaml", "PyYAML"),
            ("requests", "requests"),
            ("scapy", "Scapy"),
        ]

        for package_name, display_name in packages:
            try:
                module = importlib.import_module(package_name)
                version = getattr(module, "__version__", "unknown")
                self.successes.append(f"Package OK: {display_name} ({version})")
            except ImportError:
                self.warnings.append(f"Package not installed: {display_name}")
                self.warnings.append(f"  → Install with: pip install {package_name}")

    def _check_backward_compatibility(self):
        """Verify no breaking changes to existing components"""
        checks = [
            self._check_start_sh_integration,
            self._check_stop_sh_integration,
            self._check_setup_sh_integration,
            self._check_soar_compatibility,
            self._check_log_compatibility,
        ]

        for check in checks:
            try:
                check()
            except Exception as e:
                self.errors.append(f"Compatibility check failed: {e}")

    def _check_start_sh_integration(self):
        """Verify start.sh has correct integration (on-demand, not daemon)"""
        start_sh = Path("start.sh").read_text()

        checks = [
            ("SOAR" in start_sh, "SOAR engine in startup"),
            ("AI RULE GENERATION" in start_sh or "AI" in start_sh, "AI rule note in startup"),
            ("[4/6]" in start_sh, "Updated step count (no AI daemon)"),
        ]

        for condition, message in checks:
            if condition:
                self.successes.append(message)
            else:
                self.warnings.append(f"Startup check: {message}")

    def _check_stop_sh_integration(self):
        """Verify stop.sh no longer tries to stop AI daemon"""
        stop_sh = Path("stop.sh").read_text()

        checks = [
            ("ai_firewall_updater.py" not in stop_sh, "AI daemon NOT in stop.sh (on-demand only)"),
            ("[6/6]" in stop_sh, "Correct step count (no AI daemon)"),
        ]

        for condition, message in checks:
            if condition:
                self.successes.append(message)
            else:
                self.warnings.append(f"Shutdown check: {message}")

    def _check_setup_sh_integration(self):
        """Verify setup_linux.sh installs new dependencies"""
        setup_sh = Path("setup_linux.sh").read_text()

        if "google-generativeai" in setup_sh:
            self.successes.append("google-generativeai in setup_linux.sh")
        else:
            self.errors.append("google-generativeai not in setup_linux.sh pip install")

    def _check_soar_compatibility(self):
        """Verify SOAR engine has AI integration hooks"""
        soar_integration_file = Path("soar_ai_integration.py")

        if soar_integration_file.exists():
            self.successes.append("SOAR-AI integration module present")
            
            content = soar_integration_file.read_text()
            if "queue_threat" in content:
                self.successes.append("Async queue mechanism implemented")
            else:
                self.warnings.append("queue_threat method not found in integration")
        else:
            self.errors.append("soar_ai_integration.py not found")

    def _check_log_compatibility(self):
        """Verify logs directory structure"""
        logs_dir = Path("logs")

        if not logs_dir.exists():
            logger.info("Creating logs directory...")
            logs_dir.mkdir(exist_ok=True)

        required_subdirs = ["rules_backup"]

        for subdir in required_subdirs:
            subdir_path = logs_dir / subdir
            if not subdir_path.exists():
                subdir_path.mkdir(parents=True, exist_ok=True)
                self.successes.append(f"Created directory: logs/{subdir}")
            else:
                self.successes.append(f"Directory exists: logs/{subdir}")

    def _print_results(self):
        """Print validation results"""
        print("\n" + "=" * 70)
        print("  RESULTS")
        print("=" * 70)

        if self.successes:
            print(f"\n✅ PASSED ({len(self.successes)}):")
            for msg in self.successes:
                print(f"   ✓ {msg}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for msg in self.warnings:
                print(f"   ⚠ {msg}")

        if self.errors:
            print(f"\n❌ FAILED ({len(self.errors)}):")
            for msg in self.errors:
                print(f"   ✗ {msg}")

        print("\n" + "=" * 70)

        if self.errors:
            print("  STATUS: VALIDATION FAILED")
            print("  Please fix the errors above before deployment.")
        elif self.warnings:
            print("  STATUS: VALIDATION PASSED (with warnings)")
            print("  System is functional but consider addressing warnings.")
        else:
            print("  STATUS: VALIDATION SUCCESSFUL")
            print("  System is ready for deployment.")

        print("=" * 70 + "\n")


def main():
    validator = SystemValidator()
    success = validator.validate_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
