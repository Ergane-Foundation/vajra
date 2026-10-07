"""Tests for shared logging configuration and log directory initialization."""

import logging
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure src is in pythonpath if running directly
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vajra.common.logging import setup_logging


class TestLoggingSetup(unittest.TestCase):
    def test_setup_logging_creates_logs_directory(self):
        tmp_dir = tempfile.mkdtemp()
        try:
            logs_dir = Path(tmp_dir) / "custom_logs"
            self.assertFalse(logs_dir.exists())

            log_file = logs_dir / "test_service.log"
            logger = setup_logging("test_service", log_file=log_file)

            self.assertIsInstance(logger, logging.Logger)
            self.assertTrue(logs_dir.exists())
            self.assertTrue(logs_dir.is_dir())

            logger.info("Test message from setup_logging")

            # Flush and close handlers so file is closed cleanly on Windows
            handlers = list(logger.handlers) + list(logging.root.handlers)
            for h in handlers:
                if isinstance(h, logging.FileHandler):
                    h.flush()
                    h.close()
                    logger.removeHandler(h)
                    logging.root.removeHandler(h)

            self.assertTrue(log_file.exists())
            self.assertIn("Test message from setup_logging", log_file.read_text())
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_import_soar_engine_loads_cleanly(self):
        import vajra.soar.engine

        self.assertTrue(hasattr(vajra.soar.engine, "SOAREngine"))


if __name__ == "__main__":
    unittest.main()
