import unittest
from pathlib import Path
from didis import __version__

class ReleaseContract(unittest.TestCase):
    def test_release_migration_metadata(self) -> None:
        root = Path(__file__).resolve().parent.parent
        readme = (root / 'README.md').read_text()
        changelog = (root / 'CHANGELOG.md').read_text()
        self.assertEqual(__version__, '0.2.8')
        self.assertIn('## [0.2.8] - 2026-11-17', changelog)
        self.assertNotIn('Source-only', changelog)
        self.assertIn('not a backward-compatible patch', changelog)
        self.assertIn('Python retains its Optional annotation but validates it at runtime', readme)
        self.assertIn('requested reviewed pins only', readme)
        self.assertIn('Missing/unparseable expiry retains TTL-only behavior', readme)
        self.assertNotIn('Unreleased checkout migration', readme)
