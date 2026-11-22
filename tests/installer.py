"""Installer readiness check only: no installation, real socket or real HOME."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Installer(unittest.TestCase):
    def test_shell_integration_is_path_only(self):
        with tempfile.TemporaryDirectory() as temp:
            rc = Path(temp) / '.zshrc'
            rc.write_text('export USER_SETTING=kept\n# >>> ai-secrets >>>\nexport PATH="$HOME/.secrets:$PATH"\neval "$(~/.secrets/secrets whitelist)"\n# <<< ai-secrets <<<\n')
            env = dict(os.environ, HOME=temp, ZDOTDIR=temp)
            result = subprocess.run(['bash', '-c', 'source ./install.sh; add_shell_integration; add_shell_integration'], cwd=ROOT, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            content = rc.read_text()
            self.assertIn('export USER_SETTING=kept', content)
            self.assertEqual(content.count('export PATH="$HOME/.secrets:$PATH"'), 1)
            self.assertNotIn('secrets whitelist', content)

    def test_shell_integration_preserves_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'shell-settings'
            target.write_text('# >>> ai-secrets >>>\nold-wrapper\n# <<< ai-secrets <<<\nexport USER_SETTING=kept\n')
            rc = Path(temp) / '.zshrc'
            rc.symlink_to(target.name)
            env = dict(os.environ, HOME=temp, ZDOTDIR=temp)
            result = subprocess.run(['bash', '-c', 'source ./install.sh; add_shell_integration'], cwd=ROOT, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(rc.is_symlink())
            self.assertIn('export USER_SETTING=kept', target.read_text())
            self.assertNotIn('old-wrapper', target.read_text())

    def test_incomplete_shell_markers_preserve_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            rc = Path(temp) / '.zshrc'
            original = '# >>> ai-secrets >>>\nexport USER_SETTING=kept\n'
            rc.write_text(original)
            env = dict(os.environ, HOME=temp, ZDOTDIR=temp)
            result = subprocess.run(['bash', '-c', 'source ./install.sh; add_shell_integration'], cwd=ROOT, env=env, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(rc.read_text(), original)

    def test_replaces_legacy_crlf_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            rc = Path(temp) / '.zshrc'
            rc.write_bytes(b'export USER_SETTING=kept\r\n# >>> ai-secrets >>>\r\nold-wrapper\r\n# <<< ai-secrets <<<\r\n')
            env = dict(os.environ, HOME=temp, ZDOTDIR=temp)
            result = subprocess.run(['bash', '-c', 'source ./install.sh; add_shell_integration'], cwd=ROOT, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            content = rc.read_bytes()
            self.assertIn(b'export USER_SETTING=kept\r\n', content)
            self.assertNotIn(b'old-wrapper', content)
            self.assertEqual(content.count(b'# >>> ai-secrets >>>'), 1)

    def test_waits_for_daemon_readiness(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            nc = directory / 'nc'
            nc.write_text('#!/bin/sh\nif [ ! -e "$TEST_ROOT/attempted" ]; then touch "$TEST_ROOT/attempted"; exit 1; fi\nprintf \'%s\\n\' \'{"v":2,"status":"alive"}\'\n')
            nc.chmod(0o700)
            cli = directory / 'secrets'
            cli.write_text('#!/bin/sh\necho "secrets 3.1.0"\n')
            cli.chmod(0o700)
            env = dict(os.environ, HOME=temp, ZDOTDIR=temp, TEST_ROOT=temp, PATH=f'{temp}:/usr/bin:/bin')
            result = subprocess.run(['bash', '-c', 'source ./install.sh; SECRETS_DIR="$TEST_ROOT"; NC_AVAILABLE=true; verify_installation'], cwd=ROOT, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue((directory / 'attempted').exists())
            self.assertIn(b'Daemon PING:', result.stdout)
            self.assertNotIn(b'FAILED', result.stdout)

if __name__ == '__main__': unittest.main()
