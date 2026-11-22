"""CLI acceptance using synthetic bw and an isolated HOME; never real credentials."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'secrets-cli/target/debug/secrets'

class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='secrets-test-')
        self.home = Path(self.temp.name)
        self.bin = self.home / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), ZDOTDIR=str(self.home), PATH=f'{self.bin}:/usr/bin:/bin', BW_TEST_LOG=str(self.home / 'calls'))
        self.env.pop('BW_SESSION', None)
        self.env.pop('BW_PASSWORD', None)
        self.env['SECRETS_HOME'] = str(self.home / '.secrets')
        self.env['SECRETS_SOCKET'] = str(self.home / '.secrets/daemon.sock')
        (self.home / '.secrets').mkdir()
        (self.home / '.secrets/config.yaml').write_text('provider: bitwarden\ndaemon:\n  auto_start: false\n')
        bw = self.bin / 'bw'
        bw.write_text('#!/usr/bin/python3\nimport os,sys,json\nwith open(os.environ["BW_TEST_LOG"],"a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\nif sys.argv[1] == "sync":\n print("test network unavailable",file=sys.stderr); sys.exit(1)\nprint("{}")\n')
        bw.chmod(0o700)
    def tearDown(self):
        self.temp.cleanup()
    def run_cli(self, *args):
        return subprocess.run([str(CLI), *args], env=self.env, capture_output=True, text=True, timeout=30)
    def calls(self):
        p = self.home / 'calls'
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
    def test_sync_before_whitelist_and_error_on_stderr(self):
        result = self.run_cli('whitelist')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[0], ['sync'])
        self.assertIn('test network unavailable', result.stderr)
        self.assertNotIn('test network unavailable', result.stdout)

    def test_each_command_attempts_sync(self):
        commands = [('status',), ('ls',), ('get', 'test', 'field'), ('wrap', '/usr/bin/true'),
                    ('add', 'test'), ('sync',), ('delete', 'test'), ('setup',),
                    ('trust',), ('whitelist',), ('unlock',),
                    ('access', 'show'), ('access', 'reset-legacy'), ('access', 'open', 'test:field'),
                    ('access', 'revoke', 'test:field', '--file', '/tmp/test.py'), ('manifest', 'export', 'unused.json'),
                    ('manifest', 'apply', 'missing.json', '--dry-run')]
        for command in commands:
            with self.subTest(command=command):
                log = self.home / 'calls'
                log.unlink(missing_ok=True)
                result = self.run_cli(*command)
                self.assertEqual(self.calls()[0], ['sync'])
                self.assertIn('test network unavailable', result.stderr)
                if command[0] in ('add', 'sync') or command[:2] == ('manifest', 'apply'):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.calls(), [['sync']])

    def test_lock_does_not_contact_provider(self):
        self.run_cli('lock')
        self.assertEqual(self.calls(), [])

if __name__ == '__main__':
    unittest.main()
