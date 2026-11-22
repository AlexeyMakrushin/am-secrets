"""Legacy-vault acceptance with fake daemon: NEVER accesses macOS Keychain."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('acceptance', ROOT / 'tests/daemon-cli.py')
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)

class FakeDaemon:
    def __init__(self, path, deny_cleanup=False):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(str(path)); self.socket.listen()
        self.socket.settimeout(.1)
        self.stop = False; self.commands = []; self.deny = deny_cleanup; self.state = None
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
    def serve(self):
        while not self.stop:
            try: connection, _ = self.socket.accept()
            except socket.timeout: continue
            except OSError: return
            with connection:
                stream = connection.makefile('rb')
                size = struct.unpack('>I', stream.read(4))[0]
                req = json.loads(stream.read(size))
                cmd = req['cmd']; self.commands.append(cmd)
                reply = {'v': 2, 'status': 'ok'}
                if cmd == 'GET_STATE':
                    reply.update(status='error', code='SESSION_EXPIRED')
                elif cmd == 'RETIRE_LEGACY_PIN' and self.deny:
                    reply.update(status='error', code='KEYCHAIN_ERROR', message='synthetic cleanup denied')
                elif cmd == 'SET_STATE': self.state = req
                data = json.dumps(reply).encode()
                connection.sendall(struct.pack('>I', len(data)) + data)
    def close(self):
        self.stop = True; self.thread.join(timeout=2); self.socket.close()

class Migration(unittest.TestCase):
    def test_legacy_migration_failures_and_success(self):
        with tempfile.TemporaryDirectory(prefix='sec-mig-', dir='/private/tmp') as temp:
            root = Path(temp); fixture = root / 'fixture'
            result = subprocess.run(['cargo', 'test', '--offline', '--manifest-path', str(ROOT / 'secrets-cli/Cargo.toml'), 'old_pin_vault_survives'], env=dict(os.environ, SECRETS_TEST_FIXTURE=str(fixture)), capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            for case in ['wrong-password', 'corrupt-vault', 'cleanup-denied', 'keys-write-denied', 'success']:
                with self.subTest(case=case):
                    home = root / case; directory = home / '.secrets'; directory.mkdir(parents=True)
                    for name in ['keys.json', 'vault.enc']: shutil.copy(fixture / name, directory / name)
                    (home / 'bin').mkdir(); shutil.copy(ROOT / 'tests/fake-bw.py', home / 'bin/bw'); (home / 'bin/bw').chmod(0o700)
                    (directory / 'config.yaml').write_text('provider: bitwarden\nbitwarden:\n  email: test@example.invalid\n  server: https://test.invalid\ndaemon:\n  auto_start: false\n  socket: ' + str(home / 'daemon.sock') + '\n')
                    if case == 'corrupt-vault': (directory / 'vault.enc').write_bytes(b'corrupted synthetic vault')
                    original_keys = (directory / 'keys.json').read_bytes(); original_vault = (directory / 'vault.enc').read_bytes()
                    env = dict(os.environ, HOME=str(home), ZDOTDIR=str(home), SECRETS_HOME=str(directory), BW_TEST_ROOT=str(home), PATH=f'{home}/bin:/usr/bin:/bin')
                    daemon = FakeDaemon(home / 'daemon.sock', case == 'cleanup-denied')
                    if case == 'keys-write-denied':
                        (directory / '.command.lock').touch()
                        directory.chmod(0o500)
                    try:
                        password = b'wrong-password' if case == 'wrong-password' else acceptance.PASSWORD
                        expected = {'wrong-password': 5, 'corrupt-vault': 5, 'cleanup-denied': 1, 'keys-write-denied': 5, 'success': 0}[case]
                        acceptance.run_terminal(self, ['unlock'], [(b'Master password:', password)], env, expected)
                        self.assertEqual((directory / 'vault.enc').read_bytes(), original_vault)
                        if case == 'success':
                            self.assertNotIn('wrap_pin', json.loads((directory / 'keys.json').read_bytes()))
                            self.assertLess(daemon.commands.index('RETIRE_LEGACY_PIN'), daemon.commands.index('SET_STATE'))
                            self.assertIsNotNone(daemon.state)
                            retired = daemon.commands.count('RETIRE_LEGACY_PIN')
                            acceptance.run_terminal(self, ['unlock'], [(b'Master password:', acceptance.PASSWORD)], env)
                            self.assertEqual(daemon.commands.count('RETIRE_LEGACY_PIN'), retired)
                            shown = acceptance.run_terminal(self, ['access', 'show'], [(b'Master password:', acceptance.PASSWORD)], env)
                            self.assertIn(b'explicit fields only', shown)
                        else:
                            self.assertEqual((directory / 'keys.json').read_bytes(), original_keys)
                            self.assertNotIn('SET_STATE', daemon.commands)
                            if case == 'keys-write-denied': self.assertIn('RETIRE_LEGACY_PIN', daemon.commands)
                            if case not in ['cleanup-denied', 'keys-write-denied']: self.assertNotIn('RETIRE_LEGACY_PIN', daemon.commands)
                    finally:
                        directory.chmod(0o700)
                        daemon.close()

if __name__ == '__main__': unittest.main()
