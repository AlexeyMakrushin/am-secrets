"""A real signed CLI and Swift daemon, test bw, isolated files, no real vault."""
import json
import os
from pathlib import Path
import pty
import select
import shutil
import socket
import struct
import subprocess
import time
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'secrets-cli/target/debug/secrets'
DAEMON = ROOT / 'secrets-daemon/.build/debug/secrets-daemon'
PASSWORD = b'fixture-master-password'

def run_terminal(test, args, answers, env, expected=0):
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(str(CLI), [str(CLI), *args], env)
    data = b''
    start = time.monotonic()
    try:
        for needle, answer in answers:
            while needle not in data:
                if time.monotonic() - start > 45: test.fail('Timed out awaiting prompt: ' + needle.decode())
                if select.select([fd], [], [], .1)[0]:
                    try: data += os.read(fd, 65536)
                    except OSError: test.fail('Terminal closed before prompt: ' + needle.decode())
            # Never type before rpassword disables echo.
            time.sleep(.1)
            os.write(fd, answer + b'\n')
            data = b''
        while time.monotonic() - start < 50:
            if select.select([fd], [], [], .1)[0]:
                try:
                    chunk = os.read(fd, 65536)
                    if not chunk: break
                    data += chunk
                except OSError: break
        _, status = os.waitpid(pid, 0)
        test.assertEqual(os.waitstatus_to_exitcode(status), expected, data.decode(errors='replace').replace(PASSWORD.decode(), '[REDACTED]'))
        test.assertNotIn(PASSWORD, data)
        return data
    finally:
        os.close(fd)

class DaemonCLI(unittest.TestCase):
    def test_complete_session(self):
        with tempfile.TemporaryDirectory(prefix='sec-', dir='/private/tmp') as temp:
            home = Path(temp)
            directory = home / '.secrets'
            directory.mkdir()
            import fcntl
            background_guard=(directory/'.background.lock').open('w')
            fcntl.flock(background_guard,fcntl.LOCK_EX)
            (home / 'bin').mkdir()
            shutil.copy(ROOT / 'tests/fake-bw.py', home / 'bin/bw')
            (home / 'bin/bw').chmod(0o700)
            env = dict(os.environ, HOME=str(home), ZDOTDIR=str(home), SECRETS_HOME=str(directory), SECRETS_SOCKET=str(directory / 'daemon.sock'), BW_TEST_ROOT=str(home), PATH=f'{home}/bin:/usr/bin:/bin')
            env.pop('BW_SESSION', None)
            env.pop('BW_PASSWORD', None)
            def run(*args):
                return subprocess.run([str(CLI), *args], env=env, capture_output=True, timeout=35)
            trust = run('trust', '--self')
            self.assertEqual(trust.returncode, 0, trust.stderr)
            log = (home / 'daemon.log').open('wb')
            daemon = subprocess.Popen([str(DAEMON)], env=env, stdout=log, stderr=log)
            def wait_socket():
                for _ in range(100):
                    if (directory / 'daemon.sock').exists(): return
                    if daemon.poll() is not None: self.fail('Daemon exited before startup: ' + (home / 'daemon.log').read_text())
                    time.sleep(.05)
                self.fail('Daemon did not start')
            def terminal(args, answers):
                return run_terminal(self, args, answers, env)
            try:
                wait_socket()
                with socket.socket(socket.AF_UNIX) as untrusted:
                    untrusted.connect(str(directory / 'daemon.sock'))
                    request = json.dumps({'v': 2, 'cmd': 'GET_STATE', 'context': 'untrusted'}).encode()
                    untrusted.sendall(struct.pack('>I', len(request)) + request)
                    untrusted.shutdown(socket.SHUT_WR)
                    stream = untrusted.makefile('rb')
                    size = struct.unpack('>I', stream.read(4))[0]
                    reply = json.loads(stream.read(size))
                    self.assertEqual(reply.get('code'), 'UNAUTHORIZED')
                    self.assertNotIn('masterKey', reply)
                    self.assertNotIn('providerSession', reply)
                setup_prompts = [
                    (b'Choice', b'1'),
                    (b'Server:', b'https://test.invalid'),
                    (b'Email:', b'test@example.invalid'),
                ]
                run_terminal(self, ['setup'], [*setup_prompts, (b'Password:', b'wrong-fixture-password')], env, expected=6)
                for name in ('config.yaml', 'keys.json', 'vault.enc'):
                    self.assertFalse((directory / name).exists(), name)
                self.assertFalse((home / '.zshrc').exists())
                (home / 'mode').write_text('logged-out')
                terminal(['setup'], [*setup_prompts, (b'Password:', PASSWORD), (b'[Y/n]', b'')])
                self.assertTrue((home / 'login-complete').exists())
                shell = (home / '.zshrc').read_text()
                self.assertIn('export PATH=', shell)
                self.assertNotIn('eval ', shell, 'setup default must only add PATH')
                result = run('add', 'test-app', 'token')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(b'fixture-token', result.stdout + result.stderr)
                result = run('ls')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b'test-app', result.stdout)
                self.assertEqual(sum(json.loads(x)[0] == 'unlock' for x in (home / 'calls').read_text().splitlines()), 1)
                self.assertEqual(sum(json.loads(x)[0] == 'login' for x in (home / 'calls').read_text().splitlines()), 1)
                config = directory / 'config.yaml'
                original_config = config.read_text()
                config.write_text(original_config.replace('test@example.invalid', 'another@example.invalid'))
                self.assertNotEqual(run('ls').returncode, 0, 'Different account must not reuse key')
                config.write_text(original_config)
                self.assertEqual(run('ls').returncode, 0)
                (home / 'mode').write_text('revoked')
                calls_before = (home / 'calls').read_text().count('list')
                self.assertNotEqual(run('sync').returncode, 0, 'Revoked session requires human unlock')
                self.assertEqual((home / 'calls').read_text().count('list'), calls_before)
                self.assertEqual(run('ls').returncode, 0, 'Local key survives provider revocation')
                (home / 'mode').write_text('')
                before = (directory / 'vault.enc').read_bytes()
                (home / 'mode').write_text('missing-field')
                result = run('sync')
                self.assertNotEqual(result.returncode, 0, 'Missing field must not be success')
                self.assertEqual((directory / 'vault.enc').read_bytes(), before)
                for mode in ['missing-item', 'duplicate']:
                    (home / 'mode').write_text(mode)
                    self.assertNotEqual(run('sync').returncode, 0)
                    self.assertEqual((directory / 'vault.enc').read_bytes(), before)
                (home / 'mode').write_text('offline')
                result = run('ls')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b'test network unavailable', result.stderr)
                result = run('sync')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((directory / 'vault.enc').read_bytes(), before)
                before_lock = (home / 'calls').read_bytes()
                self.assertEqual(run('lock').returncode, 0)
                self.assertEqual((home / 'calls').read_bytes(), before_lock)
                self.assertNotEqual(run('ls').returncode, 0)
                self.assertNotEqual(run('wrap', '/usr/bin/python3', '-c', 'pass').returncode, 0, 'Locked wrap must not launch')
                (home / 'mode').write_text('')
                terminal(['unlock'], [(b'Master password:', PASSWORD)])
                self.assertEqual(run('ls').returncode, 0)
                daemon.terminate(); daemon.wait(timeout=5)
                daemon = subprocess.Popen([str(DAEMON)], env=env, stdout=log, stderr=log)
                wait_socket()
                self.assertNotEqual(run('ls').returncode, 0, 'New daemon must start locked')
                for file in home.rglob('*'):
                    if file.is_file() and file.parent != home / "bin":
                        content = file.read_bytes()
                        self.assertNotIn(PASSWORD, content, str(file))
                        self.assertNotIn(b'fixture-session', content, str(file))
                self.assertFalse((directory / '.bw_session').exists())
            finally:
                daemon.terminate()
                daemon.wait(timeout=5)
                log.close()
                background_guard.close()

if __name__ == '__main__': unittest.main()
