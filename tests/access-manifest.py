"""Public CLI acceptance. Only synthetic secrets, isolated HOME and real daemon."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('session', ROOT / 'tests/daemon-cli.py')
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)
CLI = session.CLI

class Machine:
    def __init__(self, test):
        self.test = test
        self.temp = tempfile.TemporaryDirectory(prefix='sec-policy-', dir='/private/tmp')
        self.home = Path(self.temp.name)
        self.directory = self.home / '.secrets'
        self.directory.mkdir()
        (self.home / 'bin').mkdir()
        shutil.copy(ROOT / 'tests/fake-bw.py', self.home / 'bin/bw')
        (self.home / 'bin/bw').chmod(0o700)
        self.env = dict(os.environ, HOME=str(self.home), ZDOTDIR=str(self.home), SECRETS_HOME=str(self.directory), SECRETS_SOCKET=str(self.directory / 'daemon.sock'), BW_TEST_ROOT=str(self.home), PATH=f'{self.home}/bin:/usr/bin:/bin')
        for key in ['BW_SESSION', 'BW_PASSWORD', 'SECRETS_INJECTED']: self.env.pop(key, None)
        self.records = [
            {'name': 'alpha', 'fields': [{'name': 'token', 'value': 'synthetic-alpha-secret'}]},
            {'name': 'beta', 'fields': [{'name': 'token', 'value': 'synthetic-beta-secret'}]},
        ]
        self.provider()
        self.ok('trust', '--self')
        self.log = (self.home / 'daemon.log').open('wb')
        self.daemon = subprocess.Popen([str(session.DAEMON)], env=self.env, stdout=self.log, stderr=self.log)
        test.addCleanup(self.close)
        for _ in range(100):
            if (self.directory / 'daemon.sock').exists(): break
            time.sleep(.05)
        session.run_terminal(test, ['setup'], [(b'Choice', b'1'), (b'Server:', b'https://test.invalid'), (b'Email:', b'test@example.invalid'), (b'Password:', session.PASSWORD), (b'[Y/n]', b'n')], self.env)
    def provider(self):
        (self.home / 'records.json').write_text(json.dumps(self.records))
    def run(self, *args, env=None):
        return subprocess.run([str(CLI), *map(str, args)], env=env or self.env, capture_output=True, timeout=35)
    def ok(self, *args, env=None):
        r = self.run(*args, env=env)
        self.test.assertEqual(r.returncode, 0, r.stderr.decode(errors='replace'))
        return r
    def close(self):
        self.daemon.terminate(); self.daemon.wait(timeout=5)
        self.log.close(); self.temp.cleanup()

class AccessManifest(unittest.TestCase):
    def machine(self):
        import fcntl
        m=Machine(self)
        guard=(m.directory/'.background.lock').open('w'); fcntl.flock(guard,fcntl.LOCK_EX)
        self.addCleanup(guard.close)
        return m
    def wrap(self,m,code,*uses):
        f=m.home/'check.py'; f.write_text(code)
        return m.run('wrap','--file',f,'--use',*uses,'--','python3')
    def test_numeric_names_and_selected_collisions(self):
        m=self.machine()
        m.records=[{'name':name,'fields':[{'name':'api','value':'synthetic-value'}]} for name in ['2captcha','2captcha.com','a-b','a_b']]
        m.provider()
        for name in ['2captcha','2captcha.com','a-b','a_b']: m.ok('add',name)
        r=self.wrap(m,'import os; assert os.environ["2CAPTCHA_API"] == "synthetic-value"; assert "A_B_API" not in os.environ','2captcha:api')
        self.assertEqual(r.returncode,0,r.stderr)
        r=self.wrap(m,'print("CHILD_RAN")','a-b:api','a_b:api')
        self.assertNotEqual(r.returncode,0); self.assertNotIn(b'CHILD_RAN',r.stdout)
    def test_control_variables_and_duplicate_provider_fields(self):
        m=self.machine()
        m.records=[{'name':'secrets','fields':[{'name':'home','value':'synthetic-value'}]}]
        m.provider();m.ok('add','secrets')
        r=self.wrap(m,'print("CHILD_RAN")','secrets:home')
        self.assertNotEqual(r.returncode,0);self.assertNotIn(b'CHILD_RAN',r.stdout)
        before=(m.directory/'vault.enc').read_bytes()
        m.records[0]['fields'].append({'name':'home','value':'duplicate'})
        m.provider();self.assertNotEqual(m.run('sync','secrets').returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
    def test_transfer_preserves_keys_unrelated_fields_and_config(self):
        source=self.machine();source.ok('add','alpha');source.ok('add','beta')
        manifest=source.home/'refs.json';source.ok('manifest','export',manifest)
        data=manifest.read_bytes()
        for secret in [b'synthetic-alpha-secret',b'synthetic-beta-secret',session.PASSWORD,b'fixture-session']:self.assertNotIn(secret,data)
        self.assertEqual(manifest.stat().st_mode & 0o777,0o600)
        self.assertNotEqual(source.run('manifest','export',manifest).returncode,0)
        self.assertEqual(manifest.read_bytes(),data)
        target=self.machine()
        target.records[0]['fields'][0]['value']='synthetic-fresh'
        target.records.append({'name':'local','fields':[{'name':'only','value':'synthetic-local'}]})
        target.provider();target.ok('add','local')
        keys=(target.directory/'keys.json').read_bytes();config=(target.directory/'config.yaml').read_bytes()
        target.ok('manifest','apply',manifest)
        r=self.wrap(target,'import os; assert os.environ["ALPHA_TOKEN"] == "synthetic-fresh"; assert "BETA_TOKEN" not in os.environ','alpha:token')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual((target.directory/'keys.json').read_bytes(),keys)
        self.assertEqual((target.directory/'config.yaml').read_bytes(),config)
        roundtrip=target.home/'roundtrip.json';target.ok('manifest','export',roundtrip)
        self.assertIn({'item':'local','field':'only'},json.loads(roundtrip.read_bytes())['entries'])
    def test_invalid_manifest_and_partial_provider_failure_are_atomic(self):
        m=self.machine();m.ok('add','alpha');m.ok('add','beta')
        f=m.home/'refs.json';m.ok('manifest','export',f)
        original=json.loads(f.read_bytes());before=(m.directory/'vault.enc').read_bytes()
        for case in ['version','source','extra','duplicate','files-missing','duplicate-rule','relative-file','duplicate-path']:
            data=json.loads(json.dumps(original))
            if case=='version':data['version']=999
            if case=='source':data['source']['email']='wrong@example.invalid'
            if case=='extra':data['secret']='sensitive-must-not-echo'
            if case=='duplicate':data['entries'].append(data['entries'][0])
            if case=='files-missing':del data['access']['files']
            if case=='duplicate-rule':data['access']['files']=[{'item':'alpha','field':'token','files':[]}]*2
            if case=='duplicate-path':data['access']['files']=[{'item':'alpha','field':'token','files':['/tmp/test.py','/tmp/test.py']}]
            if case=='relative-file':data['access']['files']=[{'item':'alpha','field':'token','files':['relative.py']}]
            f.write_text(json.dumps(data));r=m.run('manifest','apply',f,'--dry-run')
            self.assertNotEqual(r.returncode,0,case);self.assertNotIn(b'sensitive-must-not-echo',r.stderr)
            self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        f.write_text(json.dumps(original));m.records[0]['fields'][0]['value']='new';m.records[1]['fields']=[];m.provider()
        self.assertNotEqual(m.run('manifest','apply',f).returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        m.ok('lock');calls=(m.home/'calls').read_text().splitlines()
        m.ok('manifest','apply',f,'--dry-run')
        recent=[json.loads(x)[0] for x in (m.home/'calls').read_text().splitlines()[len(calls):]]
        self.assertEqual(recent,['sync'])
    def test_legacy_duplicate_grants_and_untrusted_input_types(self):
        m=self.machine();m.ok('add','alpha')
        f=m.home/'refs.json';m.ok('manifest','export',f);data=json.loads(f.read_text())
        refs=[{'item':'alpha','field':'token'}]
        data['access']['grants']['python3']=refs*2;f.write_text(json.dumps(data))
        self.assertNotEqual(m.run('manifest','apply',f,'--dry-run').returncode,0)
        data['access']['grants']['python3']=refs
        text=json.dumps(data);needle='"python3": '+json.dumps(refs)
        f.write_text(text.replace(needle,needle+','+needle))
        self.assertNotEqual(m.run('manifest','apply',f,'--dry-run').returncode,0)
        fifo=m.home/'pipe.json';os.mkfifo(fifo)
        r=subprocess.run([str(CLI),'manifest','apply',str(fifo),'--dry-run'],env=m.env,capture_output=True,timeout=3)
        self.assertNotEqual(r.returncode,0)
        f.write_bytes(b' '*(1024*1024+1));self.assertNotEqual(m.run('manifest','apply',f,'--dry-run').returncode,0)
    def test_nested_wrap_cleans_env_and_preserves_child_exit(self):
        m=self.machine();m.ok('add','alpha');m.ok('add','beta')
        inner=m.home/'inner.py';inner.write_text('import os; assert "ALPHA_TOKEN" in os.environ; assert "BETA_TOKEN" not in os.environ')
        outer=m.home/'outer.py';outer.write_text('import os,subprocess; assert "BETA_TOKEN" in os.environ; subprocess.run('+repr([str(CLI),'wrap','--file',str(inner),'--use','alpha:token','--','python3'])+',check=True,timeout=10)')
        m.ok('wrap','--file',outer,'--use','alpha:token','beta:token','--','python3')
        inner.write_text('raise SystemExit(23)')
        self.assertEqual(m.run('wrap','--file',inner,'--','python3').returncode,23)

if __name__ == '__main__': unittest.main()
