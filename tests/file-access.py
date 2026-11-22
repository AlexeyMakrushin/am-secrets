"""CLI acceptance for explicit fields and file identities; synthetic data only."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('policy', ROOT / 'tests/access-manifest.py')
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)

class FileAccess(unittest.TestCase):
    def machine(self):
        m = policy.Machine(self)
        import fcntl
        m.background_lock=(m.directory/'.background.lock').open('w')
        fcntl.flock(m.background_lock,fcntl.LOCK_EX)
        self.addCleanup(m.background_lock.close)
        m.records[0]['fields'].append({'name':'username','value':'synthetic-user'})
        m.provider(); m.ok('add', 'alpha'); m.ok('add', 'beta')
        return m
    def script(self, m, name, code):
        f=m.home/name; f.parent.mkdir(parents=True,exist_ok=True); f.write_text(code); return f
    def test_explicit_multiple_fields_and_no_implicit_values(self):
        m=self.machine()
        file=self.script(m,'one/main.py','import os; assert os.environ["ALPHA_TOKEN"] == "synthetic-alpha-secret"; assert os.environ["ALPHA_USERNAME"] == "synthetic-user"; assert os.environ["BETA_TOKEN"] == "synthetic-beta-secret"')
        m.ok('wrap','--file',file,'--use','alpha:token,username','beta:token','--','python3')
        file.write_text('import os; assert "ALPHA_TOKEN" not in os.environ; assert "BETA_TOKEN" not in os.environ; assert "OLD_TOKEN" not in os.environ')
        env=dict(m.env, ALPHA_TOKEN='old',OLD_TOKEN='old',SECRETS_INJECTED='OLD_TOKEN')
        m.ok('wrap','--file',file,'--','python3',env=env)
        m.ok('wrap','python3','-c','import os; assert "ALPHA_TOKEN" not in os.environ')
        for use in ['alpha:missing','alpha','alpha:token,','alpha:token,token']:
            self.assertNotEqual(m.run('wrap','--file',file,'--use',use,'--','python3').returncode,0)
        self.assertNotEqual(m.run('wrap','--use','alpha:token','--','python3','-c','pass').returncode,0)

    def approve(self,m,args,password=policy.session.PASSWORD,expected=0):
        return policy.session.run_terminal(self,args,[(b'Master password:',password)],m.env,expected)
    def test_file_grants_require_password_and_revoke_stays_closed(self):
        m=self.machine()
        code='import os; assert os.environ["ALPHA_TOKEN"] == "synthetic-alpha-secret"; assert "ALPHA_USERNAME" not in os.environ'
        first=self.script(m,'one/main.py',code); second=self.script(m,'two/main.py',code)
        before=(m.directory/'vault.enc').read_bytes()
        self.assertNotEqual(m.run('add','alpha:token','--file',first).returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.approve(m,['add','alpha:token','--file',first],b'wrong-password',5)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.approve(m,['add','alpha:token','--file',first])
        m.ok('wrap','--file',first,'--use','alpha:token','--','python3')
        self.assertNotEqual(m.run('wrap','--file',second,'--use','alpha:token','--','python3').returncode,0)
        # The same field can be granted to a second path without replacing the first.
        self.approve(m,['add','alpha:token','--file',second])
        for f in [first,second]: m.ok('wrap','--file',f,'--use','alpha:token','--','python3')
        self.approve(m,['access','revoke','alpha:token','--file',first,'--file',second])
        self.assertNotEqual(m.run('wrap','--file',first,'--use','alpha:token','--','python3').returncode,0)
        m.ok('delete','alpha','token'); m.ok('add','alpha','token')
        self.assertNotEqual(m.run('wrap','--file',first,'--use','alpha:token','--','python3').returncode,0,'Delete/reimport must not reopen a restricted field')
        self.approve(m,['access','open','alpha:token'])
        m.ok('wrap','--file',first,'--use','alpha:token','--','python3')

    def test_manifest_access_needs_password_and_old_manifest_preserves_rules(self):
        m=self.machine()
        f=self.script(m,'main.py','pass')
        self.approve(m,['add','alpha:token','--file',f])
        manifest=m.home/'fields.json'; m.ok('manifest','export',manifest)
        data=json.loads(manifest.read_text()); self.assertEqual(data['version'],2)
        before=(m.directory/'vault.enc').read_bytes()
        self.assertNotEqual(m.run('manifest','apply',manifest,'--with-access').returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.approve(m,['manifest','apply',str(manifest),'--with-access'])
        data['version']=1; del data['access']['files']; manifest.write_text(json.dumps(data))
        self.approve(m,['manifest','apply',str(manifest),'--with-access'])
        other=self.script(m,'other.py','raise SystemExit("CHILD_RAN")')
        self.assertNotEqual(m.run('wrap','--file',other,'--use','alpha:token','--','python3').returncode,0)

    def test_background_refresh_runs_after_child_and_reports_failure(self):
        import time
        m=self.machine()
        m.background_lock.close()
        m.records[0]['fields'][0]['value']='synthetic-new'; m.provider()
        f=self.script(m,'refresh.py','import os; assert os.environ["ALPHA_TOKEN"] == "synthetic-alpha-secret"')
        m.ok('wrap','--file',f,'--use','alpha:token','--','python3')
        status=m.directory/'local-sync-status.json'
        end=time.monotonic()+15
        while time.monotonic()<end:
            if status.exists() and json.loads(status.read_text()).get('last_success'): break
            time.sleep(.1)
        else: self.fail('Background refresh never completed')
        f.write_text('import os; assert os.environ["ALPHA_TOKEN"] == "synthetic-new"')
        m.ok('wrap','--file',f,'--use','alpha:token','--','python3')
        before=(m.directory/'vault.enc').read_bytes()
        (m.home/'mode').write_text('offline')
        status.unlink()
        self.assertNotEqual(m.run('refresh-local').returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.assertEqual(json.loads(status.read_text())['reason'], 'bitwarden_request_failed')
        self.assertIn(b'Background refresh failed (bitwarden_request_failed)',m.run('status').stderr)
        self.assertIsNone(json.loads(status.read_text())['reference'])
        (m.home/'mode').write_text('')
        m.records=[r for r in m.records if r['name']!='alpha'];m.provider()
        status.unlink()
        self.assertNotEqual(m.run('refresh-local').returncode,0)
        detail=json.loads(status.read_text())
        self.assertEqual(detail['reason'],'provider_item_missing')
        self.assertEqual(detail['reference'],'alpha')
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)

    def test_background_does_not_block_or_overwrite_foreground(self):
        import time
        m=self.machine(); m.background_lock.close()
        # Prevent automatic scheduling while we prepare the deterministic worker.
        status=m.directory/'local-sync-status.json'
        status.write_text(json.dumps({'last_attempt':int(time.time())}))
        (m.home/'mode').write_text('slow-list')
        status.unlink()
        worker=subprocess.Popen([str(policy.CLI),'refresh-local'],env=m.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: worker.poll() is None and worker.kill())
        until=time.monotonic()+8
        while not (m.home/'list-started').exists() and time.monotonic()<until: time.sleep(.05)
        self.assertTrue((m.home/'list-started').exists())
        started=time.monotonic()
        m.ok('delete','beta')
        self.assertLess(time.monotonic()-started,3,'Foreground waited for background network')
        after=(m.directory/'vault.enc').read_bytes()
        m.ok('refresh-local') # Another worker coalesces immediately.
        (m.home/'list-release').touch(); self.assertEqual(worker.wait(timeout=10),0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),after)
        self.assertIn('superseded',json.loads(status.read_text())['outcome'])

    def test_background_cannot_commit_across_lock_and_unlock(self):
        import time
        m=self.machine(); m.background_lock.close()
        (m.home/'mode').write_text('slow-list')
        worker=subprocess.Popen([str(policy.CLI),'refresh-local'],env=m.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: worker.poll() is None and worker.kill())
        until=time.monotonic()+8
        while not (m.home/'list-started').exists() and time.monotonic()<until: time.sleep(.05)
        self.assertTrue((m.home/'list-started').exists())
        before=(m.directory/'vault.enc').read_bytes()
        m.ok('lock'); self.approve(m,['unlock'])
        (m.home/'list-release').touch(); self.assertEqual(worker.wait(timeout=10),0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.assertIn('superseded',json.loads((m.directory/'local-sync-status.json').read_text())['outcome'])

    def test_paths_symlinks_direct_execution_and_argument_forwarding(self):
        m=self.machine()
        f=self.script(m,'one/main.py','#!/usr/bin/python3\nimport os,sys; assert os.environ["ALPHA_TOKEN"]=="synthetic-alpha-secret"; assert sys.argv[1:]==["--flag","two words"]')
        f.chmod(0o700)
        self.approve(m,['add','alpha:token','--file',f])
        link=m.home/'alias.py';link.symlink_to(f)
        m.ok('wrap','--file',link,'--use','alpha:token','--','python3','--flag','two words')
        other=self.script(m,'two/main.py','raise SystemExit("CHILD_RAN")')
        link.unlink();link.symlink_to(other)
        self.assertNotEqual(m.run('wrap','--file',link,'--use','alpha:token','--','python3').returncode,0)
        # Direct executable uses the existing local whitelist, not a bypass.
        config=m.directory/'config.yaml';config.write_text(config.read_text().replace('whitelist:', 'whitelist:\n- main.py'))
        f.write_text('#!/usr/bin/python3\nimport os; assert os.environ["ALPHA_TOKEN"]=="synthetic-alpha-secret"')
        m.ok('wrap','--file',f,'--use','alpha:token')
        before=(m.directory/'vault.enc').read_bytes()
        self.assertNotEqual(m.run('add','alpha:token','--file',m.home).returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)

    def test_failed_child_does_not_schedule_refresh(self):
        import time
        m=self.machine();m.background_lock.close()
        f=self.script(m,'fail.py','raise SystemExit(42)')
        self.assertEqual(m.run('wrap','--file',f,'--','python3').returncode,42)
        time.sleep(.3)
        self.assertFalse((m.directory/'local-sync-status.json').exists())

    def test_legacy_enforced_reset_needs_password_and_keeps_file_rules(self):
        m=self.machine()
        f=self.script(m,'one.py','pass'); other=self.script(m,'two.py','pass')
        self.approve(m,['add','alpha:token','--file',f])
        manifest=m.home/'legacy.json';m.ok('manifest','export',manifest)
        data=json.loads(manifest.read_text());data['version']=1;del data['access']['files']
        data['access']['enforced']=True
        data['access']['grants']={'python3':[{'item':'alpha','field':'token'}]}
        manifest.write_text(json.dumps(data))
        self.approve(m,['manifest','apply',str(manifest),'--with-access'])
        self.assertNotEqual(m.run('wrap','--file',f,'--use','beta:token','--','python3').returncode,0)
        m.ok('wrap','--file',f,'--use','alpha:token','--','python3')
        before=(m.directory/'vault.enc').read_bytes()
        self.assertNotEqual(m.run('access','reset-legacy').returncode,0)
        self.approve(m,['access','reset-legacy'],b'wrong-password',5)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.approve(m,['access','reset-legacy'])
        m.ok('wrap','--file',f,'--use','beta:token','--','python3')
        self.assertNotEqual(m.run('wrap','--file',other,'--use','alpha:token','--','python3').returncode,0)

    def test_move_rebinds_all_fields_atomically_and_preserves_other_paths(self):
        m=self.machine()
        old=self.script(m,'old/main.py','import os; assert os.environ["ALPHA_TOKEN"] == "synthetic-alpha-secret"')
        new=self.script(m,'new/main.py',old.read_text())
        other=self.script(m,'other/main.py',old.read_text())
        self.approve(m,['add','alpha:token,username','--file',old,'--file',other])
        self.approve(m,['add','beta:token','--file',new])
        m.ok('delete','alpha','username') # A tombstone rule must move too.
        old.unlink()
        before=(m.directory/'vault.enc').read_bytes()
        self.assertNotEqual(m.run('move',old,new).returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.approve(m,['move',str(old),str(new)],b'wrong-password',5)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.assertNotEqual(m.run('move',old,m.home/'absent').returncode,0)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        self.approve(m,['move',str(old),str(new)])
        for path in [new,other]: m.ok('wrap','--file',path,'--use','alpha:token','--','python3')
        new.write_text('pass')
        m.ok('wrap','--file',new,'--use','beta:token','--','python3')
        old.write_text(new.read_text())
        self.assertNotEqual(m.run('wrap','--file',old,'--use','alpha:token','--','python3').returncode,0)
        m.ok('add','alpha','username')
        self.assertNotEqual(m.run('wrap','--file',old,'--use','alpha:username','--','python3').returncode,0)
        m.ok('wrap','--file',new,'--use','alpha:token,username','--','python3')
        manifest=m.home/'moved.json';m.ok('manifest','export',manifest)
        data=json.loads(manifest.read_text())
        self.assertFalse(data['access']['enforced'])
        for rule in data['access']['files']:
            self.assertNotIn(str(old),rule['files'])
        before=(m.directory/'vault.enc').read_bytes()
        for source,target in [(old,new),(new,new),(m.home/'unknown',new)]:
            self.assertNotEqual(m.run('move',source,target).returncode,0)
            self.assertEqual((m.directory/'vault.enc').read_bytes(),before)

    def test_move_uses_stored_path_even_if_old_is_now_a_symlink(self):
        m=self.machine()
        old=self.script(m,'old.py','pass');other=self.script(m,'other.py','pass');new=self.script(m,'new.py','pass')
        self.approve(m,['add','alpha:token','--file',old])
        self.approve(m,['add','beta:token','--file',other])
        old.unlink();old.symlink_to(other)
        self.approve(m,['move',str(old),str(new)])
        m.ok('wrap','--file',new,'--use','alpha:token','--','python3')
        self.assertNotEqual(m.run('wrap','--file',new,'--use','beta:token','--','python3').returncode,0)
        m.ok('wrap','--file',other,'--use','beta:token','--','python3')

    def test_sync_offers_missing_removal_only_with_terminal_confirmation(self):
        m=self.machine()
        allowed=self.script(m,'allowed.py','pass');denied=self.script(m,'denied.py','pass')
        self.approve(m,['add','alpha:token','--file',allowed])
        original=json.loads(json.dumps(m.records))
        m.records=[r for r in m.records if r['name']!='beta']
        m.records[0]['fields']=[f for f in m.records[0]['fields'] if f['name']!='token']
        m.provider()
        before=(m.directory/'vault.enc').read_bytes()
        result=m.run('sync');self.assertNotEqual(result.returncode,0)
        self.assertIn(b'proposed local removals',result.stderr)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        policy.session.run_terminal(self,['sync'],[(b'[y/N]:',b'n')],m.env,7)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        # Provider failure cannot be turned into a deletion proposal.
        (m.home/'mode').write_text('offline')
        result=m.run('sync');self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'proposed local removals',result.stdout+result.stderr)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        (m.home/'mode').write_text('')
        policy.session.run_terminal(self,['sync'],[(b'[y/N]:',b'y')],m.env)
        manifest=m.home/'cleaned.json';m.ok('manifest','export',manifest)
        data=json.loads(manifest.read_text())
        self.assertNotIn(b'beta',m.ok('ls').stdout)
        self.assertNotEqual(m.run('wrap','--file',allowed,'--use','alpha:token','--','python3').returncode,0)
        self.assertTrue(any(r['item']=='alpha' and r['field']=='token' and str(allowed) in r['files'] for r in data['access']['files']))
        m.records=original;m.provider();m.ok('add','alpha','token')
        m.ok('wrap','--file',allowed,'--use','alpha:token','--','python3')
        self.assertNotEqual(m.run('wrap','--file',denied,'--use','alpha:token','--','python3').returncode,0)

    def test_sync_field_removal_keeps_unselected_local_fields(self):
        m=self.machine()
        m.records=[r for r in m.records if r['name']!='alpha'];m.provider()
        policy.session.run_terminal(self,['sync','alpha','token'],[(b'[y/N]:',b'yes')],m.env)
        fields=m.ok('ls','alpha').stdout
        self.assertIn(b'username',fields)
        self.assertNotIn(b'token',fields)
        self.assertIn(b'beta',m.ok('ls').stdout)

    def test_sync_late_error_does_not_offer_removal_and_enter_declines(self):
        m=self.machine()
        m.records=[r for r in m.records if r['name']!='alpha'];m.provider()
        before=(m.directory/'vault.enc').read_bytes()
        (m.home/'mode').write_text('late-list-error')
        result=m.run('sync')
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'missing from provider',result.stdout) # Earlier lookup confirmed absence.
        self.assertIn(b'synthetic late provider error',result.stderr)
        self.assertNotIn(b'proposed local removals',result.stdout+result.stderr)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)
        (m.home/'mode').write_text('')
        policy.session.run_terminal(self,['sync'],[(b'[y/N]:',b'')],m.env,7)
        self.assertEqual((m.directory/'vault.enc').read_bytes(),before)

if __name__=='__main__': unittest.main()
