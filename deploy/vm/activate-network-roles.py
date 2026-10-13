import datetime, os, pathlib, signal, subprocess, sys, time
os.umask(0o077)
def interrupted(signum, frame): raise RuntimeError("deployment interrupted; restoring application roles")
for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGALRM): signal.signal(sig,interrupted)
signal.alarm(150)
release=pathlib.Path(sys.argv[1])
assert release.is_dir() and (release/'bin/sherlock-control').is_file()
units=['sherlock-control','sherlock-api','sherlock-admin-ui']
workers=['sherlock-worker','sherlock-worker-fixture2']
backup=pathlib.Path('/var/backups/sherlock')/('management-units-'+release.name)
backup.mkdir(mode=0o700)
old={}
for u in units:
 p=pathlib.Path('/etc/systemd/system')/(u+'.service.d/gp09-network-release.conf')
 assert p.is_file()
 old[u]=p.read_bytes();(backup/(u+'.conf')).write_bytes(old[u])

def run(args): return subprocess.run(args,check=True,text=True,capture_output=True,timeout=50).stdout.strip()
def sql(query): return run(['docker','exec','-i','sherlock-postgres-1','psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-U','sherlock','-d','sherlock','-c',query])
def event(text): print(datetime.datetime.now(datetime.timezone.utc).isoformat(),text,flush=True)
# Hold only unleased job-row locks. ClaimDueJob uses SKIP LOCKED, while already
# leased jobs can complete normally. No scheduler configuration is rewritten.
p=subprocess.Popen(['docker','exec','-i','sherlock-postgres-1','psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-U','sherlock','-d','sherlock'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
paused=False;switched=False
try:
 p.stdin.write("BEGIN; SET LOCAL idle_in_transaction_session_timeout='120s'; SET LOCAL lock_timeout='2s';\n");p.stdin.flush()
 deadline=time.monotonic()+70
 while True:
  p.stdin.write("SELECT count(*) FROM (SELECT job_id FROM collection_jobs WHERE active AND (lease_expires_at IS NULL OR lease_expires_at<clock_timestamp()) FOR UPDATE SKIP LOCKED) j; SELECT 'LOCK_ROUND_COMPLETE';\n");p.stdin.flush()
  seen=False
  until=time.monotonic()+8
  while time.monotonic()<until:
   # readline is safe here: psql emits tiny flushed result lines; external
   # watchdog below bounds the whole deployment process.
   line=p.stdout.readline()
   if not line: raise RuntimeError('job barrier connection exited')
   if line.strip()=='LOCK_ROUND_COMPLETE':seen=True;break
  assert seen
  n=int(sql("SELECT (SELECT count(*) FROM collection_jobs WHERE lease_expires_at>clock_timestamp())+(SELECT count(*) FROM collector_work_items WHERE status IN ('AVAILABLE','LEASED'))+(SELECT count(*) FROM diagnostic_work_items WHERE status IN ('AVAILABLE','LEASED'))"))
  if n==0: break
  if time.monotonic()>deadline: raise RuntimeError('active work did not drain; abort')
  time.sleep(1)
 event('SCHEDULED_DISPATCH_BLOCKED_AND_WORK_DRAINED')
 run(['systemctl','stop',*workers]);paused=True
 # Keep the barrier until both workers are stopped. No live lease is canceled.
 p.stdin.write('ROLLBACK;\n\\q\n');p.stdin.flush();p.communicate(timeout=5)
 event('WORKERS_PAUSED')
 for u in units:
  path=pathlib.Path('/etc/systemd/system')/(u+'.service.d/gp09-network-release.conf')
  path.write_text('[Service]\nExecStart=\nExecStart='+str(release/'bin'/u)+'\n')
 switched=True
 run(['systemctl','daemon-reload'])
 run(['systemctl','restart','sherlock-control','sherlock-api'])
 run(['systemctl','restart','sherlock-admin-ui'])
 for u in units:
  pid=run(['systemctl','show',u,'-p','MainPID','--value'])
  assert pid!='0' and pathlib.Path('/proc/'+pid+'/exe').resolve()==release/'bin'/u,u
  assert run(['systemctl','is-active',u])=='active'
 event('APP_ROLES_VERIFIED')
 run(['systemctl','start',*workers]);paused=False
 for u in workers: assert run(['systemctl','is-active',u])=='active'
 event('WORKERS_RESUMED')
except BaseException:
 signal.alarm(0)
 if switched:
  for u,data in old.items():
   path=pathlib.Path('/etc/systemd/system')/(u+'.service.d/gp09-network-release.conf');path.write_bytes(data)
  subprocess.run(['systemctl','daemon-reload'],check=False)
  subprocess.run(['systemctl','restart',*units],check=False,timeout=60)
 if paused:subprocess.run(['systemctl','start',*workers],check=False,timeout=50)
 raise
finally:
 signal.alarm(0)
 if p.poll() is None:
  try:p.stdin.write('ROLLBACK;\n\\q\n');p.stdin.flush();p.communicate(timeout=5)
  except Exception:p.kill();p.communicate(timeout=5)
