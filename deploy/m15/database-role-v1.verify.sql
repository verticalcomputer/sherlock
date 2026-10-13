-- Run as an operator after setting a deployment-created LOGIN session role.
-- It reports grants only; it never emits a connection string or secret.
SELECT current_database() AS database_name, session_user, current_user,
       has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_public_schema,
       rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
FROM pg_roles WHERE rolname = current_user;

SELECT table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = current_user AND table_schema = 'public'
ORDER BY table_name, privilege_type;

-- `role_table_grants` does not include privileges inherited through PUBLIC or
-- a role membership. These two queries show the actual effective capability.
SELECT c.oid::regclass AS relation,
       has_table_privilege(current_user, c.oid, 'SELECT') AS can_select,
       has_table_privilege(current_user, c.oid, 'INSERT') AS can_insert,
       has_table_privilege(current_user, c.oid, 'UPDATE') AS can_update,
       has_table_privilege(current_user, c.oid, 'DELETE') AS can_delete
FROM pg_class c
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')
  AND (has_table_privilege(current_user, c.oid, 'SELECT')
    OR has_table_privilege(current_user, c.oid, 'INSERT')
    OR has_table_privilege(current_user, c.oid, 'UPDATE')
    OR has_table_privilege(current_user, c.oid, 'DELETE'))
ORDER BY relation;

SELECT c.oid::regclass AS relation, a.attname,
       has_column_privilege(current_user, c.oid, a.attname, 'SELECT') AS can_select,
       has_column_privilege(current_user, c.oid, a.attname, 'INSERT') AS can_insert,
       has_column_privilege(current_user, c.oid, a.attname, 'UPDATE') AS can_update
FROM pg_class c
JOIN pg_namespace n ON n.oid=c.relnamespace
JOIN pg_attribute a ON a.attrelid=c.oid
WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m')
  AND a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(current_user, c.oid, a.attname, 'SELECT')
    OR has_column_privilege(current_user, c.oid, a.attname, 'INSERT')
    OR has_column_privilege(current_user, c.oid, a.attname, 'UPDATE'))
ORDER BY relation, a.attnum;

SELECT c.oid::regclass AS relation, a.attname, x.privilege_type
FROM pg_attribute a
JOIN pg_class c ON c.oid=a.attrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
CROSS JOIN LATERAL aclexplode(a.attacl) x
WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped AND x.grantee=0
ORDER BY relation, a.attnum, x.privilege_type;

SELECT p.oid::regprocedure AS function_name
FROM pg_proc p
CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
WHERE p.prosecdef AND a.grantee = 0 AND a.privilege_type = 'EXECUTE';
