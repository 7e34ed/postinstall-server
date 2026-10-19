from django.db import migrations


TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION {table}_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'append-only: {table} update/delete запрещены';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS {table}_append_only_trigger ON {table};
CREATE TRIGGER {table}_append_only_trigger
BEFORE UPDATE OR DELETE ON {table}
FOR EACH ROW EXECUTE FUNCTION {table}_append_only();
"""

DROP_SQL = """
DROP TRIGGER IF EXISTS {table}_append_only_trigger ON {table};
DROP FUNCTION IF EXISTS {table}_append_only();
"""

TABLES = ["core_auditlog", "access_authauditlog"]


def forwards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for t in TABLES:
        schema_editor.execute(TRIGGER_SQL.format(table=t))


def backwards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for t in TABLES:
        schema_editor.execute(DROP_SQL.format(table=t))


class Migration(migrations.Migration):
    dependencies = [
        ("core", "000X_auditlog_chain"),
        ("access", "000X_authauditlog_chain"),
    ]
    operations = [
        migrations.RunPython(forwards, backwards),
    ]