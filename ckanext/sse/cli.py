"""``ckan sse ...`` commands."""

import click

from ckanext.sse import upload_security


@click.group(short_help="SSE portal administration")
def sse():
    pass


@sse.group()
def checksums():
    """SI-7 resource-file integrity checksums."""


@checksums.command()
@click.option("--dry-run", is_flag=True, help="List resources without stamping.")
def backfill(dry_run):
    """Stamp SHA-256 on active upload resources that lack one."""
    r = upload_security.backfill(dry_run=dry_run)
    verb = "would stamp" if dry_run else "stamped"
    click.secho("{} {} resource(s)".format(verb, len(r["stamped"])), fg="green")
    click.echo("{} already had a checksum".format(r["already"]))
    if r["missing_object"]:
        click.secho("{} resource(s) had no object in storage: {}".format(
            len(r["missing_object"]), ", ".join(r["missing_object"])), fg="yellow")


@checksums.command()
@click.option("--notify", is_flag=True,
              help="Post the result to the Google Chat webhook (mismatches always alert).")
def verify(notify):
    """Re-hash stored objects and compare to the recorded checksum (SI-7(1)).

    Mismatches and missing objects are written to the audit trail. Intended for
    a scheduled CronJob.
    """
    r = upload_security.verify(notify=notify)
    click.echo("checked {} resource(s)".format(r["checked"]))
    if not (r["mismatches"] or r["missing_object"]):
        click.secho("all checksums match", fg="green")
        return
    for m in r["mismatches"]:
        click.secho("MISMATCH {}: expected {} got {}".format(
            m["resource_id"], m["expected"], m["actual"]), fg="red")
    for rid in r["missing_object"]:
        click.secho("MISSING OBJECT {}".format(rid), fg="yellow")
    raise click.ClickException("checksum verification failed")


def get_commands():
    return [sse]
