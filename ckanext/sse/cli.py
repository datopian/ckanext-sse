"""``ckan sse ...`` commands.

Two of the access-control standards need something to run outside a request:
AC-2.3 wants dormant accounts disabled automatically, which means a scheduled
sweep, and AC-7 wants a locked account to be releasable "by an administrator",
which means a way to release it.
"""

import click

from ckanext.sse import upload_security, account_lifecycle, login_throttle


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
              help="Post the result to the Google Chat webhook (mismatches always go to the audit trail regardless).")
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


@sse.command()
@click.option("--dry-run", is_flag=True,
              help="List the accounts without disabling them.")
@click.option("--idle-days", type=int, default=None,
              help="Override ckanext.sse.inactivity.idle_days.")
@click.option("--min-age-days", type=int, default=None,
              help="Override ckanext.sse.inactivity.min_account_age_days.")
def disable_inactive_users(dry_run, idle_days, min_age_days):
    """Disable accounts dormant beyond the AC-2.3 threshold.

    Warns accounts approaching the threshold (7 and 1 days out), then disables
    those past it. Intended for cron or a Kubernetes CronJob. Idempotent, so a
    missed run costs nothing and a repeated one does nothing.
    """
    warned = account_lifecycle.send_dormancy_warnings(
        dry_run=dry_run, idle=idle_days, min_age=min_age_days,
    )
    for record in warned:
        click.echo("warn {}\t{} day(s) left ({})".format(
            record["name"], record["days_left"], record["kind"]))
    verb_w = "would be warned" if dry_run else "warned"
    click.secho("{} account(s) {}".format(len(warned), verb_w),
                fg="yellow" if warned else "green")

    disabled = account_lifecycle.disable_inactive_users(
        dry_run=dry_run, idle=idle_days, min_age=min_age_days,
    )

    for record in disabled:
        click.echo("{}\t{} days idle\tlast active {}".format(
            record["name"], record["idle_days"],
            record["last_active"] or "never",
        ))

    verb = "would be disabled" if dry_run else "disabled"
    click.secho("{} account(s) {}".format(len(disabled), verb),
                fg="yellow" if disabled else "green")


@sse.command()
@click.argument("login")
def login_status(login):
    """Show the failed-login count and lock state for LOGIN."""
    key = login_throttle.throttle_key(login)
    if key is None:
        raise click.ClickException("Not a usable login name")

    state = login_throttle.status(key)
    click.echo("account:  {}".format(state["key"]))
    click.echo("failures: {} of {}".format(state["failures"],
                                           login_throttle.max_attempts()))
    if state["locked"]:
        click.secho("locked:   yes, for another {} second(s)".format(
            state["seconds_remaining"]), fg="red")
    else:
        click.secho("locked:   no", fg="green")


@sse.command()
@click.argument("login")
def unlock_login(login):
    """Release the AC-7 lockout on LOGIN.

    The lock expires on its own after the configured window; this is the
    "or until released by an administrator" half of the control.
    """
    key = login_throttle.throttle_key(login)
    if key is None:
        raise click.ClickException("Not a usable login name")

    if login_throttle.clear(key):
        click.secho("Unlocked {}".format(key), fg="green")
    else:
        click.echo("{} was not locked; failure count cleared".format(key))


def get_commands():
    return [sse]
