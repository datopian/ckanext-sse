"""``ckan sse ...`` commands.

Two of the access-control standards need something to run outside a request:
AC-2.3 wants dormant accounts disabled automatically, which means a scheduled
sweep, and AC-7 wants a locked account to be releasable "by an administrator",
which means a way to release it.
"""

import click

from ckanext.sse import account_lifecycle, login_throttle


@click.group(short_help="SSE portal administration")
def sse():
    pass


@sse.command()
@click.option("--dry-run", is_flag=True,
              help="List the accounts without disabling them.")
@click.option("--idle-days", type=int, default=None,
              help="Override ckanext.sse.inactivity.idle_days.")
@click.option("--min-age-days", type=int, default=None,
              help="Override ckanext.sse.inactivity.min_account_age_days.")
def disable_inactive_users(dry_run, idle_days, min_age_days):
    """Disable accounts dormant beyond the AC-2.3 threshold.

    Intended for cron or a Kubernetes CronJob. Idempotent, so a missed run
    costs nothing and a repeated one does nothing.
    """
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
