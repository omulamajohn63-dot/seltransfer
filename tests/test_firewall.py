"""The Windows Firewall rule, tested without touching the real firewall.

`allow-firewall` is the one command that changes machine state, and it is the one
command a user runs *because* the previous attempt did not work. So the shape of
the `netsh` command is asserted here rather than being discovered on a hotspot.

The bug this guards against is concrete: the rule used to be created with
`profile=private,domain`, and Windows classifies a phone hotspot as **public**. The
rule was therefore inert on the exact setup the command exists for - and on this
machine `netsh advfirewall show currentprofile` reports `public`.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
import typer

from seltransfer.cli import (
    allow_firewall,
    firewall_rule_name,
    normalise_firewall_profiles,
    parse_firewall_profile,
    parse_rule_profiles,
)


class Recorder:
    """Stands in for `subprocess.run` and remembers every netsh invocation."""

    def __init__(self, returncode: int = 0, stdout: str = "") -> None:
        self.commands: list[list[str]] = []
        self.returncode = returncode
        self.stdout = stdout

    def __call__(self, command, **kwargs):
        self.commands.append(list(command))
        return subprocess.CompletedProcess(command, self.returncode, self.stdout, "")

    @property
    def added(self) -> list[str]:
        for command in self.commands:
            if "add" in command:
                return command
        raise AssertionError(f"no 'add' command was run: {self.commands}")


@pytest.fixture
def netsh(monkeypatch):
    def install(returncode: int = 0, stdout: str = "") -> Recorder:
        recorder = Recorder(returncode, stdout)
        monkeypatch.setattr(subprocess, "run", recorder)
        return recorder
    return install


def add_rule(port: int = 8765, profile: str = "any") -> None:
    """Invoke the command the way Typer does - every option explicitly.

    Calling `allow_firewall()` directly would pass Typer's `Option` objects in as
    the defaults, and `Option(False)` is a truthy object: `remove` would come out
    True and the command would delete the rule instead of adding it. Every
    argument is therefore spelled out here.
    """
    allow_firewall(port=port, remove=False, profile=profile)


# --- the rule covers the networks this tool is actually used on --------------


def test_the_default_rule_covers_the_public_profile(netsh):
    """A phone hotspot is a *public* network. The rule must apply there."""
    recorder = netsh()
    add_rule()

    assert "profile=any" in recorder.added, recorder.added


def test_the_exposure_is_still_limited_to_the_local_subnet(netsh):
    """Widening the profile must not widen the exposure.

    The profile controls *when* the rule applies, not *from where*. Only
    remoteip=localsubnet keeps a rule with no profile restriction from accepting
    the internet, so it has to survive every profile choice.
    """
    recorder = netsh()
    add_rule(profile="public")

    assert "remoteip=localsubnet" in recorder.added
    assert "profile=public" in recorder.added


@pytest.mark.parametrize("profile", ["any", "private", "domain", "public",
                                     "public,private", "domain,private,public"])
def test_every_accepted_profile_produces_a_scoped_rule(netsh, profile):
    recorder = netsh()
    add_rule(profile=profile)

    assert "remoteip=localsubnet" in recorder.added
    assert any(argument.startswith("profile=")
               for argument in recorder.added), recorder.added


# --- the rule is anchored to the program that actually listens --------------


def test_the_rule_names_the_running_interpreter(netsh):
    """A source install binds with python.exe; a frozen build with the .exe."""
    recorder = netsh()
    add_rule()

    assert f"program={sys.executable}" in recorder.added or any(
        argument.startswith("program=") and argument.endswith(".exe")
        for argument in recorder.added), recorder.added


def test_the_rule_is_inbound_tcp_on_the_requested_port(netsh):
    recorder = netsh()
    add_rule(port=9123)

    assert "dir=in" in recorder.added
    assert "action=allow" in recorder.added
    assert "protocol=tcp" in recorder.added
    assert "localport=9123" in recorder.added
    assert "remoteip=any" not in recorder.added


def test_the_rule_name_carries_the_port(netsh):
    """A second port must be addable without disturbing the first."""
    recorder = netsh()
    add_rule(port=9123)

    assert f"name={firewall_rule_name(9123)}" in recorder.added
    assert firewall_rule_name(8765) != firewall_rule_name(9123)


# --- idempotence and removal -------------------------------------------------


def test_an_existing_rule_is_left_alone(netsh):
    recorder = netsh(stdout="Rule Name:                            SELTRANSFER (TCP 8765)\n")
    add_rule()

    assert not any("add" in command for command in recorder.commands)


# --- a rule left by an older version gets migrated, not silently accepted ----

# Verbatim shape of `netsh advfirewall firewall show rule name=...`. Note that
# netsh capitalises the profiles and reports a profile=any rule as the full list.
LEGACY_RULE = """
Rule Name:                            SELTRANSFER (TCP 8765)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private
Program:                              C:\\Python\\python.exe
LocalIP:                              Any
RemoteIP:                             LocalSubnet
Protocol:                             TCP
LocalPort:                             8765
Action:                               Allow
Ok.
"""


def test_a_stale_private_domain_rule_is_widened_to_any(netsh):
    """The fix is worthless if it only applies to fresh installs.

    Anyone who ran the broken version already has a `Domain,Private` rule on this
    machine. Re-running the command used to print "already exists" and change
    nothing, so the hotspot stayed blocked. The existing rule must be updated.
    """
    recorder = netsh(stdout=LEGACY_RULE)
    add_rule()

    updated = [c for c in recorder.commands if "set" in c]
    assert updated, recorder.commands
    assert "profile=any" in updated[0]
    assert not any("add" in c for c in recorder.commands), (
        "should update in place, not add a second rule")


def test_a_matching_existing_rule_is_not_rewritten(netsh):
    """An up-to-date rule should not churn."""
    recorder = netsh(stdout=LEGACY_RULE)
    add_rule(profile="domain,private")

    assert not any("set" in c or "add" in c for c in recorder.commands)


def test_an_all_profile_existing_rule_counts_as_matching(netsh):
    """netsh reports profile=any as Domain,Private,Public, which must not be
    mistaken for a rule that still needs widening."""
    recorder = netsh(stdout=LEGACY_RULE.replace("Domain,Private",
                                                 "Domain,Private,Public"))
    add_rule(profile="private")

    assert not any("set" in c or "add" in c for c in recorder.commands)


def test_an_overscoped_rule_is_not_narrowed(netsh):
    """Widening only. Narrowing would silently re-break a hotspot that works."""
    recorder = netsh(stdout=LEGACY_RULE.replace("Domain,Private",
                                                 "Domain,Private,Public"))
    add_rule(profile="public")

    assert not any("set" in c or "add" in c for c in recorder.commands)


@pytest.mark.parametrize("line,expected", [
    ("Profiles:                             Domain,Private,Public", "any"),
    ("Profiles:                             Public", "public"),
    ("  Profiles:  Domain , Private ", "domain,private"),
    ("Profiles:                             Any", "any"),
    ("Profiles:                             FileName,Package", None),
    ("", None),
])
def test_parse_rule_profiles(line, expected):
    """Normalise what netsh prints into something comparable with --profile."""
    output = f"Rule Name:  X\n{line}\nAction:  Allow\n" if line else ""
    assert parse_rule_profiles(output) == expected


def test_a_blank_response_is_not_read_as_an_existing_rule(netsh):
    """`show rule` can answer with nothing at all. That is not "already exists"."""
    recorder = netsh(stdout="")
    add_rule()

    assert "add" in recorder.added


def test_the_no_match_message_is_honoured(netsh):
    """netsh reports a missing rule in its output rather than its exit code."""
    recorder = netsh(stdout="No rules match the specified criteria.\n")
    add_rule()

    assert "add" in recorder.added


def test_remove_deletes_the_rule_by_name(netsh):
    recorder = netsh()
    allow_firewall(port=8765, remove=True, profile="any")

    deleted = [c for c in recorder.commands if "delete" in c]
    assert deleted, recorder.commands
    assert f"name={firewall_rule_name(8765)}" in deleted[0]
    assert "add" not in deleted[0]


def test_a_failure_explains_what_to_run_by_hand(netsh, capsys):
    """Without this the user is stuck: the command needs Administrator rights."""
    netsh(returncode=1)
    add_rule()

    printed = capsys.readouterr().out
    assert "Administrator" in printed
    assert "remoteip=localsubnet" in printed


# --- profile parsing ---------------------------------------------------------


def test_the_active_profile_is_the_word_before_profile():
    """`netsh` prints "Public Profile Settings:".

    Reading the word *after* "Profile" yields "settings", which is plausible
    enough to pass a glance and wrong every time.
    """
    assert parse_firewall_profile("Public Profile Settings:") == "public"
    assert parse_firewall_profile("  Domain Profile Settings:") == "domain"
    assert parse_firewall_profile("Private Profile Settings:") == "private"
    assert parse_firewall_profile("no profile here") is None
    assert parse_firewall_profile("") is None


def test_a_hotspot_profile_warns_when_the_rule_does_not_cover_it(
        netsh, monkeypatch, capsys):
    """If someone narrows the rule to private, say so when they are on public."""
    netsh()  # no existing rule
    monkeypatch.setattr("seltransfer.cli.current_firewall_profile",
                        lambda: "public")

    add_rule(profile="private")

    printed = capsys.readouterr().out
    assert "public" in printed
    assert "--profile public" in printed


def test_no_warning_when_the_rule_already_covers_the_active_profile(
        netsh, monkeypatch, capsys):
    netsh()
    monkeypatch.setattr("seltransfer.cli.current_firewall_profile",
                        lambda: "public")

    add_rule(profile="any")

    printed = capsys.readouterr().out
    assert "--profile public" not in printed


def test_profiles_are_canonicalised(netsh):
    """The same request must always produce the same rule."""
    recorder = netsh()
    add_rule(profile="public, private")

    assert "profile=private,public" in recorder.added


@pytest.mark.parametrize("bad", ["pubilc", "private,pubilc", "", "   ", "nonsense"])
def test_a_bad_profile_is_rejected_rather_than_ignored(bad):
    """A typo must not silently create a rule that applies to nothing."""
    with pytest.raises(typer.BadParameter):
        normalise_firewall_profiles(bad)
