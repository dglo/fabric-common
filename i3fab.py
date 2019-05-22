#!/usr/bin/env python

"""
i3fab.py
John Jacobsen, NPX Designs, Inc., john@mail.npxdesigns.com
Started: Wed Sep 29 17:31:40 2010

Common fabric tasks.

Prerequisites: fabric python module on PYTHONPATH; python 2.6 (or, for 2.5, add
   from __future__ import with_statement
to the list of imports below).
"""

from __future__ import print_function

import getpass
import os
import sys
import tempfile
from re import sub

from fabric.api import env, hide, local, put, require, run, settings
from fabric.contrib.console import confirm
from fabric.utils import warn


def _exists(path):
    """
    Determine if remote file with path <f> (fully qualified or
    relative to remote user directory) exists.
    """
    with hide('stdout', 'running'):
        answer = run("if [ -e %s ]; then echo YES; else echo NO; fi" % path,
                     pty=False)

    return answer == "YES"

exists = _exists


def confirm_with_details(func):
    """
    Decorator which prints __doc__ for given function, asks the user
    if she really wants to pull the trigger, and executes the function
    if the user said yes.  Use as a normal decorator before any fabric
    target.

    Example usage:

           @confirm_with_details
           def reboot():
               '''
               Reboot remote node
               '''
               sudo('reboot') # Yikes!

    """
    def new(*args, **kwargs):
        "Decorator function which prompts before returning the function"
        if func.__doc__:
            print(func.__doc__)
        if confirm("%s?" % func.__name__, default=False):
            return func(*args, **kwargs)
        else:
            print("skipping %s!" % func.__name__)
        return None

    return new


def _capture_local(cmd, pty=False):
    """
    Call local() with capture enabled to emulate run() behavior
    """
    return local(cmd, capture=True)


def _activate_string():
    """
    Return a string containing the command which activates the user's Python
    virtual environment.
    """
    require("virtualenv_dir", used_for="the path to the user's" +
            " virtualenv directory")

    return "source %s/bin/activate" % env.virtualenv_dir


def _entry_in_crontab(crontext, entry):
    """
    See if <entry> is in text <crontext> from crontab.  Match Dave's
    (pDAQ's) requirement that code is invariant to different values of
    <x> in '-mtime <x>'.

    >>> _entry_in_crontab(None, None)
    False
    >>> _entry_in_crontab("foo", "foo")
    True
    >>> _entry_in_crontab("bar", "foo")
    False
    >>> _entry_in_crontab("* * * * * find 'x' -yoda -mtime blah quantaquanta",
    ...                   "* * * * * find 'x' -yoda -mtime glarch")
    True
    """
    if crontext is None:
        return False
    crontext = sub(r"-mtime\s+(\S+)", "-mtime XXXX", crontext)
    entry = sub(r"-mtime\s+(\S+)", "-mtime XXXX", entry)
    if entry in crontext:
        return True
    return False


def _load_profile_string(do_local=False):
    """
    Return a string containing the command which loads the user's shell
    environment
    """
    if do_local:
        homedir = os.environ["HOME"]
    else:
        with hide("running", "stdout", "stderr"):
            homedir = str(run("echo $HOME", pty=False))

    return "source %s/.bash_profile" % homedir


def stripnl(rawstr):
    "Strip carriage returns ('\r') from the line"
    return sub('\r', '', rawstr)


def _is_bad_cron_line(crontext):
    bad_cron_line = (27, 91, 72, 27, 91, 74)

    if crontext is None or len(crontext) != len(bad_cron_line):
        return False

    for idx, char in enumerate(bad_cron_line):
        if ord(crontext[idx]) != char:
            return False

    return True


def _get_current_cron_text(do_local=False):
    """
    \r's are removed -- they are put there by run() and mess up our inclusion
    testing
    """
    with hide('stdout', 'running'):
        if do_local:
            crontext = stripnl(local("crontab -l 2>/dev/null || exit 0",
                                     capture=True))
        else:
            crontext = stripnl(run("crontab -l 2>/dev/null || exit 0",
                                   pty=False))
            term_error = "TERM environment variable not set."
            if crontext.find(term_error) >= 0:
                crontext = crontext.replace(term_error, "").strip()
                warn("Hacked around TERM env var error")
            if _is_bad_cron_line(crontext):
                crontext = ""
        return crontext


def _add_entry_to_crontext(line, text):
    if len(text) == 0:
        return line
    return text + "\n" + line


def _add_cron_literal(line, load_profile=False, do_local=False):
    """
    Add arbitrary line to a local or remote crontab.
    """
    crontext = _get_current_cron_text(do_local)
    if _entry_in_crontab(crontext, line):
        return

    if load_profile and "SHELL=" not in crontext:
        crontext = "SHELL=/bin/bash\n" + crontext

    crontext = _add_entry_to_crontext(line, crontext)
    if do_local:
        _replace_local_crontab(crontext)
    else:
        _replace_remote_crontab(crontext)


def _write_tempfile_and_return_name(text):
    (handle, tmpfile) = tempfile.mkstemp()
    with os.fdopen(handle, "w") as fout:
        print(text, file=fout)
    return tmpfile


def _replace_local_crontab(crontext):
    local_tmp_file = _write_tempfile_and_return_name(crontext)
    local("crontab " + local_tmp_file)
    os.remove(local_tmp_file)


def _replace_remote_crontab(crontext):
    local_tmp_file = _write_tempfile_and_return_name(crontext)
    # In case remote == local, e.g. localhost
    remote_tmp_file = local_tmp_file + ".remote"
    put(local_tmp_file, remote_tmp_file)
    os.remove(local_tmp_file)
    run("crontab " + remote_tmp_file)
    run("rm " + remote_tmp_file)


def _add_cron_job(minute, hour, mday, mon, wday, rule,
                  load_profile=False, do_local=False):
    """
    Add <rule> to the remote crontab table if the crontab doesn't already
    contain the rule.  See _make_cron_job() for argument details.
    If <do_local> is True, the local crontab is (possibly) altered.
    """
    _add_cron_literal(_make_cron_job(minute, hour, mday, mon, wday, rule),
                      load_profile=load_profile, do_local=do_local)


def _file_contains_text(path, text, do_local=False):
    """
    Return True if <file> contains <text>.  Note this method uses "grep", so
    results may be confusing if <text> contains regular expression characters.
    """

    if do_local:
        frun = _capture_local
    else:
        frun = run

    with hide("running", "stdout", "stderr"):
        # this returns "" if the text was found, and "no" if not found
        rtnstr = frun("grep -q \"%s\" %s || echo no" % (text, path), pty=False)
    return len(rtnstr) == 0


def _get_password(prompt1, prompt2=None):
    """
    Have user enter a password twice, using <prompt1> for the first request
    and <prompt2> to request that they reenter the password for verification.
    If <prompt2> is not set, no verification will be done.
    """
    while True:
        passwd = getpass.getpass(prompt1 + ": ")
        if prompt2 is None:
            break

        pp2 = getpass.getpass(prompt2 + ": ")
        if passwd == pp2:
            break
        print("Password mismatch, please try again.", file=sys.stderr)

    return passwd


def _make_cron_job(minute, hour, mday, mon, wday, rule):
    """
    Format the arguments in a string acceptable to crontab.  The time arguments
    (<minute>, <hour>, <mday>, <mon>, and <wday>) are analagous to the first
    five crontab arguments; an argument of type str is passed verbatim
    (e.g. '*')
    """
    cron = [str(tstr) for tstr in [minute, hour, mday, mon, wday, rule]]
    return " ".join(cron)


def _ssh_genkey(keyfile=".ssh/id_dsa", do_local=False):
    "Generate an SSH key"
    add_homedir = (keyfile[0] != "/")
    if do_local:
        if add_homedir:
            homedir = os.environ["HOME"]
        fexists = os.path.exists
        frun = _capture_local
    else:
        if add_homedir:
            with hide("running", "stdout", "stderr"):
                homedir = run("echo $HOME", pty=False)
        fexists = _exists
        frun = run

    if add_homedir:
        keypath = os.path.join(homedir, keyfile)
    if not fexists(keypath):
        prompt1 = "Enter new SSH passphrase for %s" % env.host
        prompt2 = "Re-enter SSH passphrase"

        passphrase = _get_password(prompt1, prompt2)

        with hide("running"):
            print("Generating SSH key")
            frun("(echo '%s'; echo '%s') | ssh-keygen -t dsa -f '%s'" %
                 (passphrase, passphrase, keypath))


def _svn_checkout(svn_url, dir_name, username=None, update_existing=True,
                  do_local=False):
    """
    Check out the Subversion project from <svn_url> into directory <dir_name>.
    This method makes one attempt to check out without specifying a password.
    On subsequent attempts, it will prompt for the password, giving up after
    three attempts.

    If the project already exists and <update_existing> is True, then
    "svn update" will be run in the project directory.
    if <do_local> is True, the project will be checked out on the local
    machine.
    """
    require("svnpass", used_for="checking out Subversion projects")

    if do_local:
        homedir = os.environ["HOME"]
        fexists = os.path.exists
        frun = _capture_local
    else:
        with hide("running", "stdout", "stderr"):
            homedir = run("echo $HOME", pty=False)
        fexists = _exists
        frun = run

    path = os.path.join(homedir, dir_name)
    if fexists(path):
        if update_existing:
            frun("cd %s && svn up" % path)
    else:
        attempts = -1

        while True:
            if attempts < 0 or env.svnpass is not None:
                tmppass = env.svnpass
            else:
                if username is not None:
                    unm = username
                else:
                    unm = env.user
                prompt = "Enter Subversion password for %s" % unm

                tmppass = _get_password(prompt)

            with hide("running", "warnings", "stderr"):
                with settings(warn_only=True):
                    if username is not None:
                        user_arg = "--username %s " % username
                    else:
                        user_arg = ""
                    print("svn co %s%s %s" % (user_arg, svn_url, path))
                    if tmppass is not None:
                        pass_arg = "--password %s " % tmppass
                    else:
                        pass_arg = ""
                    rtnval = frun("(echo; echo; echo; echo) |" +
                                  " svn co %s%s%s %s" %
                                  (user_arg, pass_arg, svn_url, path),
                                  pty=False)

            if not rtnval.failed:
                if env.svnpass is None:
                    env.svnpass = tmppass
                break

            attempts += 1
            if attempts > 3:
                print("Giving up after %d attempts" % \
                      (attempts - 1), file=sys.stderr)
                break


if __name__ == "__main__":
    import doctest
    doctest.testmod()
