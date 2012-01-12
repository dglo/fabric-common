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

from re import sub
import getpass
import os
import socket
import subprocess
import sys
import tempfile
import time
from fabric.api import (sudo, env, put, run, settings, cd, lcd, hide, prompt,
                        local, require)

from os.path import join, exists as osexists
from fabric.contrib.console import confirm


def _exists(f):
    """
    Determine if remote file with path <f> (fully qualified or
    relative to remote user directory) exists.
    """
    with hide('stdout', 'running'):
        return "YES" == run("if [ -e %s ]; then echo YES; else echo NO; fi" % f)

exists = _exists


def confirm_with_details(f):
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
        if f.__doc__:
            print f.__doc__
        if confirm("%s?" % f.__name__, default=False):
            return f(*args, **kwargs)
        else:
            print "skipping %s!" % f.__name__
    return new


def _capture_local(cmd):
    """
    Call local() with capture enabled to emulate run() behavior
    """
    return local(cmd, capture=True)


def fetch_tarball(url, tar, do_local=False, skip_if_exists=True):
    """
    Fetch a tarball into the current directory, if not already there.
    Use the fabric 'with cd' context manager to set the directory
    before calling this function.
    JEJ 12/3 added a bit of witchcraft to support 'local' fetches
    """
    if do_local:
        run_func = _capture_local
    else:
        run_func = run

    if skip_if_exists:
        skip_test = "test -f "+tar+" ||"
    else:
        skip_test = ""

    run_func("%s /usr/bin/wget -q %s -O %s" % (skip_test, url, tar))


def fetch_tarball_with_cd(url, tar, path=None, do_local=False,
                          skip_if_exists=True):
    """
    Fetches a tarball but sets up the working directory context first
    so that the tar is fetched into the desired area
    """
    if do_local:
        cd_context = lcd
    else:
        cd_context = cd
    with cd_context(path):
        fetch_tarball(url, tar, do_local)

_fetch_tarball_with_cd = fetch_tarball_with_cd


def unpack_tarball(tar):
    """
    Unpack a tarball into the current directory.  Use the fabric 'with
    cd' context manager to set the directory before calling this
    function.
    """
    run("/bin/tar xzf %s" % tar)


def _put_verbatim(fname, txt):
    """
    Write <txt> to <fname> on the remote system.
    """
    (handle, tmpfile) = tempfile.mkstemp()
    f = os.fdopen(handle, "w")
    f.write(txt)
    f.write("\n")
    f.close()
    put(tmpfile, fname)
    os.remove(tmpfile)

put_verbatim = _put_verbatim


def _activate_string():
    """
    Return a string containing the command which activates the user's Python
    virtual environment.
    """
    require("virtualenv_dir", used_for="the path to the user's" +
            " virtualenv directory")

    return ". %s/bin/activate" % env.virtualenv_dir


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
    crontext = sub("-mtime\s+(\S+)", "-mtime XXXX", crontext)
    entry = sub("-mtime\s+(\S+)", "-mtime XXXX", entry)
    if entry in crontext:
        return True
    return False


def stripnl(str):
    return sub('\r','',str)


def _get_current_cron_text(do_local=False):
    """
    \r's are removed -- they are put there by run() and mess up our inclusion
    testing
    """
    with hide('stdout', 'running'):
        if do_local:
            return stripnl(local("crontab -l 2>/dev/null || exit 0",
                                 capture=True))
        else:
            return stripnl(run("crontab -l 2>/dev/null || exit 0"))


def _add_entry_to_crontext(line, text):
    return text+"\n"+line


def _add_cron_literal(line, do_local=False):
    """
    Add arbitrary line to a local or remote crontab.
    """
    crontext = _get_current_cron_text(do_local)
    if _entry_in_crontab(crontext, line):
        return

    crontext = _add_entry_to_crontext(line, crontext)
    if do_local:
        _replace_local_crontab(crontext)
    else:
        _replace_remote_crontab(crontext)


def _write_tempfile_and_return_name(text):
    (handle, tmpfile) = tempfile.mkstemp()
    f = os.fdopen(handle, "w")
    print >> f, text
    f.close()
    return tmpfile


def _replace_local_crontab(crontext):
    local_tmp_file = _write_tempfile_and_return_name(crontext)
    local("crontab "+local_tmp_file)
    os.remove(local_tmp_file)


def _replace_remote_crontab(crontext):
    local_tmp_file = _write_tempfile_and_return_name(crontext)
    remote_tmp_file = local_tmp_file+".remote" # In case remote == local, e.g. localhost
    put(local_tmp_file, remote_tmp_file)
    os.remove(local_tmp_file)
    run("crontab "+remote_tmp_file)
    run("rm "+remote_tmp_file)


def _add_cron_job(min, hr, mday, mon, wday, rule,
                  do_local=False):
    """
    Add <rule> to the remote crontab table if the crontab doesn't already
    contain the rule.  See _make_cron_job() for argument details.
    If <do_local> is True, the local crontab is (possibly) altered.
    """
    _add_cron_literal(
        _make_cron_job(min, hr, mday, mon, wday, rule), do_local)


def _check_tunnel(gateway_host, tunnel_host, local_port):
    """
    Open an ssh tunnel on <local_port> connecting the local host to
    <tunnel_host> via <gateway_host>

    Example: _check_tunnel("access-node", "hidden-node", 12345)
    """

    # assume the tunnel already exists if the port can be opened
    #
    opened = False
    sock = socket.socket()
    try:
        sock.connect(("localhost", local_port))
        opened = True
    except socket.error:
        pass
    sock.close()

    if not opened:
        # open the tunnel
        #
        p = subprocess.Popen("ssh -L %d:%s:22 -f -N %s" %
                             (local_port, tunnel_host, gateway_host), shell=True)

        # wait for tunnel initialization to complete
        #
        connected = False
        while not connected:
            sock = socket.socket()
            try:
                sock.connect(("localhost", local_port))
                connected = True
            except socket.error:
                print "waiting for %s tunnel to be created" % tunnel_host
                time.sleep(1)
            sock.close()


def _expand_tilde(dir, do_local=False):
    """
    Expand a relative path starting with ~ into an absolute path
    """
    if not dir.startswith("~"):
        return dir

    if do_local:
        return os.path.expanduser(dir)

    splitpath = dir.split(os.path.sep)
    with hide("running", "stdout", "stderr"):
        fixed = run("cd %s && pwd" % splitpath[0])
    splitpath[0] = fixed
    return os.path.sep.join(splitpath)


def _extract_file(filename, extract_dir=None, do_local=False):
    """
    Extract archive file <filename>.  If <extract_dir> is not None, the file
    will be extracted into that directory.
    If <do_local> is True, extract the file on the local machine.
    """
    if do_local:
        frun = _capture_local
    else:
        frun = run

    if extract_dir is None:
        cd_cmd = ""
    else:
        cd_cmd = "cd %s && " % extract_dir

    if filename.endswith(".tar"):
        frun(cd_cmd + "tar xvf %s" % filename)
    elif filename.endswith(".tgz") or filename.endswith(".tar.gz"):
        frun(cd_cmd + "tar xzf %s" % filename)
    elif filename.endswith(".tar.bz2"):
        frun(cd_cmd + "tar xjf %s" % filename)
    elif filename.endswith(".zip"):
        frun(cd_cmd + "unzip " + filename)
    else:
        raise Exception("Unknown extension for \"%s\"" %
                        (filename))


def _fetch_and_extract(url, host_hidden=False, do_local=False):
    """
    Fetch a file from <url>, extract it in the current directory, and remove
    the downloaded file.  If <do_local> is True, fetch the file to the local
    machine.
    (See _fetch_file() for an explanation of <host_hidden>).
    """
    filename = _fetch_file(url, host_hidden, do_local)
    _extract_file(filename, do_local)
    run("/bin/rm %s" % filename)

_fetch_and_install_tarball = _fetch_and_extract


def _fetch_file(url, host_hidden=False, do_local=False):
    """
    Fetch a file from <url>, using the local machine as a staging area
    if <host_hidden> is True (indicating that the remote machine is behind
    a firewall).  If <do_local> is True, fetch the file to the local machine.

    Return the name of the fetched file.
    """
    if do_local:
        fexists = os.path.exists
        frun = _capture_local
        host_hidden = False
    else:
        fexists = _exists
        frun = run

    filename = os.path.basename(url)
    if not fexists(filename):
        if not host_hidden:
            frun("wget -q %s" % url)
        else:
            local("wget -q %s" % url)
            put(filename, filename)
            os.remove(filename)

    return filename


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
        rtnstr = frun("grep -q \"%s\" %s || echo no" % (text, path))
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
        print >>sys.stderr, "Password mismatch, please try again."

    return passwd


def _install_python_package(pkgname, url, stage_dir=None, do_local=False,
                            check_version_method=None, check_version_args=None):
    """
    Install the Python package (imported inside Python with "import <pkgname>")
    from <url>.  If <stage_dir> is set, the downloaded file is saved there.
    If <do_local> is True, install the file in the local home directory.
    """
    require("host_hidden",
            used_for="determining if the host is behind a firewall")

    if do_local:
        frun = _capture_local
        host_hidden = False
    else:
        frun = run
        host_hidden = env.host_hidden

    if not _python_package_exists(pkgname, use_virtualenv=True,
                                  do_local=do_local) or \
        (check_version_method is not None and
         not check_version_method(check_version_args)):
        if stage_dir is None:
            tmpdir = "/tmp"
        else:
            tmpdir = _expand_tilde(stage_dir, do_local=do_local)

        pyfile = _stage_file(url, tmpdir, host_hidden=host_hidden,
                             do_local=do_local)
        _virtualenv("easy_install %s" % pyfile, do_local=do_local)

        if stage_dir is None:
            frun("rm " + pyfile)


def _make_cron_job(min, hr, mday, mon, wday, rule):
    """
    Format the arguments in a string acceptable to crontab.  The time arguments
    (<min>, <hr>, <mday>, <mon>, and <wday>) are analagous to the first five
    crontab arguments; an argument of type str is passed verbatim (e.g. '*')
    """
    cron = [str(h) for h in [min, hr, mday, mon, wday, rule]]
    return " ".join(cron)


def _python_package_exists(pkg, use_virtualenv=False, do_local=False):
    """
    Determine if Python package <pkg> is installed on the remote machine.
    If <use_virtualenv> is True, the Python virtual environment is sourced
    before the check.  If <do_local> is True, check for the package on the
    local machine.
    """
    if do_local:
        frun = _capture_local
    else:
        frun = run

    with hide("running", "stdout", "stderr"):
        if not use_virtualenv:
            veStr = ""
        else:
            veStr = _activate_string() + "&&"

        return "YES" == frun(('%s if python -c "import %s" >/dev/null 2>&1;' +
                              ' then echo YES; else echo NO; fi') %
                             (veStr, pkg))


def _remove_cron_rule(rule, do_local=False):
    """
    Remove <rule> from the remote crontab table if the crontab contains
    the rule.
    If <do_local> is True, the local crontab is (possibly) altered.
    """
    if do_local:
        frun = _capture_local
    else:
        frun = run

    with hide("running", "stdout", "stderr"):
        crontext = frun("crontab -l || exit 0")
        if not _entry_in_crontab(crontext, rule):
            return


    (handle, tmpfile) = tempfile.mkstemp()
    f = os.fdopen(handle, "w")
    for line in crontext.split("\n"):
        if line.find(rule) < 0:
            print >>f, line
    f.close()

    with hide("running", "stdout", "stderr"):
        print "Removing cron job %s" % rule
        if not do_local:
            put(tmpfile, tmpfile)

        frun("crontab %s && rm %s" % (tmpfile, tmpfile))

    os.remove(tmpfile)


def _stage_file(url, stage_dir, host_hidden=False, do_local=False):
    """
    Download file from <url> to the staging area <stage_dir>.  If <do_local> is
    True, save the file to the local staging area.  (See _fetch_file() for an
    explanation of <host_hidden>).
    """
    if do_local:
        fexists = os.path.exists
        frun = _capture_local
    else:
        fexists = _exists
        frun = run

    stagePath = os.path.join(stage_dir, os.path.basename(url))
    if not fexists(stagePath):
        if not fexists(stage_dir):
            frun("mkdir -p " + stage_dir)

        if not do_local:
            origDir = None
            stageFile = stagePath
        else:
            origDir = os.getcwd()
            os.chdir(stage_dir)
            stageFile = os.path.basename(stagePath)

        filename = _fetch_file(url, host_hidden=host_hidden,
                               do_local=do_local)
        if filename != stageFile or origDir is None:
            frun("mv %s %s" % (filename, stagePath))
        if origDir is not None:
            os.chdir(origDir)

    return stagePath


def _svn_checkout(svn_url, dir_name, username=None, update_existing=True,
                  do_local=False):
    """
    Check out the Subversion project from <svn_url> into directory <dir_name>.
    This method makes one attempt to check out without specifying a password.
    On subsequent attempts, it will prompt for the password, giving up after
    three attempts.

    If the project already exists and <update_existing> is True, then
    "svn update" will be run in the project directory.
    if <do_local> is True, the project will be checked out on the local machine.
    """
    require("svnpass", used_for="checking out Subversion projects")

    if do_local:
        homedir = os.environ["HOME"]
        fexists = os.path.exists
        frun = _capture_local
    else:
        with hide("running", "stdout", "stderr"):
            homedir = run("echo $HOME")
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
                    u = username
                else:
                    u = env.user
                prompt = "Enter Subversion password for %s" % u

                tmppass = _get_password(prompt)

            with hide("running", "warnings", "stderr"):
                with settings(warn_only=True):
                    if username is not None:
                        user_arg = "--username %s " % username
                    else:
                        user_arg = ""
                    print "svn co %s%s %s" % (user_arg, svn_url, path)
                    if tmppass is not None:
                        pass_arg = "--password %s " % tmppass
                    else:
                        pass_arg = ""
                    rtnval = frun("(echo; echo; echo; echo) | svn co %s%s%s %s" %
                                  (user_arg, pass_arg, svn_url, path))

            if not rtnval.failed:
                if env.svnpass is None:
                    env.svnpass = tmppass
                break

            attempts += 1
            if attempts > 3:
                print >>sys.stderr, "Giving up after %d attempts" % \
                      (attempts - 1)
                break


def _virtualenv(cmd, do_local=False):
    """
    Run <cmd> inside Python virtual environment.  If <do_local> is True, the
    command is run on the local machine.
    """
    if do_local:
        frun = _capture_local
    else:
        frun = run

    frun(_activate_string() + "&&" + cmd)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
