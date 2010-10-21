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

import getpass, os, socket, subprocess, sys, tempfile, time

from fabric.api import sudo, env, put, run, settings, cd, hide, prompt, local, \
     require
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


def fetch_tarball(url, tar):
    """
    Fetch a tarball into the current directory.  Use the fabric 'with
    cd' context manager to set the directory before calling this
    function.
    """
    if not exists(tar):
        run("/usr/bin/wget -q %s;" % url)


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
    local("rm %s" % tmpfile)

put_verbatim = _put_verbatim


def _activate_string():
    """
    Return a string containing the command which activates the user's Python
    virtual environment.
    """
    require("virtualenv_dir", used_for="the path to the user's" +
            " virtualenv directory")

    return "source %s/bin/activate" % env.virtualenv_dir


def _add_cron_job(min, hr, mday, mon, wday, rule, do_local=False):
    """
    Add <rule> to the remote crontab table if the crontab doesn't already
    contain the rule.  See _make_cron_job() for argument details.
    If <do_local> is True, the local crontab is (possibly) altered.
    """
    if do_local:
        frun = local
    else:
        frun = run

    with hide("running", "stdout", "stderr"):
        # -mtime argument can change, so replace it with a wildcard
        #
        greprule = GREP_MTIME_PAT.sub(" .* ", _escape_cron_rule(rule, True))
        grep = frun("crontab -l | grep '%s' || echo no" % greprule)
    if grep == "no":
        remotefile = "/tmp/crontab.%s-%d" % (env.host, os.getpid())
        frun("crontab -l >| %s || exit 0" % remotefile)
        frun("echo '%s' >> %s" % (_make_cron_job(min, hr, mday, mon, wday,
                                                  rule), remotefile))
        frun("crontab %s && rm %s" % (remotefile, remotefile))


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


def _escape_cron_rule(rule, regexp_chars=False):
    """
    Escape quote and backslash characters so the cron rule may be used as
    an argument to other commands.  It is assumed that the string will be
    enclosed in single quotes.  If <regexp_chars> is True, some regular
    expression characters will also be escaped.
    """
    special = ["\\", "'"]
    if regexp_chars:
        special += ("*", "^")
    for ch in special:
        if rule.find(ch) >= 0:
            rule = ("\\" + ch).join(p for p in rule.split(ch))
    return rule


def _fetch_and_install_tarball(url, host_hidden=False):
    """
    Fetch a tar file from <url> and extract it in the current directory.
    (See _fetch_file() for an explanation of <host_hidden>).
    """
    tarfile = _fetch_file(url, host_hidden)
    run("/bin/tar xzf %s" % tarfile)
    run("/bin/rm %s" % tarfile)


def _fetch_file(url, host_hidden=False, do_local=False):
    """
    Fetch a file from <url>, using the local machine as a staging area
    if <host_hidden> is True (indicating that the remote machine is behind
    a firewall).  If <do_local> is True, fetch the file to the local machine.
    """
    if do_local:
        fexists = os.path.exists
        frun = local
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


def _install_python_package(pkgname, url, stage_dir=None, do_local=False):
    """
    Install the Python package (imported inside Python with "import <pkgname>")
    from <url>.  If <stage_dir> is set, the downloaded file is saved there.
    If <do_local> is True, install the file in the local home directory.
    """
    require("host_hidden",
            used_for="determining if the host is behind a firewall")

    if do_local:
        frun = local
        host_hidden = False
    else:
        frun = run
        host_hidden = env.host_hidden

    if not _python_package_exists(pkgname, use_virtualenv=True,
                                  do_local=do_local):
        if stage_dir is None:
            tmpdir = "/tmp"
        else:
            tmpdir = stage_dir

        pyfile = _stage_file(url, tmpdir, host_hidden=host_hidden,
                             do_local=do_local)
        _virtualenv("easy_install %s" % pyfile, do_local=do_local)

        if stage_dir is None:
            frun("rm " + pyfile)


def _make_cron_job(min, hr, mday, mon, wday, rule):
    """
    Format the arguments in a string acceptable to crontab.  The time arguments
    (<min>, <hr>, <mday>, <mon>, and <wday>) are analagous to the first five
    crontab arguments, except that any negative number indicates a wildcard (*)
    argument.
    """
    cron = [min, hr, mday, mon, wday]
    for i in range(len(cron)):
        if cron[i] < 0:
            cron[i] = "*"
        else:
            cron[i] = str(cron[i])

    cron.append(_escape_cron_rule(rule))

    return " ".join(cron)


def _python_package_exists(pkg, use_virtualenv=False, do_local=False):
    """
    Determine if Python package <pkg> is installed on the remote machine.
    If <use_virtualenv> is True, the Python virtual environment is sourced
    before the check.  If <do_local> is True, check for the package on the
    local machine.
    """
    if do_local:
        frun = local
    else:
        frun = run

    with hide("running", "stdout", "stderr"):
        if not use_virtualenv:
            veStr = ""
        else:
            veStr = _activate_string() + "&&"

        return "YES" == frun(("%sif echo import %s | python >/dev/null 2>&1;" +
                              " then echo YES; else echo NO; fi") %
                             (veStr, pkg))


def _stage_file(url, stage_dir, host_hidden=False, do_local=False):
    """
    Download file from <url> to the staging area <stage_dir>.  If <do_local> is
    True, save the file to the local staging area.  (See _fetch_file() for an
    explanation of <host_hidden>).
    """
    if do_local:
        fexists = os.path.exists
        frun = local
    else:
        fexists = _exists
        frun = run

    stageFile = os.path.join(stage_dir, os.path.basename(url))
    if not fexists(stageFile):
        filename = _fetch_file(url, host_hidden=host_hidden, do_local=do_local)
        if filename != stageFile:
            frun("mv %s %s" % (filename, stageFile))

    return stageFile


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
        frun = local
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
        frun = local
    else:
        frun = run

    frun(_activate_string() + "&&" + cmd)
