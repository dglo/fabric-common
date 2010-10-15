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


def exists(f):
    """
    Determine if remote file with path <f> (fully qualified or
    relative to remote user directory) exists.
    """
    with hide('stdout', 'running'):
        return "YES" == run("if [ -e %s ]; then echo YES; else echo NO; fi" % f)
_exists = exists


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
        if confirm("%s?" % f.__name__):
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


def put_verbatim(fname, txt):
    """
    Write <txt> to <fname> on the remote system.
    """
    tmpfile = tempfile.mkstemp()
    f = file(tmpfile, "w")
    print >> f, txt
    f.close()
    put(tmpfile, fname)
    local("rm %s" % tmpfile)


def _activate_string():
    """
    Return a string containing the command which activates the user's Python
    virtual environment.
    """
    require("virtualenv_dir", used_for="the path to the user's" +
            " virtualenv directory")

    return "source %s/bin/activate" % env.virtualenv_dir


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


def _python_package_exists(pkg, use_virtualenv=False):
    """
    Determine if Python package <pkg> is installed on the remote machine.
    If <use_virtualenv> is True, the Python virtual environment is sourced
    before the check.
    """
    with hide("running", "stdout", "stderr"):
        if not use_virtualenv:
            veStr = ""
        else:
            veStr = _activate_string() + "&&"

        return "YES" == run(("%sif echo import %s | python >/dev/null 2>&1;" +
                             " then echo YES; else echo NO; fi") %
                            (veStr, pkg))


def _fetch_file(url, host_hidden):
    """
    Fetch a file from <url>, using the local machine as a staging area
    if <host_hidden> is True (indicating that the remote machine is behind
    a firewall).
    """
    filename = os.path.basename(url)
    if not _exists(filename):
        if not host_hidden:
            run("wget -q %s" % url)
        else:
            local("wget -q %s" % url)
            put(filename, filename)
            os.remove(filename)

    return filename


def _install_python_package(pkgname, url, stage_dir=None):
    """
    Install the Python package (imported inside Python with "import <pkgname>")
    from <url>.  If <stage_dir> is set, the downloaded file is saved there.
    """
    if not _python_package_exists(pkgname, True):
        if stage_dir is None:
            tmpdir = "/tmp"
        else:
            tmpdir = stage_dir

        pyfile = _stage_file(url, tmpdir, env.host_hidden)
        _virtualenv("easy_install %s" % pyfile)

        if stage_dir is None:
            run("rm " + pyfile)


def _install_tarball(url, host_hidden=False):
    """
    Fetch a tar file from <url> and extract it in the current directory.
    (See _fetch_file() for an explanation of <host_hidden>).
    """
    tarfile = _fetch_file(url, host_hidden)
    run("/bin/tar xzf %s" % tarfile)
    run("/bin/rm %s" % tarfile)


def _stage_file(url, stage_dir, host_hidden=False):
    """
    Download file from <url> to the staging area <stage_dir>.
    (See _fetch_file() for an explanation of <host_hidden>).
    """
    stageFile = os.path.join(stage_dir, os.path.basename(url))
    if not _exists(stageFile):
        filename = _fetch_file(url, host_hidden)
        if filename != stageFile:
            run("mv %s %s" % (filename, stageFile))

    return stageFile


def _svn_checkout(svn_url, dir_name):
    """
    Check out the Subversion project from <svn_url> into directory <dir_name>.
    This method makes one attempt to check out without specifying a password.
    On subsequent attempts, it will prompt for the password, giving up after
    three attempts.
    """
    require("svnpass", used_for="checking out Subversion projects")

    if not _exists(dir_name):
        attempts = -1

        while True:
            if attempts < 0 or env.svnpass is not None:
                tmppass = env.svnpass
            else:
                prompt = "Enter Subversion password for %s" % env.user

                tmppass = _get_password(prompt)

            with hide("running", "warnings", "stderr"):
                with settings(warn_only=True):
                    print "svn co %s %s" % (svn_url, dir_name)
                    if tmppass is None:
                        pass_arg = ""
                    else:
                        pass_arg = " --password %s " % tmppass
                    rtnval = run("(echo; echo; echo; echo) | svn co %s%s %s" %
                                 (pass_arg, svn_url, dir_name))

            if not rtnval.failed:
                if env.svnpass is None:
                    env.svnpass = tmppass
                break

            attempts += 1
            if attempts > 3:
                print >>sys.stderr, "Giving up after %d attempts" % \
                      (attempts - 1)
                break


def _virtualenv(cmd):
    """
    Run <cmd> inside Python virtual environment.
    """
    run(_activate_string() + "&&" + cmd)
