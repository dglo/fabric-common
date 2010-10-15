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

import tempfile

from fabric.api import sudo, env, put, run, settings, cd, hide, prompt, local
from fabric.contrib.console import confirm


def exists(f):
    """
    Determine if remote file with path <f> (fully qualified or
    relative to remote user directory) exists.
    """
    with hide('stdout', 'running'):
        return "YES" == run("if [ -e %s ]; then echo YES; else echo NO; fi" % f)


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
