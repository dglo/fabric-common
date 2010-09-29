#!/usr/bin/env python

"""
i3fab.py
John Jacobsen, NPX Designs, Inc., john@mail.npxdesigns.com
Started: Wed Sep 29 17:31:40 2010
"""

def exists(f):
    return "YES" == run("if [ -e %s ]; then echo YES; else echo NO; fi" % f)

if __name__ == "__main__":
    import doctest
    doctest.testmod()

