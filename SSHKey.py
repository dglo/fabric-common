#!/usr/bin/env python

import os
import re
import sys

class SSHKey(object):
    """
    SSH authorized key
    NOTE: This object only supports the 'from=' option
    """
    PAT = re.compile(r"(from=\"([^\"]+)\"\s+)?(\S+)\s+(\S+)(\s+(\S+))?\s*")
    COMMENT = re.compile(r"^\s*# ?(.*)$")

    def __init__(self, fromlist, keytype, hexkey, name, filename):
        "Initialize an SSH key"
        self.__fromlist = fromlist
        self.__keytype = keytype
        self.__hexkey = hexkey
        self.__name = name
        self.__filename = filename
        self.__marked = False

    def __str__(self):
        "Return a formatted SSH key"
        if self.__fromlist is None:
            fromstr = ""
        else:
            fromstr = "from=\"%s\" " % ",".join(self.__fromlist)
        if self.__name is None or len(self.__name) == 0:
            namestr = ""
        else:
            namestr = " " + self.__name
        return "%s%s %s%s" % (fromstr, self.__keytype, self.__hexkey, namestr)

    def filename(self):
        "Return the name of the file where this key is stored"
        return self.__filename

    def fromlist(self):
        "Return the list of host to which this key applies"
        if self.__fromlist is None:
            return None

        return self.__fromlist[:]

    def fromlistEquals(self, otherlist):
        "Return True if this key's fromlist matches 'otherlist'"
        if self.__fromlist is None:
            if otherlist is None:
                return True
            return False
        elif otherlist is None:
            return False

        if len(self.__fromlist) != len(otherlist):
            return False

        alist = self.__fromlist[:]
        alist.sort()

        blist = otherlist[:]
        blist.sort()

        for n in range(len(alist)):
            if alist[n] != blist[n]:
                return False

        return True

    def hexkey(self):
        "Return the hexadecimal key string"
        return self.__hexkey

    def is_marked(self):
        "Has this key been marked to be saved?"
        return self.__marked

    def mark(self):
        "Mark this key so it will be saved"
        self.__marked = True

    @classmethod
    def merge_dicts(cls, masterdict, checkdict, error_func=None):
        """
        Check the master dictionary of SSH keys against 'checkdict'.
        Move any entries not found in the master list, or any modified
        entries to the dead key dictionary.  Set 'changed' to True if
        any keys were added, deleted, or modified.  Report any errors
        using 'error_func(msg)'.

        Return a tuple containing (changed, deaddict)
        """
        changed = False
        deaddict = {}

        delkeys = []
        for k, v in checkdict.iteritems():
            if not k in masterdict:
                if error_func is not None:
                    error_func("Deleting unknown %s key for %s in \"%s\"" % \
                               (v.keytype(), v.name(), v.filename()))
                delkeys.append(k)
                changed = True
            else:
                if v.hexkey() != masterdict[k].hexkey() or \
                    not v.fromlistEquals(masterdict[k].fromlist()):
                    if error_func is not None:
                        error_func("Found updated %s key for %s" %
                                   (v.keytype(), v.name()))
                    deaddict[k] = checkdict[k]
                    changed = True
                masterdict[k].mark()

        for k in delkeys:
            deaddict[k] = checkdict[k]
            del checkdict[k]

        for k, v in masterdict.iteritems():
            if not v.is_marked():
                if error_func is not None:
                    error_func("Found new %s key for %s" %
                               (v.keytype(), v.name()))
                changed = True

        return (changed, deaddict)

    def name(self):
        "Return the username"
        return self.__name

    def keytype(self):
        "Return the SSH key type"
        return self.__keytype

    @classmethod
    def read_directory(cls, dirname, error_func=None):
        """
        Read all SSH keys from the files in 'dirname'.
        Report any errors using 'error_func(msg)'.
        Return the dictionary of SSHKey objects.
        """
        keydict = {}
        for f in os.listdir(dirname):
            path = os.path.join(dirname, f)
            if not os.path.isfile(path):
                continue

            checkdict = SSHKey.read_file(path, error_func)
            for k,v in checkdict.iteritems():
                if not k in keydict:
                    keydict[k] = v
                elif error_func is not None:
                    error_func(("Ignoring %s key for %s from \"%s\"" +
                                " (using version from \"%s\")") % \
                                (v.keytype(), v.name(), v.filename(),
                                 keydict[k].filename()))
        return keydict

    @classmethod
    def read_file(cls, filename, error_func=None):
        """
        Read all SSH keys from 'filename'.
        Report any errors using 'error_func(msg)'.
        Return the dictionary of SSHKey objects.
        """
        authkeys = {}
        with open(filename, "r") as fd:
            for line in fd:
                line = line.rstrip()
                if len(line) == 0:
                    continue

                # silently delete any comments
                m = cls.COMMENT.match(line)
                if m:
                    continue

                m = cls.PAT.match(line)
                if not m:
                    if error_func is not None:
                        error_func("Bad line \"%s\" in \"%s\"" %
                                   (line, filename))
                    continue

                if m.group(2) is None:
                    fromlist = None
                else:
                    fromlist = m.group(2).split(",")
                keytype = m.group(3)
                keystr = m.group(4)
                name = m.group(6)

                obj = SSHKey(fromlist, keytype, keystr, name, filename)

                if name is None:
                    hashstr = keytype
                else:
                    hashstr = name + " " + keytype
                if not hashstr in authkeys:
                    authkeys[hashstr] = obj
                else:
                    prev = authkeys[hashstr]
                    if prev.hexkey() != keystr:
                        authkeys[hashstr] = obj
                        if error_func is not None:
                            error_func(("Found multiple %s keys for %s" +
                                        " in \"%s\"") %
                                        (keytype, name, filename))
                    else:
                        # Merge 'from' lists for identical keys
                        fdict = {}
                        for f in (fromlist, prev.fromlist()):
                            if f is not None:
                                for v in fromlist:
                                    fdict[v] = 1
                        fromlist = fdict.keys()

        return authkeys

    @classmethod
    def write_file(cls, filename, keydict, file_header=None):
        "Write the SSH keys to 'filename'"
        with open(filename, "w") as fd:
            if file_header is not None:
                print >>fd, "#"
                for hline in file_header.split("\n"):
                    print >>fd, "# " + str(hline)
                print >>fd, "#"
            for k in sorted(keydict.iterkeys()):
                print >>fd, str(keydict[k])

if __name__ == "__main__":
    import optparse
    import sys

    def warn(msg):
        print >>sys.stderr, "!!! " + msg

    p = optparse.OptionParser()

    p.add_option("-c", "--valid_key_dir", type="string", dest="validKeyDir",
                 action="store", default=None,
                 help="Directory holding valid SSH keys")

    opt, args = p.parse_args()

    if opt.validKeyDir is None:
        p.error("Please specify the valid SSH key directory" +
                " using \"-c dirname\"")
    elif not os.path.isdir(opt.validKeyDir):
        p.error("Directory \"%s\" does not exist" % opt.validKeyDir)

    masterdict = SSHKey.read_directory(opt.validKeyDir, warn)

    for arg in args:
        print "==================== %s" % arg
        checkdict = SSHKey.read_file(arg, warn)

        (changed, deaddict) = SSHKey.merge_dicts(masterdict, checkdict, warn)

        if len(deaddict):
            SSHKey.write_file("deadkeys", deaddict)
            print "Preserved %d keys" % len(deaddict)

        if changed:
            SSHKey.write_file("newkeys", masterdict)
            print "!! File has been updated !!"
