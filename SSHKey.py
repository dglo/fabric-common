#!/usr/bin/env python

import os
import re


class SSHKeyException(Exception):
    "Generic SSHKey exception"
    pass


class SSHKey(object):
    """
    SSH authorized key
    NOTE: This object only supports the 'from=' option
    """

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
        return self.format(abridge=True)

    def dictkey(self):
        "Return the string to use as a dictionary key"
        if self.__name is None:
            return self.__keytype
        return self.__name + " " + self.__keytype

    def filename(self):
        "Return the name of the file where this key is stored"
        return self.__filename

    def format(self, abridge=False):
        "Return a formatted SSH key"
        if self.__fromlist is None:
            fromstr = ""
        else:
            fromstr = "from=\"%s\" " % ",".join(self.__fromlist)
        if not abridge or len(self.__hexkey) < 16:
            keystr = self.__hexkey
        else:
            keystr = "AA..." + self.__hexkey[-7:]
        if self.__name is None or len(self.__name) == 0:
            namestr = ""
        else:
            namestr = " " + self.__name
        return "%s%s %s%s" % (fromstr, self.__keytype, keystr, namestr)

    def fromlist(self):
        "Return the list of host(s) to which this key applies"
        if self.__fromlist is None:
            return None

        return self.__fromlist[:]

    def fromlist_equals(self, otherlist):
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

    def merge_fromlist(self, fromlist):
        "Merge the list of 'from' strings with this object's list"
        if fromlist is None or self.__fromlist is None:
            self.__fromlist = None
        else:
            fdict = {}
            for f in (fromlist, self.__fromlist):
                for v in f:
                    fdict[v] = 1
            self.__fromlist = fdict.keys()

    def name(self):
        "Return the username"
        return self.__name

    def keytype(self):
        "Return the SSH key type"
        return self.__keytype

    def set_fromlist(self, newlist):
        "Overwrite the list of host(s)"
        if newlist is None:
            self.__fromlist = None
        else:
            self.__fromlist = []
            for v in newlist:
                self.__fromlist.append(v)


class SSHKeyFile(object):
    """
    Manage a file of SSH public keys
    """
    PAT = re.compile(r"^(from=\"([^\"]+)\"\s+)?(\S+)\s+(\S+)(\s+(\S+))?\s*$")
    COMMENT = re.compile(r"^\s*# ?(.*)$")

    AM = True

    def __init__(self, path, error_func=None, allow_multiples=False):
        """
        Read in a list of one or more SSH public keys from 'path'.

        Report any errors using 'error_func' (if specified)
        """
        self.__allow_multiples = allow_multiples
        if not os.path.exists(path):
            raise SSHKeyException("Path \"%s\" does not exist" % path)

        if os.path.isdir(path):
            self.__keys = self.__read_directory(path, error_func)
        else:
            self.__keys = self.__read_file(path, error_func)

    def __delitem__(self, key):
        del self.__keys[key]

    def __getitem__(self, key):
        if not key in self.__keys:
            return None
        return self.__keys[key]

    def __iter__(self):
        for key in self.__keys:
            for val in self.__keys[key]:
                yield val

    def __len__(self):
        tot = 0
        for key in self.__keys:
            tot += len(self.__keys[key])
        return tot

    def __str__(self):
        rtnstr = None
        for k in self.__keys:
            if rtnstr is None:
                rtnstr = "%s: %s" % (k, self.__keys[k])
            else:
                rtnstr += "\n%s: %s" % (k, self.__keys[k])
        return rtnstr

    def __addKey(self, authkeys, newkey):
        "Add SSHKey 'newkey' to the 'authkeys' dictionary"
        hashstr = newkey.dictkey()
        if not hashstr in authkeys:
            authkeys[hashstr] = [newkey, ]
        else:
            match = None
            for key in authkeys[hashstr]:
                if key.hexkey() == newkey.hexkey():
                    match = key
                    break
            if match is None:
                if not self.__allow_multiples:
                    return False
                authkeys[hashstr].append(newkey)
            else:
                if newkey.fromlist() is None or match.fromlist() is None:
                    # if either fromlist is unqualified,
                    # don't need a list of host qualifiers
                    match.set_fromlist(None)
                else:
                    match.merge_fromlist(newkey.fromlist())

        return True

    def __mergeMultiple(self, origkeys, error_func=None):
        """
        Check this dictionary of SSH keys against the original dictionary in
        'origkeys'.  Move any original entries which are not in this dictionary
        or any original entries which have been changed to the 'deaddict'
        dictionary.

        Report any errors using 'error_func(msg)'.

        Return a tuple containing (changed, deaddict) where 'changed' is True
        if any keys were added, deleted, or modified.

        """
        changed = False
        deaddict = {}

        delkeys = {}
        delobjs = []
        for k in origkeys.iterkeys():
            if not k in self.__keys:
                if error_func is not None:
                    for v in origkeys[k]:
                        error_func(("Deleted unknown %s key for %s" +
                                    " in \"%s\"") % \
                                   (v.keytype(), v.name(), v.filename()))
                    delkeys[k] = 1
                changed = True
            else:
                for o in origkeys[k]:

                    match = None
                    killKey = False

                    for v in self.__keys[k]:
                        if o.hexkey() == v.hexkey():
                            if v.is_marked():
                                continue
                            v.mark()

                            if not o.fromlist_equals(v.fromlist()):
                                if error_func is not None:
                                    error_func(("Found updated %s fromlist" +
                                                " for %s") %
                                               (o.keytype(), o.name()))
                                v.merge_fromlist(o.fromlist())

                            match = v
                            killKey = True
                            break

                    if match is None:
                        for v in self.__keys[k]:
                            if o.fromlist_equals(v.fromlist()):
                                if v.is_marked():
                                    continue
                                v.mark()

                                if error_func is not None:
                                    error_func("Found updated %s key for %s" %
                                               (o.keytype(), o.name()))

                                match = v
                                killKey = True
                                break

                    if match is None:
                        if error_func is not None:
                            error_func(("Deleted extra %s key for %s" +
                                        " in \"%s\"") %
                                        (o.keytype(), o.name(), o.filename()))

                        killKey = True

                    if killKey:
                        if not k in deaddict:
                            deaddict[k] = [o, ]
                        else:
                            deaddict[k].append(o)
                        if len(origkeys[k]) == 1:
                            delkeys[k] = 1
                        else:
                            delobjs.append(o)
                        changed = True

        for k in delkeys:
            del origkeys[k]
        for o in delobjs:
            found = False
            for k in origkeys.iterkeys():
                if o in origkeys[k]:
                    origkeys[k].remove(o)
                    found = True
                    break
            if not found and error_func is not None:
                error_func("Could not remove %s key for %s" %
                           (v.keytype(), v.name()))

        for k in self.__keys.iterkeys():
            for v in self.__keys[k]:
                if not v.is_marked():
                    if error_func is not None:
                        error_func("Found new %s key for %s" %
                                   (v.keytype(), v.name()))
                    changed = True

        return (changed, deaddict)

    def __mergeSingle(self, origkeys, error_func=None):
        """
        Check this dictionary of SSH keys against the original dictionary in
        'origkeys'.  Move any original entries which are not in this dictionary
        or any original entries which have been changed to the 'deaddict'
        dictionary.

        Report any errors using 'error_func(msg)'.

        Return a tuple containing (changed, deaddict) where 'changed' is True
        if any keys were added, deleted, or modified.

        """
        changed = False
        deaddict = {}

        delkeys = {}
        for k in origkeys.iterkeys():
            if not k in self.__keys:
                if error_func is not None:
                    for v in origkeys[k]:
                        error_func(("Deleted unknown %s key for %s" +
                                    " in \"%s\"") % \
                                   (v.keytype(), v.name(), v.filename()))
                    delkeys[k] = 1
                changed = True
            else:
                for o in origkeys[k]:
                    if len(self.__keys[k]) != 1:
                        raise SSHKeyException(("Expected one entry for" +
                                               " %s, not %d") %
                                              (k, len(self.__keys[k])))
                    v = self.__keys[k][0]

                    killKey = False
                    if o.hexkey() != v.hexkey():
                        if error_func is not None:
                            error_func("Found updated %s key for %s" %
                                       (o.keytype(), o.name()))
                        killKey = True
                    elif not o.fromlist_equals(v.fromlist()):
                        if error_func is not None:
                            error_func("Found updated %s fromlist for %s" %
                                       (o.keytype(), o.name()))
                        killKey = True
                        v.merge_fromlist(o.fromlist())

                    if killKey:
                        if not k in deaddict:
                            deaddict[k] = origkeys[k][:]
                        else:
                            deaddict[k] += origkeys[k]
                        changed = True
                    v.mark()

        for k in delkeys:
            del origkeys[k]

        for k in self.__keys.iterkeys():
            for v in self.__keys[k]:
                if not v.is_marked():
                    if error_func is not None:
                        error_func("Found new %s key for %s" %
                                   (v.keytype(), v.name()))
                    changed = True

        return (changed, deaddict)

    def __read_directory(self, dirname, error_func=None):
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

            checkdict = self.__read_file(path, error_func)
            for k, v in checkdict.iteritems():
                if not k in keydict:
                    keydict[k] = v
                elif error_func is not None:
                    error_func(("Ignoring %s key for %s from \"%s\"" +
                                " (using version from \"%s\")") % \
                                (v.keytype(), v.name(), v.filename(),
                                 keydict[k][0].filename()))
        return keydict

    def __read_file(self, filename, error_func=None):
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
                m = self.COMMENT.match(line)
                if m:
                    continue

                m = self.PAT.match(line)
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

                if not self.__addKey(authkeys, obj):
                    error_func("Found multiple %s keys for %s in \"%s\"" %
                               (keytype, name, filename))

        return authkeys

    def add(self, newkey):
        "Add an SSHKey object"
        if not self.__addKey(self.__keys, newkey):
            raise SSHKeyException("A %s key already exists for %s" %
                                  (newkey.keytype(), newkey.name()))

    def iteritems(self):
        "Iterate through the data, returning dictionary key/value pairs"
        for key in self.__keys:
            for val in self.__keys[key]:
                yield key, val

    def iterkeys(self):
        "Iterate through the data, returning dictionary keys"
        return self.__keys.iterkeys()

    def merge(self, origkeys, error_func=None):
        """
        Check this dictionary of SSH keys against the original dictionary in
        'origkeys'.  Move any original entries which are not in this dictionary
        or any original entries which have been changed to the 'deaddict'
        dictionary.

        Report any errors using 'error_func(msg)'.

        Return a tuple containing (changed, deaddict) where 'changed' is True
        if any keys were added, deleted, or modified.

        """
        if not self.__allow_multiples:
            return self.__mergeSingle(origkeys, error_func=error_func)

        return self.__mergeMultiple(origkeys, error_func=error_func)

    def write(self, filename, file_header=None):
        "Write the SSH keys to 'filename'"
        with open(filename, "w") as fd:
            if file_header is not None:
                print >> fd, "#"
                for hline in file_header.split("\n"):
                    print >> fd, "# " + str(hline)
                print >> fd, "#"
            for k in sorted(self.__keys.iterkeys()):
                for val in self.__keys[k]:
                    print >> fd, val.format()
