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

    def __init__(self, fromlist, keytype, hexkey, comment, filename):
        "Initialize an SSH key"
        self.__fromlist = fromlist
        self.__keytype = keytype
        self.__hexkey = hexkey
        self.__comment = comment
        self.__filename = filename
        self.__marked = False

    def __str__(self):
        "Return a formatted SSH key"
        return self.format(abridge=True)

    @property
    def comment(self):
        "Return the comment field"
        return self.__comment

    @property
    def dictkey(self):
        "Return the string to use as a dictionary key"
        if self.__comment is None:
            return self.__keytype
        return self.__comment + " " + self.__keytype

    @property
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
        if self.__comment is None or len(self.__comment) == 0:
            comstr = ""
        else:
            comstr = " " + self.__comment
        return "%s%s %s%s" % (fromstr, self.__keytype, keystr, comstr)

    @property
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

        alist = sorted(self.__fromlist)
        blist = sorted(otherlist)

        for idx in range(len(alist)):
            if alist[idx] != blist[idx]:
                return False

        return True

    @property
    def hexkey(self):
        "Return the hexadecimal key string"
        return self.__hexkey

    @property
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
            for flist in (fromlist, self.__fromlist):
                for val in flist:
                    fdict[val] = 1
            self.__fromlist = fdict.keys()

    @property
    def keytype(self):
        "Return the SSH key type"
        return self.__keytype

    def set_fromlist(self, newlist):
        "Overwrite the list of host(s)"
        if newlist is None:
            self.__fromlist = None
        else:
            self.__fromlist = []
            for val in newlist:
                self.__fromlist.append(val)


class SSHKeyFile(object):
    """
    Manage a file of SSH public keys
    """
    PAT = re.compile(r"^(from=\"([^\"]+)\"\s+)?(\S+)\s+(\S+)(\s+(.*))?\s*$")
    COMMENT = re.compile(r"^\s*# ?(.*)$")

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
        if key not in self.__keys:
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
        rtnstr = ""
        for key in self.__keys:
            if len(rtnstr) == 0:
                rtnstr = "%s: %s" % (key, self.__keys[key])
            else:
                rtnstr += "\n%s: %s" % (key, self.__keys[key])
        return rtnstr

    def __add_key(self, authkeys, newkey):
        "Add SSHKey 'newkey' to the 'authkeys' dictionary"
        hashstr = newkey.dictkey
        if hashstr not in authkeys:
            authkeys[hashstr] = [newkey, ]
        else:
            match = None
            for key in authkeys[hashstr]:
                if key.hexkey == newkey.hexkey:
                    match = key
                    break
            if match is None:
                if not self.__allow_multiples:
                    return False
                authkeys[hashstr].append(newkey)
            else:
                if newkey.fromlist is None or match.fromlist is None:
                    # if either fromlist is unqualified,
                    # don't need a list of host qualifiers
                    match.set_fromlist(None)
                else:
                    match.merge_fromlist(newkey.fromlist)

        return True

    def __merge_multiple(self, origkeys, error_func=None, ignore_extra=False):
        """
        Check this dictionary of SSH keys against the original dictionary in
        'origkeys'.  Move any original entries which are not in this dictionary
        or any original entries which have been changed to the 'deaddict'
        dictionary.

        Report any errors using 'error_func(msg)'.

        Return a tuple containing (changed, deaddict) where 'changed' is True
        if any keys were added, deleted, or modified.

        """

        # replace duplicated keys with original entries
        self.__replace_duplicate_hexkeys(origkeys)

        changed = False
        deaddict = {}

        delkeys = {}
        delobjs = []

        for key in origkeys.iterkeys():
            if key not in self.__keys:
                if error_func is not None:
                    for val in origkeys[key]:
                        error_func(("Deleted unknown %s key for %s" +
                                    " in \"%s\"") %
                                   (val.keytype, val.comment, val.filename))
                    delkeys[key] = 1
                changed = True
            else:
                for orig in origkeys[key]:

                    match = None
                    kill_key = False

                    for val in self.__keys[key]:
                        if orig.hexkey == val.hexkey:
                            if val.is_marked:
                                continue
                            val.mark()

                            if not orig.fromlist_equals(val.fromlist):
                                if error_func is not None:
                                    error_func(("Found updated %s fromlist" +
                                                " for %s") %
                                               (orig.keytype, orig.comment))
                                val.merge_fromlist(orig.fromlist)
                                kill_key = True

                            match = val
                            break

                    if match is None:
                        for val in self.__keys[key]:
                            if orig.fromlist_equals(val.fromlist):
                                if val.is_marked:
                                    continue
                                val.mark()

                                if error_func is not None:
                                    error_func("Found updated %s key for %s" %
                                               (orig.keytype, orig.comment))

                                match = val
                                kill_key = True
                                break

                    if match is None:
                        if ignore_extra:
                            if error_func is not None:
                                error_func(("Ignoring extra %s key for %s" +
                                            " in \"%s\"") %
                                           (orig.keytype, orig.comment,
                                            orig.filename))
                        else:
                            if error_func is not None:
                                error_func(("Deleted extra %s key for %s" +
                                            " in \"%s\"") %
                                           (orig.keytype, orig.comment,
                                            orig.filename))

                            kill_key = True

                    if kill_key:
                        if key not in deaddict:
                            deaddict[key] = [orig, ]
                        else:
                            deaddict[key].append(orig)
                        if len(origkeys[key]) == 1:
                            delkeys[key] = 1
                        else:
                            delobjs.append(orig)
                        changed = True

        for key in delkeys:
            del origkeys[key]
        for obj in delobjs:
            found = False
            for key in origkeys.iterkeys():
                if obj in origkeys[key]:
                    origkeys[key].remove(obj)
                    found = True
                    break
            if not found and error_func is not None:
                error_func("Could not remove %s key for %s" %
                           (obj.keytype, obj.comment))

        for key in self.__keys.iterkeys():
            for val in self.__keys[key]:
                if not val.is_marked:
                    if error_func is not None:
                        error_func("Found new %s key for %s" %
                                   (val.keytype, val.comment))
                    changed = True

        return (changed, deaddict)

    def __merge_single(self, origkeys, error_func=None):
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
        for key in origkeys.iterkeys():
            if key not in self.__keys:
                if error_func is not None:
                    for val in origkeys[key]:
                        error_func(("Deleted unknown %s key for %s" +
                                    " in \"%s\"") %
                                   (val.keytype, val.comment, val.filename))
                    delkeys[key] = 1
                changed = True
            else:
                for orig in origkeys[key]:
                    if len(self.__keys[key]) != 1:
                        raise SSHKeyException(("Expected one entry for" +
                                               " %s, not %d") %
                                              (key, len(self.__keys[key])))
                    val = self.__keys[key][0]

                    kill_key = False
                    if orig.hexkey != val.hexkey:
                        if error_func is not None:
                            error_func("Found updated %s key for %s" %
                                       (orig.keytype, orig.comment))
                        kill_key = True
                    elif not orig.fromlist_equals(val.fromlist):
                        if error_func is not None:
                            error_func("Found updated %s fromlist for %s" %
                                       (orig.keytype, orig.comment))
                        kill_key = True
                        val.merge_fromlist(orig.fromlist)

                    if kill_key:
                        if key not in deaddict:
                            deaddict[key] = origkeys[key][:]
                        else:
                            deaddict[key] += origkeys[key]
                        changed = True
                    val.mark()

        for key in delkeys:
            del origkeys[key]

        for key in self.__keys.iterkeys():
            for val in self.__keys[key]:
                if not val.is_marked:
                    if error_func is not None:
                        error_func("Found new %s key for %s" %
                                   (val.keytype, val.comment))
                    changed = True

        return (changed, deaddict)

    def __read_directory(self, dirname, error_func=None):
        """
        Read all SSH keys from the files in 'dirname'.
        Report any errors using 'error_func(msg)'.
        Return the dictionary of SSHKey objects.
        """
        keydict = {}
        hexdict = {}
        for fnm in os.listdir(dirname):
            path = os.path.join(dirname, fnm)
            if not os.path.isfile(path):
                continue

            checkdict = self.__read_file(path, error_func)
            for key, ckval in checkdict.iteritems():
                if isinstance(ckval, SSHKey):
                    vlist = (ckval, )
                else:
                    vlist = ckval
                addlist = []
                for val in vlist:
                    if val.hexkey not in hexdict:
                        addlist.append(val)
                    else:
                        error_func("Ignoring \"%s\" key which duplicates"
                                   " earlier \"%s\"" %
                                   (val.comment, hexdict[val.hexkey].comment))
                        continue
                if len(addlist) > 0:
                    if key not in keydict:
                        keydict[key] = addlist
                    elif error_func is not None:
                        error_func("Ignoring %s key for %s from \"%s\""
                                   " (using version from \"%s\")" %
                                   (addlist[0].keytype, addlist[0].comment,
                                    addlist[0].filename,
                                    keydict[key][0].filename))
        return keydict

    def __read_file(self, filename, error_func=None):
        """
        Read all SSH keys from 'filename'.
        Report any errors using 'error_func(msg)'.
        Return the dictionary of SSHKey objects.
        """
        authhex = {}
        with open(filename, "r") as fin:
            for line in fin:
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
                comment = m.group(6)

                obj = SSHKey(fromlist, keytype, keystr, comment, filename)

                if fromlist is None:
                    hexkey = keystr
                else:
                    hexkey = ",".join(fromlist) + " " + keystr
                authhex[hexkey] = obj

        authkeys = {}
        for obj in authhex.itervalues():
            if not self.__add_key(authkeys, obj):
                error_func("Found multiple %s keys for %s in \"%s\"" %
                           (obj.keytype, obj.comment, obj.filename))

        return authkeys

    def __replace_duplicate_hexkeys(self, origkeys):
        """
        Repeatedly replace a duplicated key with the original version
        until all duplicates have been replaced
        """
        while True:
            done = self.__replace_one_duplicate_hexkey(origkeys)
            if done:
                break

    def __replace_one_duplicate_hexkey(self, origkeys):
        "Return False once we've replaced a duplicate key"
        for okey, oval in origkeys.iteritems():
            for nkey, nlist in self.__keys.iteritems():
                for nval in nlist:
                    if nval.hexkey == oval.hexkey and nkey != okey:
                        if len(self.__keys[nkey]) == 1:
                            del self.__keys[nkey]
                        else:
                            del self.__keys[nkey][nlist.index(nval)]
                        if okey not in self.__keys:
                            self.__keys[okey] = []
                        self.__keys[okey].append(oval)
                        return False

        return True

    def add(self, newkey):
        "Add an SSHKey object"
        if not self.__add_key(self.__keys, newkey):
            raise SSHKeyException("A %s key already exists for %s" %
                                  (newkey.keytype, newkey.comment))

    def iteritems(self):
        "Iterate through the data, returning dictionary key/value pairs"
        for key in self.__keys:
            for val in self.__keys[key]:
                yield key, val

    def iterkeys(self):
        "Iterate through the data, returning dictionary keys"
        return self.__keys.iterkeys()

    def merge(self, origkeys, error_func=None, ignore_extra=False):
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
            return self.__merge_single(origkeys, error_func=error_func)

        return self.__merge_multiple(origkeys, error_func=error_func,
                                     ignore_extra=ignore_extra)

    def write(self, filename, file_header=None):
        "Write the SSH keys to 'filename'"
        with open(filename, "w") as fout:
            if file_header is not None:
                print >> fout, "#"
                for hline in file_header.split("\n"):
                    print >> fout, "# " + str(hline)
                print >> fout, "#"
            for key in sorted(self.__keys.iterkeys()):
                for val in self.__keys[key]:
                    print >> fout, val.format()


if __name__ == "__main__":
    import sys

    def print_error(msg):
        print >>sys.stderr, "*** ERROR: %s ***" % msg

    for arg in sys.argv[1:]:
        ssf = SSHKeyFile(arg, error_func=print_error, allow_multiples=True)
