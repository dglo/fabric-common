#!/usr/bin/env python

from __future__ import print_function

import filecmp
import os
import shutil
import tempfile
import unittest

from SSHKey import SSHKeyFile


class KeyLine(object):
    def __init__(self, fromtext, keytype, hexkey, comment):
        if fromtext is None or len(fromtext) == 0:
            self.__fromlist = None
        elif isinstance(fromtext, str):
            self.__fromlist = fromtext.split(",")
        elif isinstance(fromtext, list):
            self.__fromlist = fromtext
        else:
            raise Exception("Unknown fromtext %s<%s>" %
                            (fromtext, type(fromtext)))

        self.__keytype = keytype
        self.__hexkey = hexkey
        self.__comment = comment

    def __repr__(self):
        return str(self)

    def __str__(self):
        if self.__fromlist is None or len(self.__fromlist) == 0:
            fromstr = ""
        else:
            fromstr = "from=\"%s\" " % ",".join(self.__fromlist)
        if self.__comment is None or len(self.__comment) == 0:
            comstr = ""
        else:
            comstr = " " + str(self.__comment)
        return "%s%s %s%s" % (fromstr, self.__keytype, self.__hexkey, comstr)

    def addFromEntries(self, text):
        if text is None or len(text) == 0:
            return
        elif isinstance(text, str):
            newlist = text.split(",")
        elif isinstance(text, list):
            newlist = text
        else:
            raise Exception("Unknown text %s<%s>" % (text, type(text)))

        if self.__fromlist is None:
            self.__fromlist = newlist
        else:
            self.__fromlist += newlist

    @property
    def comment(self):
        return self.__comment

    @property
    def dictkey(self):
        if self.__comment is None:
            return self.__keytype
        return self.__comment + " " + self.__keytype

    @property
    def fromlist(self):
        return self.__fromlist

    def fromlist_equals(self, fromlist):
        if self.__fromlist is None or fromlist is None:
            return self.__fromlist is None and fromlist is None

        if len(self.__fromlist) != len(fromlist):
            return False

        fkeys = {}
        for fl in self.__fromlist:
            fkeys[fl] = 1
        for fl in fromlist:
            if fl not in fkeys:
                return False

        return True

    @property
    def hexkey(self):
        return self.__hexkey

    def is_key(self):
        return True

    @property
    def keytype(self):
        return self.__keytype


class EmptyLine(KeyLine):
    def __init__(self):
        super(EmptyLine, self).__init__(None, None, None, None)

    def __str__(self):
        return ""

    def is_key(self):
        return False


class CommentLine(KeyLine):
    def __init__(self, text):
        super(CommentLine, self).__init__(None, None, None, None)
        self.__text = text

    def __str__(self):
        if self.__text is None or len(self.__text) == 0:
            return "#"

        return "# " + self.__text

    def is_key(self):
        return False


class TestSSHKey(unittest.TestCase):
    def __createFile(self, name, data, dirname=None):
        tmpfile = tempfile.mktemp(suffix=".key", prefix=name, dir=dirname)

        fd = open(tmpfile, "w")
        for d in data:
            print(str(d), file=fd)

        fd.close()

        return tmpfile

    def __addError(self, msg):
        self.__error.append(msg)

    def __checkMergeErrors(self, templateData, deployedData, deployedFile,
                           allow_multiples=False):
        for td in templateData:
            found = None
            for dd in deployedData:
                if td.comment == dd.comment and \
                    td.keytype == dd.keytype and \
                    td.hexkey == dd.hexkey:
                    if found is not None:
                        self.fail("Found multiple matches for %s" % td)

                    if not td.fromlist_equals(dd.fromlist):
                        expErr = "Found updated %s fromlist for %s" % \
                            (td.keytype, td.comment)
                        self.assertTrue(self.__removeError(expErr),
                                        "Didn't see error \"%s\"" % expErr)

                    found = dd
            if found is None:
                for dd in deployedData:
                    if td.comment == dd.comment and \
                        td.keytype == dd.keytype:
                        fromEq = td.fromlist_equals(dd.fromlist)
                        if not allow_multiples or fromEq:
                            if found is not None:
                                self.fail("Found too many matches for %s" % td)

                            expErr = "Found updated %s key for %s" % \
                                (td.keytype, td.comment)
                            self.assertTrue(self.__removeError(expErr),
                                            "Didn't see error \"%s\"" % expErr)

                            found = dd

            if found is None:
                expErr = "Found new %s key for %s" % (td.keytype, td.comment)
                self.assertTrue(self.__removeError(expErr),
                                "Didn't see error \"%s\"" % expErr)

        for dd in deployedData:
            found = None
            partial = None
            for td in templateData:
                if dd.comment == td.comment and \
                    dd.keytype == td.keytype and \
                    dd.hexkey == td.hexkey:
                    if found is not None:
                        self.fail("Found multiple matches for %s" % dd)
                    found = td
            if found is None:
                for td in templateData:
                    if dd.comment == td.comment and \
                        dd.keytype == td.keytype:
                        if not allow_multiples or \
                            dd.fromlist_equals(td.fromlist):
                            if found is not None:
                                self.fail("Found multiple matches for %s" % dd)
                            found = td
                        elif allow_multiples:
                            partial = td

            if found is None:
                if partial is not None:
                    expErr = "Deleted extra %s key for %s in \"%s\"" % \
                        (dd.keytype, dd.comment, deployedFile)
                else:
                    expErr = "Deleted unknown %s key for %s in \"%s\"" % \
                        (dd.keytype, dd.comment, deployedFile)
                self.assertTrue(self.__removeError(expErr),
                                "Didn't see error \"%s\"" % expErr)

        self.assertFalse(self.__hasError(),
                         "Found unexpected merge errors: %s" %
                         str(self.__error))

    def __countKeys(self, data, allow_multiples=False):
        keys = {}
        for d in data:
            if d.is_key():
                k = d.dictkey
                if k not in keys:
                    keys[k] = {d.hexkey: 1, }
                elif allow_multiples:
                    keys[k][d.hexkey] = 1
        num = 0
        for k in keys:
            num += len(keys[k])
        return num

    def __createMerged(self, templateData, deployedData, newKey, mergeType):
        tval = int(mergeType / 4)
        dval = mergeType % 4

        tstate = None
        dstate = None
        active = False

        if dval == 1 or dval == 2:
            if tval == 1:
                tstate = False
                active = True
            elif tval == 2:
                tstate = True
                active = True
            if dval == 1:
                dstate = False
                active = True
            elif dval == 2:
                dstate = True
                active = True
        if tval == 0 and dval == 0:
            active = True
        if active:
            if dstate:
                deployedData.insert(0, newKey)
            elif dstate is not None:
                deployedData.append(newKey)
            if tstate:
                templateData.insert(0, newKey)
            elif tstate is not None:
                templateData.append(newKey)

        return (active, templateData, deployedData)

    def __dumpKeys(self, keys, name):
        print("=== %s" % name)
        for k in keys.iterkeys():
            print("  %s" % str(k))
            for v in keys[k]:
                print("    %s" % str(v))

    def __hasError(self, msg=None):
        if msg is None:
            return len(self.__error) > 0
        return msg in self.__error

    def __removeError(self, msg=None):
        if msg not in self.__error:
            return False

        self.__error.remove(msg)
        return True

    def __validateData(self, sshkeys, data, filename=None):
        for d in data:
            if not d.is_key():
                return

            key = d.dictkey
            if key not in sshkeys.iterkeys():
                self.fail("Cannot find entry for \"%s\"" % key)
            self.assertTrue(isinstance(sshkeys[key], list),
                            "Expected %s entry to be list, not %s" %
                            (key, type(sshkeys[key])))

            match = None
            for k in sshkeys[key]:
                if k.hexkey == d.hexkey:
                    match = k
                    break
            self.assertTrue(match is not None, "Cannot find entry for %s" % d)
            self.assertEqual(d.comment, match.comment,
                             "Expected comment \"%s\" not \"%s\"" %
                             (d.comment, match.comment))
            self.assertEqual(d.keytype, match.keytype,
                             "Expected key type \"%s\" not \"%s\"" %
                             (d.keytype, match.keytype))
            self.assertEqual(d.hexkey, match.hexkey,
                             "Expected key \"%s\" not \"%s\"" %
                             (d.hexkey, match.hexkey))
            self.assertEqual(d.fromlist, match.fromlist,
                             "Expected from list \"%s\" not \"%s\"" %
                             (d.fromlist, match.fromlist))
            self.assertEqual(d.fromlist, match.fromlist,
                             "Expected from list \"%s\" not \"%s\"" %
                             (d.fromlist, match.fromlist))
            if filename is not None:
                self.assertEqual(filename, match.filename,
                                 "Expected file name \"%s\" not \"%s\"" %
                                 (filename, match.filename))
            self.assertFalse(match.is_marked,
                             "Entry \"%s\" should not be marked" % match)
            self.assertEqual(str(d), str(match),
                             "Expected string \"%s\" not \"%s\"" %
                             (str(d), str(match)))

    def setUp(self):
        self.__error = []

    def testRead(self):
        data = (CommentLine("Test file"),
                EmptyLine(),
                KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine("*.spts.icecube.wisc.edu", "ssh-dss", "AAAAabcw==",
                         "me@you"),
                KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                         )

        tmpfile = self.__createFile("testRead", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError)
        finally:
            os.remove(tmpfile)

        self.assertFalse(self.__hasError(),
                         "Error while parsing %s: %s" % (data, self.__error))

        self.assertTrue(len(sshkeys) == self.__countKeys(data),
                        "Expected %d keys, not %d" %
                        (self.__countKeys(data), len(sshkeys)))

        self.__validateData(sshkeys, data, tmpfile)

    def testReadNoMulti(self):
        data = (CommentLine("Test file"),
                EmptyLine(),
                KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine(None, "ssh-dss", "AAAA456w==", "foo@bar.baz"),
                KeyLine("*.spts.icecube.wisc.edu", "ssh-dss", "AAAAabcw==",
                         "me@you"),
                KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                         )

        tmpfile = self.__createFile("testRead", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError)
        finally:
            os.remove(tmpfile)

        # find duplicate keys
        valid = {}
        invalid = []
        for d in data:
            if not d.is_key():
                continue
            if d.dictkey in valid:
                invalid.append(d)
            else:
                valid[d.dictkey] = d

        self.assertEqual(len(invalid), 1,
                         "Expected one invalid key, not %d" % len(invalid))
        self.assertTrue(self.__hasError(),
                        "No error while parsing %s" % (data, ))
        expErr = "Found multiple %s keys for %s in \"%s\"" % \
            (invalid[0].keytype, invalid[0].comment, tmpfile)
        self.assertTrue(self.__removeError(expErr),
                        "Didn't see error \"%s\"" % expErr)
        self.assertFalse(self.__hasError(),
                         "Found extra error(s) while parsing %s: %s" %
                         (data, self.__error))

        self.assertTrue(len(sshkeys) == len(valid),
                        "Expected %d keys, not %d" %
                        (len(valid), len(sshkeys)))

        self.__validateData(sshkeys, valid.values(), tmpfile)

    def testReadDir(self):
        tmpdir = tempfile.mkdtemp()
        try:
            alldata = (KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                       KeyLine("*.spts.icecube.wisc.edu", "ssh-dss",
                               "AAAAabcw==", "me@you"),
                       KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                )

            allkeys = []
            for i in range(len(alldata)):
                tmpfile = self.__createFile("testReadDir%d" % i,
                                            (alldata[i], ), dirname=tmpdir)
                allkeys.append(SSHKeyFile(tmpfile, self.__addError))

                self.assertFalse(self.__hasError(),
                                 "Error while parsing %s: %s" %
                                 (alldata[i], self.__error))

                self.assertTrue(len(allkeys) == i + 1,
                                "Expected %s keys, not %d" %
                                (i + 1, len(allkeys)))

            dirkeys = SSHKeyFile(tmpdir, self.__addError)

            self.assertFalse(self.__hasError(),
                             "Error while parsing %s: %s" %
                             (alldata, self.__error))

            self.assertTrue(len(dirkeys) == len(allkeys),
                            "Expected %s keys, not %d" %
                            (len(allkeys), len(dirkeys)))

            self.__validateData(dirkeys, alldata, None)

        finally:
            shutil.rmtree(tmpdir)

    def testMultiLine(self):
        data = (KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine(None, "ssh-dss", "AAAA987w==", "foo@bar.baz"))

        tmpfile = self.__createFile("testMultiLine", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError,
                                 allow_multiples=False)
        finally:
            os.remove(tmpfile)

        self.assertTrue(self.__hasError(),
                        "No error while parsing %s" % (data, ))
        expErr = "Found multiple %s keys for %s in \"%s\"" % \
            (data[0].keytype, data[0].comment, tmpfile)
        self.assertTrue(self.__removeError(expErr),
                        "Didn't see error \"%s\"" % expErr)
        self.assertFalse(self.__hasError(),
                         "Found extra error(s) while parsing %s: %s" %
                         (data, self.__error))

        self.assertTrue(len(sshkeys) == 1,
                        "Expected 1 key, not %d" % len(sshkeys))

        self.__validateData(sshkeys, (data[0], ), tmpfile)

    def testAdd(self):
        data = (KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine(None, "ssh-dss", "AAAA987w==", "hea@bar.baz"))

        tmpfile = self.__createFile("testAdd_Master", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError)
        finally:
            os.remove(tmpfile)

        self.assertFalse(self.__hasError(),
                         "Error while parsing %s: %s" % (data, self.__error))

        self.assertTrue(len(sshkeys) == len(data),
                        "Expected %d keys, not %d" % (len(data), len(sshkeys)))

        self.__validateData(sshkeys, data, tmpfile)

        data2 = (KeyLine(None, "ssh-dss", "AAAA1a2bw==", "bla@bar.baz"), )

        tmpfile = self.__createFile("testAdd_One", data2)
        try:
            addkey = SSHKeyFile(tmpfile, self.__addError)
        finally:
            os.remove(tmpfile)

        self.assertFalse(self.__hasError(),
                         "Error while parsing %s: %s" % (data, self.__error))

        self.assertTrue(len(addkey) == len(data2),
                        "Expected %d keys, not %d" % (len(data2), len(addkey)))

        self.__validateData(addkey, (data2[0], ), tmpfile)

        for key in addkey:
            sshkeys.add(key)

        self.assertTrue(len(sshkeys) == len(data) + 1,
                        "Expected %d keys, not %d" %
                        (len(data) + 1, len(sshkeys)))

        self.__validateData(sshkeys, (data[0], data[1], data2[0]))

    def testMergeLines(self):
        data = (KeyLine("*.abc", "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine("def", "ssh-dss", "AAAA123w==", "foo@bar.baz"))

        tmpfile = self.__createFile("testMergeLines", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError)
        finally:
            os.remove(tmpfile)

        self.assertFalse(self.__hasError(),
                         "Error while parsing %s: %s" % (data, self.__error))

        self.assertTrue(len(sshkeys) == 1,
                        "Expected 1 key, not %d" % len(sshkeys))

        # get only entry
        entry = None
        for e in sshkeys:
            entry = e

        self.assertFalse(entry.fromlist_equals(data[0].fromlist),
                         "FromList %s should not equal %s" %
                         (entry.fromlist, data[0].fromlist))
        self.assertFalse(entry.fromlist_equals(data[1].fromlist),
                         "FromList %s should not equal %s" %
                         (entry.fromlist, data[1].fromlist))

        merged = KeyLine(data[0].fromlist, data[0].keytype,
                         data[0].hexkey, data[0].comment)
        merged.addFromEntries(data[1].fromlist)
        self.assertTrue(entry.fromlist_equals(merged.fromlist),
                         "FromList %s should not equal %s" %
                         (entry.fromlist, merged.fromlist))

        self.__validateData(sshkeys, (merged, ), tmpfile)

    def testMergeLineNone(self):
        data = (KeyLine("*.abc", "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"))

        tmpfile = self.__createFile("testMergeLinesNone", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError)
        finally:
            os.remove(tmpfile)

        self.assertFalse(self.__hasError(),
                         "Error while parsing %s: %s" % (data, self.__error))

        self.assertTrue(len(sshkeys) == 1,
                        "Expected 1 key, not %d" % len(sshkeys))

        # get only entry
        entry = None
        for e in sshkeys:
            entry = e

        self.assertFalse(entry.fromlist is not None,
                         "FromList %s should be empty" % entry.fromlist)

        self.__validateData(sshkeys, (data[1], ), tmpfile)

    def testMergeKeepBoth(self):
        data = (KeyLine("*.abc", "ssh-dss", "AAAAkeepw==", "foo@bar.baz"),
                KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"))

        tmpfile = self.__createFile("testMergeLinesNone", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError,
                                 allow_multiples=True)
        finally:
            os.remove(tmpfile)

        self.assertFalse(self.__hasError(),
                         "Error while parsing %s: %s" % (data, self.__error))

        self.assertTrue(len(sshkeys) == len(data),
                        "Expected %d key, not %d" % (len(data), len(sshkeys)))

        self.__validateData(sshkeys, data, tmpfile)

    def testFromEquals(self):
        nofrom = KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz")
        hasfrom = KeyLine("abc,xyz", "ssh-dss", "AAAA456w==", "me@you")
        data = (nofrom, hasfrom)

        tmpfile = self.__createFile("testFromEquals", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError)
        finally:
            os.remove(tmpfile)

        self.assertFalse(self.__hasError(),
                         "Error while parsing %s: %s" % (data, self.__error))

        self.assertTrue(len(sshkeys) == self.__countKeys(data),
                        "Expected %d keys, not %d" %
                        (self.__countKeys(data), len(sshkeys)))

        for entry in sshkeys:
            if entry.comment == nofrom.comment:
                match = nofrom
                diff = hasfrom
            else:
                match = hasfrom
                diff = nofrom

            self.assertTrue(entry.fromlist_equals(match.fromlist),
                            "FromList %s should equal %s" %
                            (entry.fromlist, match.fromlist))
            self.assertFalse(entry.fromlist_equals(diff.fromlist),
                             "FromList %s should not equal %s" %
                             (entry.fromlist, diff.fromlist))
            if match == hasfrom:
                numList = ["123", "456"]
                self.assertFalse(entry.fromlist_equals(numList),
                                 "FromList %s should not equal %s" %
                                 (entry.fromlist, numList))

    def testReadWrite(self):
        data = (CommentLine(""),
                CommentLine("Test file"),
                CommentLine(""),
                KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine("*.spts.icecube.wisc.edu", "ssh-dss", "AAAAabcw==",
                         "me@you"),
                KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                         )

        tmpfile = self.__createFile("testReadWrite", data)
        try:
            sshkeys = SSHKeyFile(tmpfile, self.__addError)

            self.assertFalse(self.__hasError(),
                             "Error while parsing %s: %s" %
                             (data, self.__error))

            self.assertTrue(len(sshkeys) == self.__countKeys(data),
                            "Expected %d keys, not %d" %
                            (self.__countKeys(data), len(sshkeys)))

            self.__validateData(sshkeys, data, tmpfile)

            tmpcopy = self.__createFile("testReadWrite_Copy", data)
            try:
                sshkeys.write(tmpcopy, "Test file")

                filesMatch = filecmp.cmp(tmpfile, tmpcopy)
                if not filesMatch:
                    print("== Original file")
                    with open(tmpfile, "r") as fd:
                        for line in fd:
                            print(line.rstrip())
                    print("== Copied file")
                    with open(tmpcopy, "r") as fd:
                        for line in fd:
                            print(line.rstrip())

                    self.assertTrue(filesMatch,
                                    "Written file does not match original")

                sshkeys2 = SSHKeyFile(tmpcopy, self.__addError)
            finally:
                os.remove(tmpcopy)

                self.assertFalse(self.__hasError(),
                                 "Error while parsing %s: %s" %
                                 (data, self.__error))

            self.assertTrue(len(sshkeys2) == self.__countKeys(data),
                            "Expected %d keys, not %d" %
                            (self.__countKeys(data), len(sshkeys2)))

            for key in sshkeys.iterkeys():
                self.assertTrue(key in sshkeys2.iterkeys(),
                                "Didn't find \"%s\" in written file" % key)

        finally:
            os.remove(tmpfile)

    def testMergeNoChange(self):
        templateData = (KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                        KeyLine("*.spts.icecube.wisc.edu", "ssh-dss",
                                "AAAAabcw==", "me@you"),
                        KeyLine("*.sps.icecube.wisc.edu",
                                "ssh-dss", "AAAAA1B2C3w==", "multi@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                        KeyLine(None, "ssh-dss", "AAAAlmnop==", "old@bar.baz"),
            )

        deployedData = (KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                        KeyLine("*.spts.icecube.wisc.edu", "ssh-dss",
                                "AAAAabcw==", "me@you"),
                        KeyLine("*.sps.icecube.wisc.edu",
                                "ssh-dss", "AAAAA1B2C3w==", "multi@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                        KeyLine(None, "ssh-dss", "AAAAlmnop==", "old@bar.baz"),
            )

        try:
            mfile = self.__createFile("testMrgNoChgTmpl", templateData)
            templateKeys = SSHKeyFile(mfile, self.__addError,
                                      allow_multiples=False)

            self.assertFalse(self.__hasError(),
                             "Error while parsing %s: %s" %
                             (templateData, self.__error))

            try:
                cfile = self.__createFile("testMrgNoChgCheck", deployedData)
                deployedKeys = SSHKeyFile(cfile, self.__addError)

                self.assertFalse(self.__hasError(),
                                 "Error while parsing %s: %s" %
                                 (deployedData, self.__error))

            finally:
                os.remove(cfile)
        finally:
            os.remove(mfile)

        self.assertTrue(len(templateKeys) == self.__countKeys(templateData),
                        "Expected %d keys, not %d" %
                        (self.__countKeys(templateData), len(templateKeys)))
        self.assertTrue(len(deployedKeys) == self.__countKeys(deployedData),
                        "Expected %d keys, not %d" %
                        (self.__countKeys(deployedData), len(deployedKeys)))

        (changed, deaddict) = templateKeys.merge(deployedKeys, self.__addError)
        self.assertFalse(changed, "Unexpected change while merging")
        self.assertEqual(len(deaddict), 0,
                         "Found unexpected dead entries %s" % str(deaddict))

        self.assertFalse(self.__hasError(), "Error while merging")

        self.__checkMergeErrors(templateData, deployedData, cfile)

    def testMergeNoMulti(self):
        templateData = (KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                        KeyLine("*.spts.icecube.wisc.edu", "ssh-dss",
                                "AAAAabcw==", "me@you"),
                        KeyLine("*.sps.icecube.wisc.edu",
                                "ssh-dss", "AAAAA1B2C3w==", "multi@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                        KeyLine(None, "ssh-dss", "AAAAlmnop==", "new@bar.baz"),
            )

        deployedData = (KeyLine(None, "ssh-dss", "AAAA456w==", "foo@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAaaaw==", "old@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAqrsw==",
                                "multi@bar.baz"),
                        KeyLine("*.sps.icecube.wisc.edu," +
                                "cygnus.icecube.wisc.edu",
                                "ssh-dss", "AAAAabcw==", "me@you"),
            )

        try:
            mfile = self.__createFile("TestMrgNoMuTmpl", templateData)
            templateKeys = SSHKeyFile(mfile, self.__addError)

            self.assertFalse(self.__hasError(),
                             "Error while parsing %s: %s" %
                             (templateData, self.__error))

            try:
                cfile = self.__createFile("TestMrgNoMuCheck", deployedData)
                deployedKeys = SSHKeyFile(cfile, self.__addError)

                self.assertFalse(self.__hasError(),
                                 "Error while parsing %s: %s" %
                                 (deployedData, self.__error))

            finally:
                os.remove(cfile)
        finally:
            os.remove(mfile)

        self.assertTrue(len(templateKeys) == self.__countKeys(templateData),
                        "Expected %d keys, not %d" %
                        (self.__countKeys(templateData), len(templateKeys)))
        self.assertTrue(len(deployedKeys) == self.__countKeys(deployedData),
                        "Expected %d keys, not %d" %
                        (self.__countKeys(deployedData), len(deployedKeys)))

        (changed, deaddict) = templateKeys.merge(deployedKeys, self.__addError)
        self.assertTrue(changed, "Expected change while merging")
        self.assertEqual(len(deaddict), 3, "Expected %d dead entries, not %d" %
                         (3, len(deaddict)))

        self.assertTrue(self.__hasError(), "No error while merging")

        self.__checkMergeErrors(templateData, deployedData, cfile,
                                allow_multiples=False)

    def testMergeMulti(self):
        templateBase = [KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                        KeyLine("*.spts.icecube.wisc.edu", "ssh-dss",
                                "AAAAabcw==", "me@you"),
                        KeyLine("*.sps.icecube.wisc.edu",
                                "ssh-dss", "AAAAA1B2C3w==", "multi@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                        KeyLine(None, "ssh-dss", "AAAAlmnop==", "new@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAaaaa==",
                                "nomas@bar.baz"),
                        ]

        deployedBase = [KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                        KeyLine(None, "ssh-dss", "AAAAaaaw==", "old@bar.baz"),
                        KeyLine("*.bar.baz",
                                "ssh-dss", "AAAAA1B2C3w==", "multi@bar.baz"),
                        KeyLine("*.sps.icecube.wisc.edu," +
                                "cygnus.icecube.wisc.edu",
                                "ssh-dss", "AAAAabcw==", "me@you"),
                        KeyLine(None, "ssh-dss", "AAAAbbbb==",
                                "nomas@bar.baz"),
                        ]

        extraKey = KeyLine(None, "ssh-dss", "AAAAX9Y8Z7w==", "multi@bar.baz")

        for mergeType in range(0, 12):
            (active, templateData, deployedData) = \
                self.__createMerged(templateBase[:], deployedBase[:], extraKey,
                                    mergeType)
            if not active:
                continue

            try:
                mfile = self.__createFile("testMrgMuTmpl", templateData)
                templateKeys = SSHKeyFile(mfile, self.__addError,
                                          allow_multiples=True)

                self.assertFalse(self.__hasError(),
                                 "Error while parsing %s: %s" %
                                 (templateData, self.__error))

                try:
                    cfile = self.__createFile("testMrgMuCheck", deployedData)
                    deployedKeys = SSHKeyFile(cfile, self.__addError,
                                           allow_multiples=True)

                    self.assertFalse(self.__hasError(),
                                     "Error while parsing %s: %s" %
                                     (deployedData, self.__error))

                finally:
                    os.remove(cfile)
            finally:
                os.remove(mfile)

            self.assertTrue(len(templateKeys) ==
                            self.__countKeys(templateData,
                                             allow_multiples=True),
                            "Expected %d keys, not %d" %
                            (self.__countKeys(templateData),
                             len(templateKeys)))
            self.assertTrue(len(deployedKeys) ==
                            self.__countKeys(deployedData,
                                             allow_multiples=True),
                            "Expected %d keys, not %d" %
                            (self.__countKeys(deployedData,
                                              allow_multiples=True),
                             len(deployedKeys)))

            (changed, deaddict) = templateKeys.merge(deployedKeys,
                                                     self.__addError)

            self.assertTrue(self.__hasError(), "No error while merging")

            self.__checkMergeErrors(templateData, deployedData, cfile,
                                    allow_multiples=True)

    def testIterItemsMulti(self):
        data = (KeyLine(None, "ssh-dss", "AAAA123w==", "foo@bar.baz"),
                KeyLine("*.spts.icecube.wisc.edu", "ssh-dss",
                        "AAAAabcw==", "me@you"),
                KeyLine("*.bar.baz", "ssh-dss",
                        "AAAAX9Y8W7w==", "multi@bar.baz"),
                KeyLine("*.sps.icecube.wisc.edu",
                        "ssh-dss", "AAAAA1B2C3w==", "multi@bar.baz"),
                KeyLine(None, "ssh-dss", "AAAAxyzw==", None),
                KeyLine(None, "ssh-dss", "AAAAlmnop==", "old@bar.baz"),
                KeyLine(None, "ssh-dss", "AAAAaaaa==", "nomas@bar.baz"),
            )

        try:
            tmpfile = self.__createFile("testIterItemsMulti", data)
            sshkeys = SSHKeyFile(tmpfile, self.__addError,
                                 allow_multiples=True)

            self.assertFalse(self.__hasError(),
                             "Error while parsing %s: %s" %
                             (data, self.__error))
        finally:
            os.remove(tmpfile)

        self.assertTrue(len(sshkeys) == len(data),
                        "Expected %d keys, not %d" % (len(data), len(sshkeys)))
        self.assertTrue(len(sshkeys) == self.__countKeys(data,
                                                         allow_multiples=True),
                        "Expected %d keys, not %d" %
                        (self.__countKeys(data, allow_multiples=True),
                         len(sshkeys)))

        self.__validateData(sshkeys, data, tmpfile)

        for k, v in sshkeys.iteritems():
            found = False
            for d in data:
                if v.comment == d.comment and v.keytype == d.keytype and \
                    v.hexkey == d.hexkey:
                    found = True
                    break
            self.assertTrue(found, "Didn't find key for %s" % k)


if __name__ == '__main__':
    unittest.main()
