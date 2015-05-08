# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import os
import pwd
from string import Template


def fix_user_dirs(path, user=None, mode=0700):
    pw = None
    if user:
        pw = pwd.getpwnam(user)
    for t in os.walk(path, topdown=False):
        root, files = t[0], t[2]
        for name in files:
            target = os.path.join(root, name)
            if pw:
                os.chown(target, pw.pw_uid, pw.pw_gid)
            os.chmod(target, mode & 0666)
        if pw:
            os.chown(root, pw.pw_uid, pw.pw_gid)
        os.chmod(root, mode)


def write_from_template(destfile, template, opts):
    with open(template) as f:
        t = Template(f.read())
    text = t.substitute(**opts)
    with open(destfile, 'w+') as f:
        f.write(text)
