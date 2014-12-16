# Copyright (C) 2014  Simo Sorce <simo@redhat.com>
#
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
    text = t.substitute(**opts)  # pylint: disable=star-args
    with open(destfile, 'w+') as f:
        f.write(text)
