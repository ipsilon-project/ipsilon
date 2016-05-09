# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

import base64
from cryptography.hazmat.primitives.constant_time import bytes_eq
import os


def generate_random_secure_string(size=32):
    return base64.urlsafe_b64encode(os.urandom(size))[:size]


def constant_time_string_comparison(stra, strb):
    return bytes_eq(str(stra), str(strb))
