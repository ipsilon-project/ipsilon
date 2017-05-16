# Copyright (C) 2017 Ipsilon project Contributors, for license see COPYING

from __future__ import print_function

import sys


class TC(object):
    """Test Control helpers methods.

    This class is here to give methods short names, and users should not need
    to instantiate classes.
    """
    prefix = '**TEST**:'
    output_method = print

    def __init__(self):
        raise Exception("No need to initialize Test Control class instances")

    @staticmethod
    def store_results(lst):
        """Registers an output_method that adds results into lst."""
        @staticmethod
        def putter(msg):
            lst.append(msg)
        TC.output_method = putter

    class case(object):
        def __init__(self, name, should_fail=False):
            self.name = name
            self.should_fail = should_fail

        def __enter__(self):
            TC.output_method(TC.prefix + 'start:' + self.name)

        def __exit__(self, exc_class, exc, tb):
            if exc is None and not self.should_fail:
                TC.output_method(TC.prefix + 'done')
            elif not self.should_fail:
                TC.output_method(TC.prefix + 'fail:' + repr(exc))
                sys.exit(1)
            elif not exc:
                TC.output_method(TC.prefix + 'fail:Should have failed')
                sys.exit(1)
            else:
                # should_fail can either be True, in which any exception counts
                # as pass, or it can be a string, in which case the string
                # needs to occur in the str(exc) to count as a pass
                failed_correctly = False
                if self.should_fail is True:
                    failed_correctly = True
                else:
                    failed_correctly = self.should_fail in str(exc)

                if failed_correctly:
                    TC.output_method(TC.prefix + 'done')
                    return True  # Tell Python to swallow the exception
                else:
                    TC.output_method(TC.prefix + 'fail:' + repr(exc))
                    sys.exit(1)

    @staticmethod
    def info(msg):
        TC.output_method(TC.prefix + 'info:' + msg)

    @staticmethod
    def fail(msg):
        TC.output_method(TC.prefix + 'fail:' + msg)
        sys.exit(1)

    @staticmethod
    def get_result(line):
        """Determines whether the line is a test case result.

        If the input line is a test case result, a tuple is returned with the
        different result fields. If not, None is returned.

        The output tuple depends on the type of result:
        case start: ('start', 'casename')
        case done:  ('done',)
        case fail:  ('fail', 'some error')
        """
        if line.startswith(TC.prefix):
            return tuple(line[len(TC.prefix):].split(':'))
        else:
            return None

    @staticmethod
    def output(result):
        """Prints the result tuple."""
        if result[0] == 'start':
            print('Case %s... ' % result[1], end=' ')
        elif result[0] == 'info':
            print('Info: %s' % result[1])
        elif result[0] == 'done':
            print('SUCCESS')
        elif result[0] == 'fail':
            print('FAILED: %s' % result[1])
