# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
import copy
import sys


class Policy(Log):

    def __init__(self, mappings=None, allowed=None):
        """ A Policy engine to filter attributes.
        Mappings is a list of lists where the first value ia a list itself
        and the second value is an attribute name or a list if the values
        should go in a sub dictionary.
        Note that mappings is a list and not a dictionary as this allows
        to map the same original attribute to different resulting attributes
        if wanted, by simply repeating the 'key list' with different values
        or 'value lists'.

            Example: [[['extras', 'shoes'], 'shoeNumber']]

        A '*' can be used to allow any attribute.

        The default mapping is [[['*'], '*']]
        This copies all attributes without transformation.

        Allowed is a list of allowed attributes.
        Normally mapping should be called before filtering, this means
        allowed attributes should name the mapped attributes.
        Allowed attributes can be multi-element lists

            Example: ['fullname', ['groups', 'domain users']]

        Allowed is '*' by default.
        """

        self.mappings = None
        if mappings:
            if not isinstance(mappings, list):
                raise ValueError("Mappings should be a list not '%s'" %
                                 type(mappings))
            for el in mappings:
                if not isinstance(el, list):
                    raise ValueError("Mappings must be lists, not '%s'" %
                                     type(el))
                if len(el) != 2:
                    raise ValueError("Mappings must contain 2 elements, "
                                     "found %d" % len(el))
                if isinstance(el[0], list) and len(el[0]) > 2:
                    raise ValueError("1st Mapping element can contain at "
                                     "most 2 values, found %d" % len(el[0]))
                if isinstance(el[1], list) and len(el[1]) > 2:
                    raise ValueError("2nd Mapping element can contain at "
                                     "most 2 values, found %d" % len(el[1]))
            self.mappings = mappings
        else:
            # default mapping, return all userdata and groups
            # but ignore extras
            self.mappings = [['*', '*']]

        self.allowed = ['*']
        if allowed:
            if not isinstance(allowed, list):
                raise ValueError("Allowed should be a list not '%s'" %
                                 type(allowed))
            self.allowed = allowed

    def map_attributes(self, attributes, ignore_case=False):

        if not isinstance(attributes, dict):
            raise ValueError("Attributes must be dictionary, not %s" %
                             type(attributes))

        not_mapped = copy.deepcopy(attributes)
        mapped = dict()

        # If ignore_case is True,
        # then PD translates case insensitively prefixes
        PD = dict()
        for k in attributes.keys():
            if ignore_case:
                # note duplicates that differ only by case
                # will be lost here, beware!
                PD[k.lower()] = k
            else:
                PD[k] = k

        for (key, value) in self.mappings:
            if not isinstance(key, list):
                key = [key]
            if len(key) == 2:
                prefix = key[0]
                name = key[1]
            else:
                prefix = None
                name = key[0]

            if not isinstance(value, list):
                value = [value]
            if len(value) == 2:
                mapprefix = value[0]
                mapname = value[1]
            else:
                mapprefix = None
                mapname = value[0]

            if ignore_case:
                if prefix:
                    prefix = prefix.lower()
                name = name.lower()

            if prefix:
                if prefix in PD:
                    attr = attributes[PD[prefix]]
                else:
                    # '*' in a prefix matches nothing
                    continue

                # If ignore_case is True,
                # then ND translates case insensitively names
                ND = dict()
                if isinstance(attr, list):
                    klist = attr
                else:
                    klist = attr.keys()
                for k in klist:
                    if ignore_case:
                        # note duplicates that differ only by case
                        # will be lost here, beware!
                        ND[k.lower()] = k
                    else:
                        ND[k] = k
            else:
                attr = attributes
                ND = PD

            if name in ND and ND[name] in attr:
                if isinstance(attr, list):
                    if mapprefix:
                        if mapprefix not in mapped:
                            mapped[mapprefix] = list()
                        mapped[mapprefix].append(mapname)
                        if not_mapped:
                            if PD[prefix] in not_mapped:
                                while ND[name] in not_mapped[PD[prefix]]:
                                    not_mapped[PD[prefix]].remove(ND[name])
                    else:
                        if mapname not in mapped:
                            mapped[mapname] = list()
                        mapped[mapname].append(attr[ND[name]])
                        if not_mapped:
                            if PD[prefix] in not_mapped:
                                del not_mapped[PD[prefix]]
                else:
                    mapin = copy.deepcopy(attr[ND[name]])
                    if mapname == '*':
                        mapname = ND[name]
                    if mapprefix:
                        if mapprefix not in mapped:
                            mapped[mapprefix] = dict()
                        mapped[mapprefix].update({mapname: mapin})
                    else:
                        mapped.update({mapname: mapin})
                    if not_mapped:
                        if prefix:
                            if PD[prefix] in not_mapped:
                                if ND[name] in not_mapped[PD[prefix]]:
                                    del not_mapped[PD[prefix]][ND[name]]
                        elif ND[name] in not_mapped:
                            del not_mapped[ND[name]]
            elif name == '*':
                mapin = copy.deepcopy(attr)
                # mapname is ignored if name == '*'
                if mapprefix:
                    if mapprefix not in mapped:
                        mapped[mapprefix] = mapin
                    else:
                        mapped[mapprefix].update(mapin)
                else:
                    mapped.update(mapin)
                if not_mapped:
                    if prefix and PD[prefix] in not_mapped:
                        del not_mapped[PD[prefix]]
                    else:
                        not_mapped = None
            else:
                continue

        return mapped, not_mapped

    def filter_attributes(self, attributes, whitelist=True):

        filtered = dict()

        for name in self.allowed:
            if isinstance(name, list):
                key = name[0]
                value = name[1]
                if key in attributes:
                    attr = attributes[key]
                    if value == '*':
                        filtered[key] = attr
                    elif isinstance(attr, dict):
                        if key not in filtered:
                            filtered[key] = dict()
                        if value in attr:
                            filtered[key][value] = attr[value]
                    elif isinstance(attr, list):
                        if key not in filtered:
                            filtered[key] = list()
                        if value in attr:
                            filtered[key].append(value)
                    else:
                        continue
            else:
                if name in attributes:
                    filtered[name] = attributes[name]
                elif name == '*':
                    filtered = attributes

        if whitelist:
            allowed = filtered
        else:
            # filtered contains the blacklisted
            allowed = copy.deepcopy(attributes)
            for lvl1 in filtered:
                attr = filtered[lvl1]
                if isinstance(attr, dict):
                    for lvl2 in attr:
                        del allowed[lvl1][lvl2]
                elif isinstance(attr, list):
                    for lvl2 in attr:
                        allowed[lvl1].remove(lvl2)
                else:
                    allowed[lvl1] = {}
                if len(allowed[lvl1]) == 0:
                    del allowed[lvl1]

        return allowed

# Unit tests
if __name__ == '__main__':

    ret = 0

    # Policy
    t_attributes = {'onenameone': 'onevalueone',
                    'onenametwo': 'onevaluetwo',
                    'two': {'twonameone': 'twovalueone',
                            'twonametwo': 'twovaluetwo'},
                    'three': {'threenameone': 'threevalueone',
                              'threenametwo': 'threevaluetwo'},
                    'four': {'fournameone': 'fourvalueone',
                             'fournametwo': 'fourvaluetwo'},
                    'five': ['one', 'two', 'three'],
                    'six': ['one', 'two', 'three']}

    # test defaults first
    p = Policy()

    print 'Default attribute mapping'
    m, n = p.map_attributes(t_attributes)
    if m == t_attributes and n is None:
        print 'SUCCESS'
    else:
        ret += 1
        print 'FAIL: Expected %s\nObtained %s' % (t_attributes, m)

    print 'Default attribute filtering'
    f = p.filter_attributes(t_attributes)
    if f == t_attributes:
        print 'SUCCESS'
    else:
        ret += 1
        print 'Expected %s\nObtained %s' % (t_attributes, f)

    # test custom mappings and filters
    t_mappings = [[['onenameone'], 'onemappedone'],
                  [['onenametwo'], 'onemappedtwo'],
                  [['two', '*'], '*'],
                  [['three', 'threenameone'], 'threemappedone'],
                  [['three', 'threenameone'], 'threemappedbis'],
                  [['four', '*'], ['four', '*']],
                  [['five'], 'listfive'],
                  [['six', 'one'], ['six', 'mapone']]]

    m_result = {'onemappedone': 'onevalueone',
                'onemappedtwo': 'onevaluetwo',
                'twonameone': 'twovalueone',
                'twonametwo': 'twovaluetwo',
                'threemappedone': 'threevalueone',
                'threemappedbis': 'threevalueone',
                'four': {'fournameone': 'fourvalueone',
                         'fournametwo': 'fourvaluetwo'},
                'listfive': ['one', 'two', 'three'],
                'six': ['mapone']}

    n_result = {'three': {'threenametwo': 'threevaluetwo'},
                'six': ['two', 'three']}

    t_allowed = ['twonameone',
                 ['four', 'fournametwo'],
                 ['listfive', 'three'],
                 ['six', '*']]

    f_result = {'twonameone': 'twovalueone',
                'four': {'fournametwo': 'fourvaluetwo'},
                'listfive': ['three'],
                'six': ['mapone']}

    p = Policy(t_mappings, t_allowed)

    print 'Custom attribute mapping'
    m, n = p.map_attributes(t_attributes)
    if m == m_result and n == n_result:
        print 'SUCCESS'
    else:
        ret += 1
        print 'Expected %s\nObtained %s' % (m_result, m)

    print 'Custom attribute filtering'
    f = p.filter_attributes(m)
    if f == f_result:
        print 'SUCCESS'
    else:
        ret += 1
        print 'Expected %s\nObtained %s' % (f_result, f)

    t2_allowed = ['onemappedone', 'twonametwo', 'threemappedone',
                  ['listfive', 'two']]

    f2_result = {'onemappedtwo': 'onevaluetwo',
                 'twonameone': 'twovalueone',
                 'threemappedbis': 'threevalueone',
                 'four': {'fournameone': 'fourvalueone',
                          'fournametwo': 'fourvaluetwo'},
                 'listfive': ['one', 'three'],
                 'six': ['mapone']}

    p = Policy(t_mappings, t2_allowed)

    print 'Custom attribute filtering 2'
    m, _ = p.map_attributes(t_attributes)
    f = p.filter_attributes(m, whitelist=False)
    if f == f2_result:
        print 'SUCCESS'
    else:
        ret += 1
        print 'Expected %s\nObtained %s' % (f2_result, f)

    # Case Insensitive matching
    tci_attributes = {'oneNameone': 'onevalueone',
                      'onenamEtwo': 'onevaluetwo',
                      'Two': {'twonameone': 'twovalueone',
                              'twonameTwo': 'twovaluetwo'},
                      'thrEE': {'threeNAMEone': 'threevalueone',
                                'thrEEnametwo': 'threevaluetwo'},
                      'foUr': {'fournameone': 'fourvalueone',
                               'fournametwo': 'fourvaluetwo'},
                      'FIVE': ['one', 'two', 'three'],
                      'six': ['ONE', 'two', 'three']}

    tci_mappings = [[['onenameone'], 'onemappedone'],
                    [['onenametwo'], 'onemappedtwo'],
                    [['two', '*'], '*'],
                    [['three', 'threenameone'], 'threemappedone'],
                    [['three', 'threenameone'], 'threemappedbis'],
                    [['four', '*'], ['Four', '*']],
                    [['five'], 'listfive'],
                    [['six', 'one'], ['six', 'mapone']]]

    mci_result = {'onemappedone': 'onevalueone',
                  'onemappedtwo': 'onevaluetwo',
                  'twonameone': 'twovalueone',
                  'twonameTwo': 'twovaluetwo',
                  'threemappedone': 'threevalueone',
                  'threemappedbis': 'threevalueone',
                  'Four': {'fournameone': 'fourvalueone',
                           'fournametwo': 'fourvaluetwo'},
                  'listfive': ['one', 'two', 'three'],
                  'six': ['mapone']}

    nci_result = {'thrEE': {'thrEEnametwo': 'threevaluetwo'},
                  'six': ['two', 'three']}

    p = Policy(tci_mappings)
    print 'Case insensitive attribute mapping'
    m, n = p.map_attributes(tci_attributes, ignore_case=True)
    if m == mci_result and n == nci_result:
        print 'SUCCESS'
    else:
        ret += 1
        print 'FAIL: Expected %s // %s\nObtained %s // %s' % \
            (mci_result, nci_result, m, n)

    sys.exit(ret)
