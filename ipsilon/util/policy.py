# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
import copy
import sys


class Policy(Log):
    """
    A policy engine to filter and map (rename) attributes.
    """

    def __init__(self, mappings=None, allowed=None):
        """
        Create a new policy engine instance with the specified mapping
        and filter configuration.

        mappings is a list of mapping rules.

        Each mapping rule is a two-element list.  The first element defines the
        name of an attribute to map.  The second element is the name to map the
        attribute to in the output.

          For example, given this mapping,

          [
            ['name', 'username']
          ]

          and this input,

          {
            'name': 'bob',
            'groups': ['bob', 'allbobs', 'people']
          }

          the output will be

          {
            'username': 'bob'
          }

        Either the input or output name may itself be a two-element list
        instead of a string.  If the input name is a list, the first element is
        the name of a dict or list in the input, and the second element is the
        name of a parameter in that iterable.  If the output name is a list,
        then the first element is the name of a dict or list to create in the
        output, and the second element is the name of the value to add to it.

          Given this mapping,

          [
            [['gecos', 'roomno'], 'roomno'],
            [['groups', 'people'], ['groups', 'peoplegroup']]
          ]

          and this input,

          {
            'gecos': {
              'roomno': '12B'
            },
            'groups': ['bob', 'allbobs', 'people']
          }

          the output will be

          {
            'roomno': '12B',
            'groups': ['peoplegroup']
          }

        The value '*' can be used as a wildcard.  If the input name is '*',
        this causes all input attributes to be copied to the output.  If the
        output name is also '*', the attribute names are unchanged.  '*' can be
        combined with the two-element for to copy dicts and lists in the input.

        For example:

          [['gecos', '*'], ['gecos', '*']] which is functionally identical to
          ['gecos', 'gecos']

          ['*', ['allparams', '*']] which copies all input attributes into an
          output parameter called 'allparams'.

        The default mapping is [['*', '*']] - i.e. all input attributes are
        copied as-is to the output.

        As the mapping configuration is specified as a list of mappings, this
        allows input attributes to be mapping to the output in multiple ways at
        the same time.


        allowed is a list of filter rules.

        Each filter rule is either a simple string specifying an attribute
        name, or a two-element list specifying a dict or list attribute name,
        and a value in that iterable.

        The filter list can be used as either a whitelist (filtering attributes
        into the output) or as a blacklist (filtering attributes out of
        output).

        Filter rules can also use the '*' wildcard.  A filter rule of ['*']
        matches all attributes.  A filter rule of ['gecos', '*'] matches all
        elements of a dict or list called 'gecos'.

        The default mapping is ['*'] - i.e. all attributes are matched.

        An example:

          Combining this filter config,

          [
            'username',
            ['groups', 'allbobs'],
            ['groups', 'people']
          ]

          with this input,

          {
            'username': 'bob',
            'groups': ['bob', 'allbobs', 'people']
          }

          the output will be

          {
            'username': 'bob',
            'groups': ['allbobs', 'people']
          }
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
        """
        Map the specified dictionary of attributes using the mapping
        configuration specified at policy engine creation time.

        Returns a tuple of two dicts, containing the resulting mapped and
        unmapped attributes respectively.

        If ignore_case is true, then the mapping list is compared to attribute
        names in a case-insensitive fashion.  If the attribute list has one or
        more attributes that differ only in case, then only one of the
        attributes will be mapped (at random, due to Python's default dict
        ordering).
        """

        if not isinstance(attributes, dict):
            raise ValueError("Attributes must be dictionary, not %s" %
                             type(attributes))

        not_mapped = copy.deepcopy(attributes)
        mapped = dict()

        # This is an implicit _* -> _* mapping.
        # This is done because we expect certain internal attributes (_*) to be
        # passed along always.
        for k in attributes:
            if k.startswith('_'):
                mapped[k] = attributes[k]

        # If ignore_case is True,
        # then PD translates case insensitively prefixes
        PD = dict()
        for k in attributes:
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
        """
        Filter the specified dictionary of attributes using the filter
        configuration specified at policy engine creation time.

        Returns a dict containing the resulting filter attributes.

        If whitelist is true, the filter specifies which attributes are allowed
        in the output.  If whitelist is false, the filter specifies which
        attributes should be removed from the output.
        """

        if not isinstance(attributes, dict):
            raise ValueError("Attributes must be dictionary, not %s" %
                             type(attributes))

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
            # the filtered dict contains the attributes that are blacklisted,
            # so take a copy of the original attributes, and remove them
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

    print('Default attribute mapping')
    m, n = p.map_attributes(t_attributes)
    if m == t_attributes and n is None:
        print('SUCCESS')
    else:
        ret += 1
        print('FAIL: Expected %s\nObtained %s' % (t_attributes, m))

    print('Default attribute filtering')
    f = p.filter_attributes(t_attributes)
    if f == t_attributes:
        print('SUCCESS')
    else:
        ret += 1
        print('Expected %s\nObtained %s' % (t_attributes, f))

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

    print('Custom attribute mapping')
    m, n = p.map_attributes(t_attributes)
    if m == m_result and n == n_result:
        print('SUCCESS')
    else:
        ret += 1
        print('Expected %s\nObtained %s' % (m_result, m))

    print('Custom attribute filtering')
    f = p.filter_attributes(m)
    if f == f_result:
        print('SUCCESS')
    else:
        ret += 1
        print('Expected %s\nObtained %s' % (f_result, f))

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

    print('Custom attribute filtering 2')
    m, _ = p.map_attributes(t_attributes)
    f = p.filter_attributes(m, whitelist=False)
    if f == f2_result:
        print('SUCCESS')
    else:
        ret += 1
        print('Expected %s\nObtained %s' % (f2_result, f))

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
    print('Case insensitive attribute mapping')
    m, n = p.map_attributes(tci_attributes, ignore_case=True)
    if m == mci_result and n == nci_result:
        print('SUCCESS')
    else:
        ret += 1
        print('FAIL: Expected %s // %s\nObtained %s // %s' %
              (mci_result, nci_result, m, n))

    sys.exit(ret)
