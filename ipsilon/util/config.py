# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
import json


class Config(Log):

    def __init__(self, name, *args):
        self.name = name
        self._list = list()
        self._dict = dict()
        for item in args:
            if not isinstance(item, Option):
                raise ValueError('Invalid option type for %s' % repr(item))
            self._list.append(item.name)
            self._dict[item.name] = item
        self.debug('Config(%s) %s' % (self.name, self._dict))

    def __repr__(self):
        return '%s: %s' % (self.__class__, ', '.join(self._list))

    def __str__(self):
        return str(self._list)

    def __len__(self):
        return len(self._list)

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, value):
        if not isinstance(value, Option):
            raise ValueError('Invalid type for %s' % value)
        if key != value.name:
            raise NameError('Name mismatch, key=%s but value.name=%s' % (
                key, value.name))
        if key not in self._list:
            self._list.append(key)
        self._dict[key] = value

    def __delitem__(self, key):
        self._list.remove(key)
        del self._dict[key]

    def __iter__(self):
        i = 0
        while i < len(self._list):
            yield self._list[i]
            i += 1

    def __reversed__(self):
        i = len(self._list)
        while i > 0:
            yield self._list[i - 1]
            i -= 1

    def __contains__(self, item):
        return (item in self._dict)

    def iteritems(self):
        i = 0
        while i < len(self._list):
            yield (self._list[i], self._dict[self._list[i]])
            i += 1

    def items(self):
        return [(k, self._dict[k]) for k in self._list]


class Option(Log):

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self._default_value = None
        self._assigned_value = None

    def __repr__(self):
        return "%s: %s {%s}, value = %s [def: %s]" % (self.__class__,
                                                      self.name,
                                                      self.description,
                                                      self._assigned_value,
                                                      self._default_value)

    def __str__(self):
        return '%s=%s' % (self.name, self.get_value())

    def get_value(self, default=True):
        if self._assigned_value is not None:
            return self._assigned_value
        elif default is True:
            return self._default_value
        else:
            return None

    def set_value(self, value):
        self._assigned_value = value

    def export_value(self):
        raise NotImplementedError

    def import_value(self, value):
        raise NotImplementedError

    def _str_export_value(self):
        if self._assigned_value:
            return str(self._assigned_value)
        return None

    def _str_import_value(self, value):
        if not isinstance(value, str):
            raise ValueError('Value must be string')
        self._assigned_value = value


class String(Option):

    def __init__(self, name, description, default_value=None):
        super(String, self).__init__(name, description)
        self._default_value = str(default_value)

    def set_value(self, value):
        self._assigned_value = str(value)

    def export_value(self):
        return self._str_export_value()

    def import_value(self, value):
        self._str_import_value(value)


class Template(Option):

    def __init__(self, name, description, default_template=None):
        super(Template, self).__init__(name, description)
        self._default_value = str(default_template)

    def set_value(self, value):
        self._assigned_value = str(value)

    def templatize(self, args):
        if not args:
            raise ValueError('Templatized called w/o arguments')

        return self.get_value() % args

    def export_value(self):
        return self._str_export_value()

    def import_value(self, value):
        self._str_import_value(value)


class List(Option):

    def __init__(self, name, description, default_list=None):
        super(List, self).__init__(name, description)
        if default_list:
            self._default_value = default_list
        else:
            self._default_value = []

    def set_value(self, value):
        self._assigned_value = list(value)

    def export_value(self):
        if self._assigned_value:
            return ','.join(self._assigned_value)
        return None

    def import_value(self, value):
        if not isinstance(value, str):
            raise ValueError('Value (type: %s) must be string' % type(value))
        self._assigned_value = [x.strip() for x in value.split(',')]


class ComplexList(List):

    def _check_value(self, value):
        if value is None:
            return
        if not isinstance(value, list):
            raise ValueError('The value type must be a list, not "%s"' %
                             type(value))

    def set_value(self, value):
        self._check_value(value)
        self._assigned_value = value

    def export_value(self):
        if self._assigned_value:
            return json.dumps(self._assigned_value)
        return None

    def import_value(self, value):
        if not isinstance(value, str):
            raise ValueError('The value type must be a string, not "%s"' %
                             type(value))
        jsonval = json.loads(value)
        self.set_value(jsonval)


class MappingList(ComplexList):

    def _check_value(self, value):
        if value is None:
            return
        if not isinstance(value, list):
            raise ValueError('The value type must be a list, not "%s"' %
                             type(value))
        for v in value:
            if not isinstance(v, list):
                raise ValueError('Each element must be a list, not "%s"' %
                                 type(v))
            if len(v) != 2:
                raise ValueError('Each element must contain 2 values,'
                                 ' not %d' % len(v))

    def import_value(self, value):
        if not isinstance(value, str):
            raise ValueError('Value (type: %s) must be string' % type(value))
        jsonval = json.loads(value)
        self.set_value(jsonval)


class Choice(Option):

    def __init__(self, name, description, allowed=None, default=None):
        super(Choice, self).__init__(name, description)
        if allowed:
            self._allowed_values = list(allowed)
        else:
            self._allowed_values = list()
        self._default_value = list()
        if default is None:
            default = []
        for name in default:
            if name not in self._allowed_values:
                raise ValueError(
                    'item [%s] is not in allowed [%s]' % (name, allowed))
            self._default_value.append(name)

    def __repr__(self):
        return "%s: %s {%s}, values = %s d:%s ok:%s" % (self.__class__,
                                                        self.name,
                                                        self.description,
                                                        self._assigned_value,
                                                        self._default_value,
                                                        self._allowed_values)

    def __str__(self):
        return '%s=%s' % (self.name, self.get_value())

    def set_value(self, value):
        if not isinstance(value, list):
            value = [value]
        self._assigned_value = list()
        for val in value:
            if val not in self._allowed_values:
                raise ValueError(
                    'Value "%s" not allowed [%s]' % (val,
                                                     self._allowed_values))
            self._assigned_value.append(val)

        if not self._assigned_value:
            self._assigned_value = None

    def unset_value(self, value):
        if isinstance(value, str):
            value = [value]
        unset = list()
        for val in value:
            unset.append((val, False))
        self.set_value(unset)

    def get_allowed(self):
        return self._allowed_values

    def export_value(self):
        enabled = self.get_value()
        return ', '.join(enabled)

    def import_value(self, value):
        enabled = [x.strip() for x in value.split(',')]
        if enabled:
            if self._assigned_value is None:
                self._assigned_value = list()
        for val in enabled:
            if val not in self._allowed_values:
                # We silently ignore invalid options on import for now
                continue
            self._assigned_value.append(val)


class Pick(Option):

    def __init__(self, name, description, allowed, default_value):
        super(Pick, self).__init__(name, description)
        self._allowed_values = list(allowed)
        if default_value not in self._allowed_values:
            raise ValueError('The default value is not in the allowed list')
        self._default_value = default_value

    def set_value(self, value):
        if value not in self._allowed_values:
            raise ValueError(
                'Value "%s" not allowed [%s]' % (value, self._allowed_values))
        self._assigned_value = value

    def get_allowed(self):
        return self._allowed_values

    def export_value(self):
        return self._str_export_value()

    def import_value(self, value):
        self._str_import_value(value)


class Condition(Pick):

    def __init__(self, name, description, default_value=False):
        super(Condition, self).__init__(name, description,
                                        [True, False], default_value)

    def import_value(self, value):
        self._assigned_value = value == 'True'


class ConfigHelper(Log):

    def __init__(self):
        self._config = None

    def new_config(self, name, *config_args):
        self._config = Config(name, *config_args)

    def get_config_obj(self):
        if self._config is None:
            raise AttributeError('Config not initialized')
        return self._config

    def import_config(self, config):
        if not self._config:
            raise AttributeError('Config not initialized, cannot import')

        for key, value in config.iteritems():
            if key in self._config:
                self._config[key].import_value(str(value))

    def export_config(self):
        config = dict()
        for name, option in self._config.iteritems():
            config[name] = option.export_value()
        return config

    def get_config_value(self, name):
        if not self._config:
            raise AttributeError('Config not initialized')
        return self._config[name].get_value()

    def set_config_value(self, name, value):
        if not self._config:
            raise AttributeError('Config not initialized')
        return self._config[name].set_value(value)
