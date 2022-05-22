# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import base64
import re
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SURICATA_SUPPRESS_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    name=dict(required=True, type='str'),
    descr=dict(type='str', default=''),
    rules=dict(type='str', default=''),
)

# replacement strings
WINDOWS_LINE_ENDING = '\r\n'
UNIX_LINE_ENDING = '\n'


class PFSenseSuricataSuppressModule(PFSenseModuleBase):
    """ module managing pfsense suricata suppression lists """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SURICATA_SUPPRESS_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseSuricataSuppressModule, self).__init__(module, pfsense)
        self.name = "pfsense_suricata_suppress"
        self.obj = dict()

        pkgs_elt = self.pfsense.get_element('installedpackages')
        self.suricata = pkgs_elt.find('suricata') if pkgs_elt is not None else None
        self.root_elt = self.suricata.find('suppress') if self.suricata is not None else None
        if self.root_elt is None:
            self.module.fail_json(msg='Unable to find suppression list XML configuration entry. Are you sure suricata is installed?')

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        obj = dict()
        obj['name'] = self.params['name']
        if self.params['state'] == 'present':
            self._get_ansible_param(obj, 'descr', force=True)
            self.params['rules'] = self.params['rules'].replace(UNIX_LINE_ENDING, WINDOWS_LINE_ENDING)
            obj['suppresspassthru'] = base64.b64encode(self.params['rules'].encode()).decode()

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        # check name
        if re.search(r'[^a-zA-Z0-9_]', self.params['name']) is not None:
            self.module.fail_json(msg="The field 'name' contains invalid characters.")

    ##############################
    # XML processing
    #
    def _copy_and_add_target(self):
        """ create the XML target_elt """
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.obj.copy()
        self.diff['after']['rules'] = self.params['rules']
        del self.diff['after']['suppresspassthru']
        self.root_elt.append(self.target_elt)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before.copy()
        self.diff['before']['rules'] = base64.b64decode(before['suppresspassthru'].encode()).decode()
        del self.diff['before']['suppresspassthru']
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        self.diff['after']['rules'] = self.params['rules']
        del self.diff['after']['suppresspassthru']
        if self._remove_deleted_params():
            changed = True

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        this_elt = self.pfsense.new_element('item')
        return this_elt

    def _find_target(self):
        """ find the XML target_elt """
        result = self.root_elt.findall("item[name='{0}']".format(self.obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple suppress items for name {0}.'.format(self.obj['name']))
        else:
            return None

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload suricata """
        return self.pfsense.phpshell('''require_once("suricata/suricata.inc");
sync_suricata_package_config();''')

    ##############################
    # Logging
    #
    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'descr')
            values += self.format_cli_field(self.params, 'rules')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'rules', add_comma=(values))
        return values

    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj['name'])
