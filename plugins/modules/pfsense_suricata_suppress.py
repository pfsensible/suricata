#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_suricata_suppress
short_description: Manage pfSense Suricata suppression lists
description:
  - Manage pfSense Suricata suppression lists
version_added: 0.1.0
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The suppression list name.
    required: true
    type: str
  descr:
    description: The suppression list description.
    required: false
    type: str
    default: ''
  rules:
    description: The suppression list rules
    required: false
    type: str
    default: ''
  state:
    description: State in which to leave the suppression list
    choices: [ "present", "absent" ]
    default: present
    type: str
'''

EXAMPLES = r'''
- name: Modify suppression list
  pfsense_suricata_suppress:
    name: lansuppress_57d8285cbd9c0
    rules: |
      #SURICATA STREAM CLOSEWAIT FIN out of window
      suppress gen_id 1, sig_id 2210016
'''

RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create suricata_suppress 'lansuppress_57d8285cbd9c0', rules='suppress gen_id 1, sig_id 2210016'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.suricata.plugins.module_utils.suricata_suppress import PFSenseSuricataSuppressModule, SURICATA_SUPPRESS_ARGUMENT_SPEC


def main():
    module = AnsibleModule(
        argument_spec=SURICATA_SUPPRESS_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseSuricataSuppressModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
