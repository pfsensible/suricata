#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_suricata_interface
short_description: Manage pfSense suricata interfaces
description:
  - Manage pfSense suricata interfaces
version_added: 0.1.0
author: Orion Poplawski (@opoplawski)
notes:
options:
  interface:
    description: The interface name.
    required: true
    type: str
  descr:
    description: The interface description.
    required: false
    type: str
    default: ''
  uuid:
    description: The interface UUID.  This will be generated if not specified.
    required: false
    type: int
  state:
    description: State in which to leave the interface
    choices: [ "present", "absent" ]
    default: present
    type: str
'''

EXAMPLES = r'''
- name: Configure Suricata interface
  pfsense_suricata_interface:
    interface: lan
'''

RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create suricata_interface 'lan'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.suricata_interface import PFSenseSuricataInterfaceModule, SURICATA_INTERFACE_ARGUMENT_SPEC


def main():
    module = AnsibleModule(
        argument_spec=SURICATA_INTERFACE_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseSuricataInterfaceModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
