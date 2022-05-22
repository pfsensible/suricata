# pfsensible.suricata

This is a set of modules to allow you to configure Suricata on pfSense firewalls with ansible.

## Installation using ansible galaxy

To install:

```
ansible-galaxy collection install pfsensible.suricata
```

Optionally, you can specify the path of the collection installation with the `-p` option.

```
ansible-galaxy collection install pfsensible.suricata -p ./collections
```

Additionally, you can set the `collections_paths` option in your `ansible.cfg` file to automatically designate install locations.

```ini
# ansible.cfg
[defaults]
collections_paths=collections
```

## Configuration

If Python discovery fails, you can set ansible_python_interpreter in your playbook or hosts vars:

pfSense >= 2.5.2:
```
ansible_python_interpreter: /usr/local/bin/python3.8
```
pfSense >= 2.4.5, < 2.5.2:
```
ansible_python_interpreter: /usr/local/bin/python3.7
```
pfSense < 2.4.5:
```
ansible_python_interpreter: /usr/local/bin/python2.7
```

Modules must run as root in order to make changes to the system.  By default pfSense does not have sudo capability so `become` will not work.  You can install it with:
```
  - name: "Install packages"
    package:
      name:
        - pfSense-pkg-sudo
      state: present
```
and then configure sudo so that your user has permission to use sudo.
## Modules
The following modules are currently available:

* [pfsense_suricata_interface](https://github.com/pfsensible/suricata_interface/wiki/pfsense_suricata_interface) for Suricata interfaces
* [pfsense_suricata_suppress](https://github.com/pfsensible/suricata_suppress/wiki/pfsense_suricata_suppress) for Suricata suppression lists

## Operation

Modules in the collection work by editing `/cf/conf/config.xml` using xml.etree.ElementTree, then
calling the appropriate PHP update function via the pfSense PHP developer shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## License

GPLv3.0 or later
