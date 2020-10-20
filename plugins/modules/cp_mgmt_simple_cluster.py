#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage Check Point Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_simple_cluster
short_description: Manages simple-cluster objects on Check Point over Web Services API
description:
  - Manages simple-cluster objects on Check Point devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
version_added: "2.10"
author: "Or Soffer (@chkp-orso), Jon Spriggs (@jontheniceguy)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  ip_address:
    description:
      - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
    type: str
  ipv4_address:
    description:
      - IPv4 address.
    type: str
  ipv6_address:
    description:
      - IPv6 address.
    type: str
  anti_bot:
    description:
      - Anti-Bot blade enabled.
    type: bool
  anti_virus:
    description:
      - Anti-Virus blade enabled.
    type: bool
  application_control:
    description:
      - Application Control blade enabled.
    type: bool
  cluster_mode:
    description:
      - Cluster mode.
    type: str
    choices: ['cluster-xl-ha', 'cluster-ls-multicast', 'cluster-ls-unicast', 'opsec-ha', 'opsec-ls']
  content_awareness:
    description:
      - Content Awareness blade enabled.
    type: bool
  firewall:
    description:
      - Firewall blade enabled.
    type: bool
  firewall_settings:
    description:
      - N/A
    type: dict
    suboptions:
      auto_calculate_connections_hash_table_size_and_memory_pool:
        description:
          - N/A
        type: bool
      auto_maximum_limit_for_concurrent_connections:
        description:
          - N/A
        type: bool
      connections_hash_size:
        description:
          - N/A
        type: int
      maximum_limit_for_concurrent_connections:
        description:
          - N/A
        type: int
      maximum_memory_pool_size:
        description:
          - N/A
        type: int
      memory_pool_size:
        description:
          - N/A
        type: int
  hardware:
    description:
      - Cluster platform hardware.
  interfaces:
    description:
      - Cluster interfaces. When a cluster is updated with a new interfaces, the existing interfaces are removed.
    type: list
    suboptions:
      name:
        description:
          - Object name.
        type: str
      interface_type:
        description:
          - Cluster interface type.
        type: str
        choices: ['cluster', 'sync', 'cluster + sync', 'private']
      ip_address:
        description:
          - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
        type: str
      ipv4_address:
        description:
          - IPv4 address.
        type: str
      ipv6_address:
        description:
          - IPv6 address.
        type: str
      network_mask:
        description:
          - IPv4 or IPv6 network mask. If both masks are required use ipv4-network-mask and ipv6-network-mask fields explicitly. Instead of
            providing mask itself it is possible to specify IPv4 or IPv6 mask length in mask-length field. If both masks length are required use
            ipv4-mask-length and  ipv6-mask-length fields explicitly.
        type: str
      ipv4_network_mask:
        description:
          - IPv4 network address.
        type: str
      ipv6_network_mask:
        description:
          - IPv6 network address.
        type: str
      mask_length:
        description:
          - IPv4 or IPv6 network mask length.
        type: str
      ipv4_mask_length:
        description:
          - IPv4 network mask length.
        type: str
      ipv6_mask_length:
        description:
          - IPv6 network mask length.
        type: str
      anti_spoofing:
        description:
          - N/A
        type: bool
      anti_spoofing_settings:
        description:
          - N/A
        type: dict
        suboptions:
          action:
            description:
              - If packets will be rejected (the Prevent option) or whether the packets will be monitored (the Detect option).
            type: str
            choices: ['prevent', 'detect']
      multicast_address:
        description:
          - Multicast IP Address.
        type: str
      multicast_address_type:
        description:
          - Multicast Address Type.
        type: str
        choices: ['manual', 'default']
      security_zone:
        description:
          - N/A
        type: bool
      security_zone_settings:
        description:
          - N/A
        type: dict
        suboptions:
          auto_calculated:
            description:
              - Security Zone is calculated according to where the interface leads to.
            type: bool
          specific_zone:
            description:
              - Security Zone specified manually.
            type: str
      tags:
        description:
          - Collection of tag identifiers.
        type: list
      topology:
        description:
          - N/A
        type: str
        choices: ['automatic', 'external', 'internal']
      topology_settings:
        description:
          - N/A
        type: dict
        suboptions:
          interface_leads_to_dmz:
            description:
              - Whether this interface leads to demilitarized zone (perimeter network).
            type: bool
          ip_address_behind_this_interface:
            description:
              - N/A
            type: str
            choices: ['not defined', 'network defined by the interface ip and net mask', 'network defined by routing', 'specific']
          specific_network:
            description:
              - Network behind this interface.
            type: str
      color:
        description:
          - Color of the object. Should be one of existing colors.
        type: str
        choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                 'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                 'orange', 'red', 'sienna', 'yellow']
      comments:
        description:
          - Comments string.
        type: str
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
      ignore_warnings:
        description:
          - Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description:
          - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
  ips:
    description:
      - Intrusion Prevention System blade enabled.
    type: bool
  members:
    description:
      - Cluster members.
    type: list
    suboptions:
      uid:
        description:
          - Object unique identifier.
        type: str
      name:
        description:
          - Object name.
        type: str
      interfaces:
        description:
          - Cluster Member network interfaces. When a cluster member is updated with a new interfaces, the existing interfaces are removed.
        type: list
        suboptions:
          uid:
            description:
              - Object unique identifier.
            type: str
          name:
            description:
              - Object name.
            type: str
          anti_spoofing:
            description:
              - N/A
            type: bool
          anti_spoofing_settings:
            description:
              - N/A
            type: dict
            suboptions:
              action:
                description:
                  - If packets will be rejected (the Prevent option) or whether the packets will be monitored (the Detect option).
                type: str
                choices: ['prevent', 'detect']
          ip_address:
            description:
              - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
            type: str
          ipv4_address:
            description:
              - IPv4 address.
            type: str
          ipv6_address:
            description:
              - IPv6 address.
            type: str
          network_mask:
            description:
              - IPv4 or IPv6 network mask. If both masks are required use ipv4-network-mask and ipv6-network-mask fields explicitly. Instead of
                providing mask itself it is possible to specify IPv4 or IPv6 mask length in mask-length field. If both masks length are required use
                ipv4-mask-length and  ipv6-mask-length fields explicitly.
            type: str
          ipv4_network_mask:
            description:
              - IPv4 network address.
            type: str
          ipv6_network_mask:
            description:
              - IPv6 network address.
            type: str
          mask_length:
            description:
              - IPv4 or IPv6 network mask length.
            type: str
          ipv4_mask_length:
            description:
              - IPv4 network mask length.
            type: str
          ipv6_mask_length:
            description:
              - IPv6 network mask length.
            type: str
          new_name:
            description:
              - New name of the object.
            type: str
          security_zone:
            description:
              - N/A
            type: bool
          security_zone_settings:
            description:
              - N/A
            type: dict
            suboptions:
              auto_calculated:
                description:
                  - Security Zone is calculated according to where the interface leads to.
                type: bool
              specific_zone:
                description:
                  - Security Zone specified manually.
                type: str
          tags:
            description:
              - Collection of tag identifiers.
            type: list
          topology:
            description:
              - N/A
            type: str
            choices: ['automatic', 'external', 'internal']
          topology_settings:
            description:
              - N/A
            type: dict
            suboptions:
              interface_leads_to_dmz:
                description:
                  - Whether this interface leads to demilitarized zone (perimeter network).
                type: bool
              ip_address_behind_this_interface:
                description:
                  - N/A
                type: str
                choices: ['not defined', 'network defined by the interface ip and net mask', 'network defined by routing', 'specific']
              specific_network:
                description:
                  - Network behind this interface.
                type: str
          color:
            description:
              - Color of the object. Should be one of existing colors.
            type: str
            choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                    'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                    'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                    'orange', 'red', 'sienna', 'yellow']
          comments:
            description:
              - Comments string.
            type: str
          details_level:
            description:
              - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
                representation of the object.
            type: str
            choices: ['uid', 'standard', 'full']
          ignore_warnings:
            description:
              - Apply changes ignoring warnings.
            type: bool
          ignore_errors:
            description:
              - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
            type: bool
      ip_address:
        description:
          - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
        type: str
      ipv4_address:
        description:
          - IPv4 address.
        type: str
      ipv6_address:
        description:
          - IPv6 address.
        type: str
      new_name:
        description:
          - New name of the object.
        type: str
      one_time_password:
        description:
          - N/A
        type: str
      tags:
        description:
          - Collection of tag identifiers.
        type: list
      color:
        description:
          - Color of the object. Should be one of existing colors.
        type: str
        choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                'orange', 'red', 'sienna', 'yellow']
      comments:
        description:
          - Comments string.
        type: str
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
      ignore_warnings:
        description:
          - Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description:
          - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
  os_name:
    description:
      - Gateway platform operating system.
    type: str
  send_alerts_to_server:
    description:
      - Server(s) to send alerts to.
    type: list
  send_logs_to_backup_server:
    description:
      - Backup server(s) to send logs to.
    type: list
  send_logs_to_server:
    description:
      - Server(s) to send logs to.
    type: list
  tags:
    description:
      - Collection of tag identifiers.
    type: list
  threat_emulation:
    description:
      - Threat Emulation blade enabled.
    type: bool
  url_filtering:
    description:
      - URL Filtering blade enabled.
    type: bool
  gateway_version:
    description:
      - Gateway platform version.
    type: str
  vpn:
    description:
      - VPN blade enabled.
    type: bool
  vpn_settings:
    description:
      - Gateway VPN settings.
    type: dict
    suboptions:
      maximum_concurrent_ike_negotiations:
        description:
          - N/A
        type: int
      maximum_concurrent_tunnels:
        description:
          - N/A
        type: int
      vpn_domain:
        description:
          - Gateway VPN domain identified by the name or UID.
        type: str
      vpn_domain_type:
        description:
          - Gateway VPN domain type.
        type: str
        choices: ['manual', 'addresses_behind_gw']
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  groups:
    description:
      - Collection of group identifiers.
    type: list
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-simple-cluster
  cp_mgmt_simple_cluster:
    ip_address: 192.0.2.1
    name: gw1
    state: present

- name: set-simple-cluster
  cp_mgmt_simple_cluster:
    anti_bot: true
    anti_virus: true
    application_control: true
    ips: true
    name: test_cluster
    state: present
    threat_emulation: true
    url_filtering: true

- name: delete-simple-cluster
  cp_mgmt_simple_cluster:
    name: gw1
    state: absent
"""

RETURN = """
cp_mgmt_simple_cluster:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        ip_address=dict(type='str'),
        ipv4_address=dict(type='str'),
        ipv6_address=dict(type='str'),
        anti_bot=dict(type='bool'),
        anti_virus=dict(type='bool'),
        application_control=dict(type='bool'),
        cluster_mode=dict(type='str', choices=['cluster-xl-ha', 'cluster-ls-multicast', 'cluster-ls-unicast', 'opsec-ha', 'opsec-ls']),
        content_awareness=dict(type='bool'),
        firewall=dict(type='bool'),
        firewall_settings=dict(type='dict', options=dict(
            auto_calculate_connections_hash_table_size_and_memory_pool=dict(type='bool'),
            auto_maximum_limit_for_concurrent_connections=dict(type='bool'),
            connections_hash_size=dict(type='int'),
            maximum_limit_for_concurrent_connections=dict(type='int'),
            maximum_memory_pool_size=dict(type='int'),
            memory_pool_size=dict(type='int')
        )),
        hardware=dict(type='str'),
        interfaces=dict(type='list', options=dict(
            name=dict(type='str'),
            interface_type=dict(type='str', choices=['cluster', 'sync', 'cluster + sync', 'private']),
            ip_address=dict(type='str'),
            ipv4_address=dict(type='str'),
            ipv6_address=dict(type='str'),
            network_mask=dict(type='str'),
            ipv4_network_mask=dict(type='str'),
            ipv6_network_mask=dict(type='str'),
            mask_length=dict(type='str'),
            ipv4_mask_length=dict(type='str'),
            ipv6_mask_length=dict(type='str'),
            anti_spoofing=dict(type='bool'),
            anti_spoofing_settings=dict(type='dict', options=dict(
                action=dict(type='str', choices=['prevent', 'detect'])
            )),
            multicast_address=dict(type='str'),
            multicast_address_type=dict(type='str', choices=['manual', 'default']),
            security_zone=dict(type='bool'),
            security_zone_settings=dict(type='dict', options=dict(
                auto_calculated=dict(type='bool'),
                specific_zone=dict(type='str')
            )),
            tags=dict(type='list'),
            topology=dict(type='str', choices=['automatic', 'external', 'internal']),
            topology_settings=dict(type='dict', options=dict(
                interface_leads_to_dmz=dict(type='bool'),
                ip_address_behind_this_interface=dict(type='str', choices=['not defined', 'network defined by the interface ip and net mask',
                                                                           'network defined by routing', 'specific']),
                specific_network=dict(type='str')
            )),
            color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan',
                                            'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue',
                                            'firebrick',
                                            'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
                                            'coral',
                                            'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange',
                                            'red',
                                            'sienna', 'yellow']),
            comments=dict(type='str'),
            details_level=dict(type='str', choices=['uid', 'standard', 'full']),
            ignore_warnings=dict(type='bool'),
            ignore_errors=dict(type='bool')
        )),
        ips=dict(type='bool'),
        members=dict(type='list', options=dict(
            uid=dict(type='str'),
            name=dict(type='str'),
            interfaces=dict(type='list', options=dict(
                uid=dict(type='str'),
                name=dict(type='str'),
                anti_spoofing=dict(type='bool'),
                anti_spoofing_settings=dict(type='dict', options=dict(
                    action=dict(type='str', choices=['prevent', 'detect'])
                )),
                ip_address=dict(type='str'),
                ipv4_address=dict(type='str'),
                ipv6_address=dict(type='str'),
                network_mask=dict(type='str'),
                ipv4_network_mask=dict(type='str'),
                ipv6_network_mask=dict(type='str'),
                mask_length=dict(type='str'),
                ipv4_mask_length=dict(type='str'),
                ipv6_mask_length=dict(type='str'),
                new_name=dict(type='str'),
                security_zone=dict(type='bool'),
                security_zone_settings=dict(type='dict', options=dict(
                    auto_calculated=dict(type='bool'),
                    specific_zone=dict(type='str')
                )),
                tags=dict(type='list'),
                topology=dict(type='str', choices=['automatic', 'external', 'internal']),
                topology_settings=dict(type='dict', options=dict(
                    interface_leads_to_dmz=dict(type='bool'),
                    ip_address_behind_this_interface=dict(type='str', choices=['not defined', 'network defined by the interface ip and net mask',
                                                                              'network defined by routing', 'specific']),
                    specific_network=dict(type='str')
                )),
                color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan',
                                                'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue',
                                                'firebrick',
                                                'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
                                                'coral',
                                                'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange',
                                                'red',
                                                'sienna', 'yellow']),
                comments=dict(type='str'),
                details_level=dict(type='str', choices=['uid', 'standard', 'full']),
                ignore_warnings=dict(type='bool'),
                ignore_errors=dict(type='bool')
            )),
            ip_address=dict(type='str'),
            ipv4_address=dict(type='str'),
            ipv6_address=dict(type='str'),
            new_name=dict(type='str'),
            one_time_password=dict(type='str'),
            tags=dict(type='list'),
            color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan',
                                            'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue',
                                            'firebrick',
                                            'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
                                            'coral',
                                            'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange',
                                            'red',
                                            'sienna', 'yellow']),
            comments=dict(type='str'),
            details_level=dict(type='str', choices=['uid', 'standard', 'full']),
            ignore_warnings=dict(type='bool'),
            ignore_errors=dict(type='bool')
        )),
        os_name=dict(type='str'),
        send_alerts_to_server=dict(type='list'),
        send_logs_to_backup_server=dict(type='list'),
        send_logs_to_server=dict(type='list'),
        tags=dict(type='list'),
        threat_emulation=dict(type='bool'),
        url_filtering=dict(type='bool'),
        gateway_version=dict(type='str'),
        vpn=dict(type='bool'),
        vpn_settings=dict(type='dict', options=dict(
            maximum_concurrent_ike_negotiations=dict(type='int'),
            maximum_concurrent_tunnels=dict(type='int')
        )),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral',
                                        'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        groups=dict(type='list'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'simple-cluster'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
