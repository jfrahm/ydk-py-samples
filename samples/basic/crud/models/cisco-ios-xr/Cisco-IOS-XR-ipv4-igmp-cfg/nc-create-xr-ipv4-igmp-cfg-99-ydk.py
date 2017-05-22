#!/usr/bin/env python
#
# Copyright 2017 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Create configuration for model Cisco-IOS-XR-ipv4-igmp-cfg.

usage: nc-create-xr-ipv4-igmp-cfg-10-ydk.py [-h] [-v] device

positional arguments:
  device         NETCONF device (ssh://user:password@host:port)

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

from argparse import ArgumentParser
from urlparse import urlparse

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_igmp_cfg \
    as xr_ipv4_igmp_cfg
import logging


def config_igmp_static_groups(igmp):
    """Add several variations of igmp static group configs"""
    # Setup default context
    igmp.default_context = igmp.DefaultContext()
    igmp.default_context.interfaces = igmp.default_context.Interfaces()

    # Add interface
    intf = igmp.default_context.interfaces.Interface()
    igmp.default_context.interfaces.interface.append(intf)
    intf.interface_name = "Loopback0"

    intf.static_group_group_addresses = intf.StaticGroupGroupAddresses()
    sg = intf.static_group_group_addresses

    # Add static group config for only group
    sgg = sg.StaticGroupGroupAddress()
    sg.static_group_group_address.append(sgg)
    sgg.group_address = "232.1.1.1"
    sgg.suppress_report = True

    # Add static group config for group and source
    sggs = sg.StaticGroupGroupAddressSourceAddress()
    sg.static_group_group_address_source_address.append(sggs)
    sggs.source_address = "10.10.10.1"
    sggs.group_address = "232.1.1.2"

    # Add static group config for group with increment mask
    sggm = sg.StaticGroupGroupAddressGroupAddressMask()
    sg.static_group_group_address_group_address_mask.append(sggm)
    sggm.group_address = "232.1.1.3"
    sggm.group_address_mask = "0.0.0.2"
    sggm.group_count = 10

    # Add static group config for group and source with increment mask
    sggsm = sg.StaticGroupGroupAddressSourceAddressSourceAddressMask()
    sg.static_group_group_address_source_address_source_address_mask\
            .append(sggsm)
    sggsm.group_address = "232.1.1.4"
    sggsm.source_address = "10.10.10.1"
    sggsm.source_address_mask = "0.0.0.2"
    sggsm.source_count = 10

    # Add static group config for group with increment mask
    # and source with increment mask
    sggmsm = sg.StaticGroupGroupAddressGroupAddressMaskSourceAddressSourceAddressMask()
    sg.static_group_group_address_group_address_mask_source_address_source_address_mask\
            .append(sggmsm)
    sggmsm.group_address = "232.1.1.5"
    sggmsm.group_address_mask = "0.0.0.2"
    sggmsm.group_count = 10
    sggmsm.source_address = "10.10.10.1"
    sggmsm.source_address_mask = "0.0.0.2"
    sggmsm.source_count = 10



if __name__ == "__main__":
    """Execute main program."""
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("device",
                        help="NETCONF device (ssh://user:password@host:port)")
    args = parser.parse_args()
    device = urlparse(args.device)

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # create NETCONF provider
    provider = NetconfServiceProvider(address=device.hostname,
                                      port=device.port,
                                      username=device.username,
                                      password=device.password,
                                      protocol=device.scheme)
    # create CRUD service
    crud = CRUDService()

    igmp = xr_ipv4_igmp_cfg.Igmp()  # create object
    config_igmp_static_groups(igmp)  # add object configuration

    # create configuration on NETCONF device
    crud.create(provider, igmp)

    provider.close()
    exit()
# End of script
