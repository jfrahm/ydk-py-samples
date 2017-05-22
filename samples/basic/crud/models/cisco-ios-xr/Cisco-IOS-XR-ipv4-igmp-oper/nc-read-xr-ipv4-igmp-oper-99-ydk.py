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
Read all data for model Cisco-IOS-XR-ipv4-igmp-oper.

usage: nc-read-xr-ipv4-igmp-oper-99-ydk.py [-h] [-v] device

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
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_igmp_oper \
    as xr_ipv4_igmp_oper
import logging
import textwrap


def prep_igmp_summary(igmp):
    """prepare command equivalent to 'show igmp summary'"""
    igmp.active = igmp.Active()
    igmp.active.default_context = igmp.active.DefaultContext()
    igmp.active.default_context.summary = \
        igmp.active.default_context.Summary()


def process_igmp_summary(summary):
    """Process data in igmp object."""
    template = textwrap.dedent("""\
    Robustness Value {0.robustness}
    No. of Group x Interfaces {0.group_count}
    Maximum number of Groups for this VRF {0.group_limit}

    Supported Interfaces   : {0.supported_interfaces}
    Unsupported Interfaces : {0.unsupported_interfaces}
    Enabled Interfaces     : {0.enabled_interface_count}
    Disabled Interfaces    : {0.disabled_interface_count}

    MTE tuple count        : {0.tunnel_mte_config_count}

    Interface                       Number  Max #
                                    Groups  Groups
    """)
    intf_template = "{0.interface_name:<32}{0.group_count:<8}{0.group_limit}"

    print(template.format(summary))
    for interface in summary.interface:
        print(intf_template.format(interface))


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

    igmp = xr_ipv4_igmp_oper.Igmp()  # create object

    # read data from NETCONF device
    prep_igmp_summary(igmp)
    summary = crud.read(provider, igmp.active.default_context.summary)
    process_igmp_summary(summary)

    provider.close()
    exit()
# End of script
