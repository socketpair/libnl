#
# Copyright (c) 2011 Thomas Graf <tgraf@suug.ch>
#

"""IPv4

"""

from __future__ import absolute_import

__all__ = [
    '',
]

from ... import core as netlink
from ..  import capi as capi
from ... import util as util
DEVCONF_FORWARDING = 1
DEVCONF_MC_FORWARDING = 2
DEVCONF_PROXY_ARP = 3
DEVCONF_ACCEPT_REDIRECTS = 4
DEVCONF_SECURE_REDIRECTS = 5
DEVCONF_SEND_REDIRECTS = 6
DEVCONF_SHARED_MEDIA = 7
DEVCONF_RP_FILTER = 8
DEVCONF_ACCEPT_SOURCE_ROUTE = 9
DEVCONF_BOOTP_RELAY = 10
DEVCONF_LOG_MARTIANS = 11
DEVCONF_TAG = 12
DEVCONF_ARPFILTER = 13
DEVCONF_MEDIUM_ID = 14
DEVCONF_NOXFRM = 15
DEVCONF_NOPOLICY = 16
DEVCONF_FORCE_IGMP_VERSION = 17
DEVCONF_ARP_ANNOUNCE = 18
DEVCONF_ARP_IGNORE = 19
DEVCONF_PROMOTE_SECONDARIES = 20
DEVCONF_ARP_ACCEPT = 21
DEVCONF_ARP_NOTIFY = 22
DEVCONF_ACCEPT_LOCAL = 23
DEVCONF_SRC_VMARK = 24
DEVCONF_PROXY_ARP_PVLAN = 25
DEVCONF_MAX = DEVCONF_PROXY_ARP_PVLAN


class InetLink(object):
    def __init__(self, link):
        self._link = link

    @staticmethod
    def _resolve_ident(ident):
        if not isinstance(ident, basestring):
            return int(ident)

        ret = capi.rtnl_link_inet_str2devconf(bytes(ident))[0]
        if ret < 0:
            raise NameError('unknown configuration id {0}'.format(ident))
        return ret

    def details(self, fmt):
        buf = [
            fmt.nl('\n\t{0}\n\t'.format(util.title('Configuration:')))
        ]
        for i in xrange(DEVCONF_FORWARDING, DEVCONF_MAX+1):
            if i & 1 and i > 1:
                buf.append(fmt.nl('\t'))
            txt = util.kw(str(capi.rtnl_link_inet_devconf2str(i, 32)[0]))
            buf.append(fmt.format('{0:28s} {1:12}  ', txt, self.get_conf(i)))

        return ''.join(buf)

    def get_conf(self, ident):
        ident = self._resolve_ident(ident)
        return capi.rtnl_link_inet_get_conf(self._link._rtnl_link, ident)

    def set_conf(self, ident, value):
        ident = self._resolve_ident(ident)
        return capi.rtnl_link_inet_set_conf(self._link._rtnl_link, ident, int(value))

    @property
    @netlink.nlattr(type=bool, fmt=util.boolean)
    def forwarding(self):
        return bool(self.get_conf(DEVCONF_FORWARDING))

    @forwarding.setter
    def forwarding(self, value):
        self.set_conf(DEVCONF_FORWARDING, int(value))


    @property
    @netlink.nlattr(type=bool, fmt=util.boolean)
    def mc_forwarding(self):
        return bool(self.get_conf(DEVCONF_MC_FORWARDING))

    @mc_forwarding.setter
    def mc_forwarding(self, value):
        self.set_conf(DEVCONF_MC_FORWARDING, int(value))


    @property
    @netlink.nlattr(type=bool, fmt=util.boolean)
    def proxy_arp(self):
        return bool(self.get_conf(DEVCONF_PROXY_ARP))

    @proxy_arp.setter
    def proxy_arp(self, value):
        self.set_conf(DEVCONF_PROXY_ARP, int(value))

    @property
    @netlink.nlattr(type=bool, fmt=util.boolean)
    def accept_redirects(self):
        return bool(self.get_conf(DEVCONF_ACCEPT_REDIRECTS))

    @accept_redirects.setter
    def accept_redirects(self, value):
        self.set_conf(DEVCONF_ACCEPT_REDIRECTS, int(value))

    @property
    @netlink.nlattr(type=bool, fmt=util.boolean)
    def secure_redirects(self):
        return bool(self.get_conf(DEVCONF_SECURE_REDIRECTS))

    @secure_redirects.setter
    def secure_redirects(self, value):
        self.set_conf(DEVCONF_SECURE_REDIRECTS, int(value))

    @property
    @netlink.nlattr(type=bool, fmt=util.boolean)
    def send_redirects(self):
        return bool(self.get_conf(DEVCONF_SEND_REDIRECTS))

    @send_redirects.setter
    def send_redirects(self, value):
        self.set_conf(DEVCONF_SEND_REDIRECTS, int(value))

    @property
    @netlink.nlattr(type=bool, fmt=util.boolean)
    def shared_media(self):
        return bool(self.get_conf(DEVCONF_SHARED_MEDIA))

    @shared_media.setter
    def shared_media(self, value):
        self.set_conf(DEVCONF_SHARED_MEDIA, int(value))

#	IPV4_DEVCONF_RP_FILTER,
#	IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE,
#	IPV4_DEVCONF_BOOTP_RELAY,
#	IPV4_DEVCONF_LOG_MARTIANS,
#	IPV4_DEVCONF_TAG,
#	IPV4_DEVCONF_ARPFILTER,
#	IPV4_DEVCONF_MEDIUM_ID,
#	IPV4_DEVCONF_NOXFRM,
#	IPV4_DEVCONF_NOPOLICY,
#	IPV4_DEVCONF_FORCE_IGMP_VERSION,
#	IPV4_DEVCONF_ARP_ANNOUNCE,
#	IPV4_DEVCONF_ARP_IGNORE,
#	IPV4_DEVCONF_PROMOTE_SECONDARIES,
#	IPV4_DEVCONF_ARP_ACCEPT,
#	IPV4_DEVCONF_ARP_NOTIFY,
#	IPV4_DEVCONF_ACCEPT_LOCAL,
#	IPV4_DEVCONF_SRC_VMARK,
#	IPV4_DEVCONF_PROXY_ARP_PVLAN,
