#
# Netlink interface based on libnl
#
# Copyright (c) 2011 Thomas Graf <tgraf@suug.ch>
#

"""netlink library based on libnl

This module provides an interface to netlink sockets

The module contains the following public classes:
 - Socket -- The netlink socket
 - Object -- Abstract object (based on struct nl_obect in libnl) used as
         base class for all object types which can be put into a Cache
 - Cache -- A collection of objects which are derived from the base
        class Object. Used for netlink protocols which maintain a list
        or tree of objects.
 - DumpParams --

The following exceptions are defined:
 - NetlinkError -- Base exception for all general purpose exceptions raised.
 - KernelError -- Raised when the kernel returns an error as response to a
          request.

All other classes or functions in this module are considered implementation
details.
"""
from __future__ import absolute_import



from . import capi
import sys
import socket

__all__ = [
    'Message',
    'Socket',
    'DumpParams',
    'Object',
    'Cache',
    'KernelError',
    'NetlinkError',
]

__version__ = '0.1'

# netlink protocols
NETLINK_ROUTE = 0
# NETLINK_UNUSED = 1
NETLINK_USERSOCK = 2
NETLINK_FIREWALL = 3
NETLINK_INET_DIAG = 4
NETLINK_NFLOG = 5
NETLINK_XFRM = 6
NETLINK_SELINUX = 7
NETLINK_ISCSI = 8
NETLINK_AUDIT = 9
NETLINK_FIB_LOOKUP = 10
NETLINK_CONNECTOR = 11
NETLINK_NETFILTER = 12
NETLINK_IP6_FW = 13
NETLINK_DNRTMSG = 14
NETLINK_KOBJECT_UEVENT = 15
NETLINK_GENERIC = 16
NETLINK_SCSITRANSPORT = 18
NETLINK_ECRYPTFS = 19

NL_DONTPAD = 0
NL_AUTO_PORT = 0
NL_AUTO_SEQ = 0

NL_DUMP_LINE = 0
NL_DUMP_DETAILS = 1
NL_DUMP_STATS = 2

NLM_F_REQUEST = 1
NLM_F_MULTI = 2
NLM_F_ACK = 4
NLM_F_ECHO = 8

NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_ATOMIC = 0x400
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

NLM_F_REPLACE = 0x100
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLM_F_APPEND = 0x800

class NetlinkError(Exception):
    def __init__(self, error):
        self._error = error
        self._msg = str(capi.nl_geterror(error))

    def __str__(self):
        return self._msg

class KernelError(NetlinkError):
    def __str__(self):
        return 'Kernel returned: {0}'.format(self._msg)

class ImmutableError(NetlinkError):
    def __init__(self, msg):
        self._msg = str(msg)

    def __str__(self):
        return 'Immutable attribute: {0}'.format(self._msg)

class CAPIError(NetlinkError):
    def __init__(self, message):
        self._msg = str(message)

class Message(object):
    """Netlink message"""

    def __init__(self, size=None):
        self._msg = None
        if size is None:
            self._msg = capi.nlmsg_alloc()
        else:
            self._msg = capi.nlmsg_alloc_size(int(size))

        if self._msg is None:
            raise CAPIError('Message allocation returned NULL')

    def __del__(self):
        if self._msg is not None:
            capi.nlmsg_free(self._msg)

    def __len__(self):
        return capi.nlmsg_len(nlmsg_hdr(self._msg))

    @property
    def protocol(self):
        """ Return protocol as integer value"""
        return capi.nlmsg_get_proto(self._msg)

    @protocol.setter
    def protocol(self, value):
        capi.nlmsg_set_proto(self._msg, int(value))

    @property
    def maxSize(self):
        return capi.nlmsg_get_max_size(self._msg)

    @property
    def hdr(self):
        return capi.nlmsg_hdr(self._msg)

    @property
    def data(self):
        return capi.nlmsg_data(self._msg)

    @property
    def attrs(self):
        return capi.nlmsg_attrdata(self._msg)

class Socket(object):
    """Netlink socket"""

    def __init__(self, cb=None):
        self._sock = None
        if cb is None:
            self._sock = capi.nl_socket_alloc()
        else:
            self._sock = capi.nl_socket_alloc_cb(cb)

        if self._sock is None:
            raise Exception('NULL pointer returned while allocating socket')

    def __del__(self):
        if self._sock is not None:
            capi.nl_socket_free(self._sock)

    def __repr__(self):
        return 'nlsock<{0}>'.format(self.localPort)

    @property
    def local_port(self):
        return capi.nl_socket_get_local_port(self._sock)

    @local_port.setter
    def local_port(self, value):
        capi.nl_socket_set_local_port(self._sock, int(value))

    @property
    def peer_port(self):
        return capi.nl_socket_get_peer_port(self._sock)

    @peer_port.setter
    def peer_port(self, value):
        capi.nl_socket_set_peer_port(self._sock, int(value))

    @property
    def peer_groups(self):
        return capi.nl_socket_get_peer_groups(self._sock)

    @peer_groups.setter
    def peer_groups(self, value):
        capi.nl_socket_set_peer_groups(self._sock, int(value))

    def set_bufsize(self, rx, tx):
        capi.nl_socket_set_buffer_size(self._sock, int(rx), int(tx))

    def connect(self, proto):
        capi.nl_connect(self._sock, int(proto))

    def disconnect(self):
        capi.nl_close(self._sock)

    def sendto(self, buf):
        buf = bytes(buf)
        ret = capi.nl_sendto(self._sock, buf, len(buf))
        if ret < 0:
            raise CAPIError('Failed to send (retval {0})'.format(ret))
        return ret

    def send(self, message):
        ret = capi.nl_send(self._sock, message._msg)
        if ret < 0:
            raise CAPIError('Failed to send (retval {0})'.format(ret))
        return ret

class DumpParams(object):
    """Dumping parameters"""

    def __init__(self, type_=NL_DUMP_LINE):
        self._dp = capi.alloc_dump_params()
        if self._dp is None:
            raise CAPIError('Unable to allocate struct nl_dump_params')

        self._dp.dp_type = type_

    def __del__(self):
        if self._dp is not None:
            capi.free_dump_params(self._dp)

    @property
    def type(self):
        return self._dp.dp_type

    @type.setter
    def type(self, value):
        self._dp.dp_type = int(value)

    @property
    def prefix(self):
        return self._dp.dp_prefix

    @prefix.setter
    def prefix(self, value):
        self._dp.dp_prefix = int(value)



class Object(object):
    """Cacheable object (base class)"""

    _defaultDumpParams = DumpParams(NL_DUMP_LINE)

    def __init__(self, obj_name, name, obj=None):
        self._nl_object = None

        if self.__class__ is Object:
            raise NotImplementedError('Object is abstract class')

        self._obj_name = bytes(obj_name)
        if obj is None:
            self._nl_object = capi.object_alloc_name(self._obj_name)
            if self._nl_object is None:
                raise CAPIError('Can not allocate object')
        else:
            self._nl_object = obj
        self._name = name
        self._modules = []

        # Create a clone which stores the original state to notice
        # modifications
        clone_obj = capi.nl_object_clone(self._nl_object)
        if clone_obj is None:
            raise CAPIError('Can not clone netlink object')
        self._orig = self._obj2type(clone_obj)

    def __del__(self):
        if self._nl_object is not None:
            capi.nl_object_put(self._nl_object)

    @staticmethod
    def _obj2type(self, obj):
        raise NotImplementedError()

    def __str__(self):
        if hasattr(self, 'format'):
            return self.format()
        return str(capi.nl_object_dump_buf(self._nl_object, 4096)).rstrip()

    def _new_instance(self):
        raise NotImplementedError()

    def clone(self):
        clone_obj = capi.nl_object_clone(self._nl_object)
        if clone_obj is None:
            raise CAPIError('Can not clone netlink object')
        return self._new_instance(clone_obj)

    def _module_lookup(self, path, constructor=None):
        """Lookup object specific module and load it

        Object implementations consisting of multiple types may
        offload some type specific code to separate modules which
        are loadable on demand, e.g. a VLAN link or a specific
        queueing discipline implementation.

        Loads the module `path` and calls the constructor if
        supplied or `module`.init()

        The constructor/init function typically assigns a new
        object covering the type specific implementation aspects
        to the new object, e.g. link.vlan = VLANLink()
        """
        try:
            __import__(path)
        except ImportError:
            return

        module = sys.modules[path]

        if constructor:
            ret = getattr(module, constructor)(self)
        else:
            ret = module.init(self)

        if ret:
            self._modules.append(ret)

    def _module_brief(self):
        ret = []

        for module in self._modules:
            if hasattr(module, 'brief'):
                ret.append(module.brief())

        return ''.join(ret)

    def dump(self, params=None):
        """Dump object as human readable text"""
        if params is None:
            params = self._defaultDumpParams

        capi.nl_object_dump(self._nl_object, params._dp)


    @property
    def mark(self):
        return bool(capi.nl_object_is_marked(self._nl_object))

    @mark.setter
    def mark(self, value):
        if value:
            capi.nl_object_mark(self._nl_object)
        else:
            capi.nl_object_unmark(self._nl_object)

    @property
    def shared(self):
        return bool(capi.nl_object_shared(self._nl_object))

    @property
    def attrs(self):
        attr_list = capi.nl_object_attr_list(self._nl_object, 1024)
        return str(attr_list[0]).split()

    @property
    def refcnt(self):
        return capi.nl_object_get_refcnt(self._nl_object)

class ObjIterator(object):
    def __init__(self, cache, obj):
        self._nl_object = None
        self._cache = cache

        if not obj:
            self._end = 1
        else:
            capi.nl_object_get(obj)
            self._nl_object = obj
            self._first = 1
            self._end = 0

    def __del__(self):
        if self._nl_object is not None:
            capi.nl_object_put(self._nl_object)

    def __iter__(self):
        return self

    def get_next(self):
        return capi.nl_cache_get_next(self._nl_object)

    def next(self):
        if self._end:
            raise StopIteration()

        if self._first:
            ret = self._nl_object
            self._first = 0
        else:
            ret = self.get_next()
            if not ret:
                self._end = 1
                raise StopIteration()

        # return ref of previous element and acquire ref of current
        # element to have object stay around until we fetched the
        # next ptr
        capi.nl_object_put(self._nl_object)
        capi.nl_object_get(ret)
        self._nl_object = ret

        # reference used inside object
        capi.nl_object_get(ret)
        return self._cache.object_type(ret)


class ReverseObjIterator(ObjIterator):
    def get_next(self):
        return capi.nl_cache_get_prev(self._nl_object)

class Cache(object):
    """Collection of netlink objects"""

    _cache_name = None # undefined, should be defined in subclasses
    _protocol = None # undefined, should be defined in subclasses
    object_type = None # undefined, should be the type of cached objects

    def __init__(self):
        self._nl_cache = None
        if self.__class__ is Cache:
            raise NotImplementedError()
        self._nl_cache = self._alloc_cache_name(self._cache_name)
        self.arg1 = None
        self.arg2 = None

    def __del__(self):
        if self._nl_cache is not None:
            capi.nl_cache_free(self._nl_cache)

    def __len__(self):
        return capi.nl_cache_nitems(self._nl_cache)

    def __iter__(self):
        obj = capi.nl_cache_get_first(self._nl_cache)
        return ObjIterator(self, obj)

    def __reversed__(self):
        obj = capi.nl_cache_get_last(self._nl_cache)
        return ReverseObjIterator(self, obj)

    def __contains__(self, item):
        obj = capi.nl_cache_search(self._nl_cache, item._nl_object)
        if obj is None:
            return False
        capi.nl_object_put(obj)
        return True

    # called by sub classes to allocate type specific caches by name
    @staticmethod
    def _alloc_cache_name(name):
        cache = capi.alloc_cache_name(bytes(name))
        if cache is None:
            raise CAPIError('Can not allocate cache by name {0}'.format(name))
        return cache

    # implemented by sub classes, must return instance of sub class
    def _new_cache(self, cache):
        raise NotImplementedError()

    def subset(self, filter_):
        """Return new cache containing subset of cache

        Cretes a new cache containing all objects which match the
        specified filter.
        """
        c = capi.nl_cache_subset(self._nl_cache, filter_._nl_object)
        return self._new_cache(cache=c)

    def dump(self, params=None, filter_=None):
        """Dump (print) cache as human readable text"""
        if not params:
            params = Object._defaultDumpParams

        if filter_:
            filter_ = filter_._nl_object

        capi.nl_cache_dump_filter(self._nl_cache, params._dp, filter_)

    def clear(self):
        """Remove all cache entries"""
        capi.nl_cache_clear(self._nl_cache)

    # Called by sub classes to set first cache argument
    def _set_arg1(self, arg):
        self.arg1 = arg
        capi.nl_cache_set_arg1(self._nl_cache, arg)

    # Called by sub classes to set second cache argument
    def _set_arg2(self, arg):
        self.arg2 = arg
        capi.nl_cache_set_arg2(self._nl_cache, arg)

    def refill(self, sock):
        """Clear cache and refill it"""
        capi.nl_cache_refill(sock._sock, self._nl_cache)

    def resync(self, sock, cb=None):
        """Synchronize cache with content in kernel"""
        capi.nl_cache_resync(sock._sock, self._nl_cache, cb)

    def provide(self):
        """Provide this cache to others

        Caches which have been "provided" are made available
        to other users (of the same application context) which
        "require" it. F.e. a link cache is generally provided
        to allow others to translate interface indexes to
        link names
        """

        capi.nl_cache_mngt_provide(self._nl_cache)

    def unprovide(self):
        """Unprovide this cache

        No longer make the cache available to others. If the cache
        has been handed out already, that reference will still
        be valid.
        """
        capi.nl_cache_mngt_unprovide(self._nl_cache)

# Cache Manager (Work in Progress)
NL_AUTO_PROVIDE = 1
class CacheManager(object):
    def __init__(self, protocol, flags=NL_AUTO_PROVIDE):
        self._sock = None
        self._mngr = None
        self._sock = Socket()
        self._sock.connect(int(protocol))
        self._mngr = capi.cache_mngr_alloc(self._sock._sock, int(protocol), int(flags))
        if self._mngr is None:
            raise CAPIError('Can not allocate cache manager')

    def __del__(self):
        if self._mngr is not None:
            capi.nl_cache_mngr_free(self._mngr)

        if self._sock is not None:
            self._sock.disconnect()


    def add(self, name):
        capi.cache_mngr_add(self._mngr, bytes(name), None, None)

class AddressFamily(object):
    """Address family representation

    af = AddressFamily('inet6')
    # raises:
    #   - ValueError if family name is not known
    #   - TypeError if invalid type is specified for family

    print af        # => 'inet6' (string representation)
    print int(af)   # => 10 (numeric representation)
    print repr(af)  # => AddressFamily('inet6')
    """
    def __init__(self, family=socket.AF_UNSPEC):
        if isinstance(family, basestring):
            self._family = capi.nl_str2af(bytes(family))
            if self._family < 0:
                raise ValueError('Unknown family name {0}'.format(family)
        else:
            self._family = int(family)

    def __str__(self):
        return str(capi.nl_af2str(self._family, 32)[0])

    def __int__(self):
        return self._family

    def __cmp__(self, other):
        return self._family - other._family

    def __repr__(self):
        return 'AddressFamily({0!r})'.format(str(self))


class AbstractAddress(object):
    """Abstract address object

    addr = AbstractAddress('127.0.0.1/8')
    print addr               # => '127.0.0.1/8'
    print addr.prefixlen     # => '8'
    print addr.family        # => 'inet'
    print len(addr)          # => '4' (32bit ipv4 address)

    a = AbstractAddress('10.0.0.1/24')
    b = AbstractAddress('10.0.0.2/24')
    print a == b             # => False


    """
    def __init__(self, addr):
        self._nl_addr = None

        if isinstance(addr, basestring):
            addr_ = capi.addr_parse(addr, socket.AF_UNSPEC)
            if addr_ is None:
                raise ValueError('Invalid address {0!r}'.format(addr))
            addr = addr_
        self._nl_addr = capi.nl_addr_get(addr)

    def __del__(self):
        if self._nl_addr is not None:
            capi.nl_addr_put(self._nl_addr)

    def __cmp__(self, other):
        if isinstance(other, basestring):
            other = AbstractAddress(other)

        diff = self.prefixlen - other.prefixlen
        if diff:
            return diff
        return capi.nl_addr_cmp(self._nl_addr, other._nl_addr)

    def __contains__(self, item):
        if isinstance(item, basestring):
            item = AbstractAddress(item)

        if item.family != self.family:
            return False

        if item.prefixlen < self.prefixlen:
            return False

        return not bool(capi.nl_addr_cmp_prefix(self._nl_addr, item._nl_addr))

    def __nonzero__(self):
        return not bool(capi.nl_addr_iszero(self._nl_addr))

    def __len__(self):
        return capi.nl_addr_get_len(self._nl_addr)

    def __str__(self):
        return str(capi.nl_addr2str(self._nl_addr, 64)[0])

    @property
    def shared(self):
        """True if address is shared (multiple users)"""
        return bool(capi.nl_addr_shared(self._nl_addr))

    @property
    def prefixlen(self):
        """Length of prefix (number of bits)"""
        return capi.nl_addr_get_prefixlen(self._nl_addr)

    @prefixlen.setter
    def prefixlen(self, value):
        capi.nl_addr_set_prefixlen(self._nl_addr, int(value))

    @property
    def family(self):
        """Address family"""
        return AddressFamily(capi.nl_addr_get_family(self._nl_addr))

    @family.setter
    def family(self, value):
        if not isinstance(value, AddressFamily):
            value = AddressFamily(value)

        capi.nl_addr_set_family(self._nl_addr, int(value))


# keyword:
#   type = { int | str }
#   immutable = { True | False }
#   fmt = func (formatting function)
#   title = string

def nlattr(**kwds):
    """netlink object attribute decorator

    decorator used to mark mutable and immutable properties
    of netlink objects. All properties marked as such are
    regarded to be accessable.

    @property
    @netlink.nlattr(type=int)
    def my_attr(self):
        return self._my_attr

    """

    def wrap_fn(func):
        func.formatinfo = kwds
        return func
    return wrap_fn
