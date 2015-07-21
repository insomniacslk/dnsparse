'''
    dnsparse.dnsheader

    Module for parsing DNS packets

    Author: Andrea Barberio <insomniac@slackware.it>
'''

import os

from construct import (
    this,
    Adapter,
    IfThenElse,
    Switch,
    Embed,
    Struct,
    Union,
    Array,
    Enum,
    Anchor,
    Pointer,
    RepeatUntil,
    BitStruct,
    BitField,
    Nibble,
    Bytes,
    Flag,
    UBInt8,
    UBInt16,
    UBInt32,
    PascalString,
)


# TODO implement packet crafting
# TODO implement parsing from zone file/line
# TODO implement Label as Adapter subclass to enable decoding


def Label(name):
    '''
    return a construct to parse/build a DNS label.

    Example:
    >> Label('qname').parse('\x05hello\x00')
    >> ['hello', '']

    :param name: the name of the field
    :type name: string
    :returns: a construct to parse/build a DNS label
    :rtype: construct.core.RepeatUntil
    '''
    return RepeatUntil(
        lambda obj, ctx: obj == '',
        PascalString(name),
    )


def Type(name):
    '''
    return a construct to parse/build a DNS TYPE field.

    Example:
    >> Type('qtype').parse('\x00\x01')
    >>> 'A'
    >>> Type('qtype').build('AAAA')
    >>> '\0x00\x1c'

    :param name: the name of the field
    :type name: string
    :returns: a construct to parse/build a DNS TYPE field
    :rtype: construct.adapters.MappingAdapter
    '''
    return Enum(
        UBInt16(name),
        A=1,
        NS=2,
        MD=3,
        MF=4,
        CNAME=5,
        SOA=6,
        MB=7,
        MG=8,
        MR=9,
        NULL=10,
        WKS=11,
        PTR=12,
        HINFO=13,
        MINFO=14,
        MX=15,
        TXT=16,
        RP=17,
        AFSDB=18,
        X25=19,
        ISDN=20,
        RT=21,
        NSAP=22,
        NSAP_PTR=23,
        SIG=24,
        KEY=25,
        PX=26,
        GPOS=27,
        AAAA=28,
        LOC=29,
        NXT=30,
        EID=31,
        NIMLOC=32,
        SRV=33,
        ATMA=34,
        NAPTR=35,
        KX=36,
        CERT=37,
        A6=38,
        DNAME=39,
        SINK=40,
        OPT=41,
        APL=42,
        DS=43,
        SSHFP=44,
        IPSECKEY=45,
        RRSIG=46,
        NSEC=47,
        DNSKEY=48,
        DHCID=49,
        NSEC3=50,
        NSEC3PARAM=51,
        TLSA=52,
        Unassigned=53-54,
        HIP=55,
        NINFO=56,
        RKEY=57,
        TALINK=58,
        CDS=59,
        CDNSKEY=60,
        OPENPGPKEY=61,
        CSYNC=62,
        SPF=99,
        UINFO=100,
        UID=101,
        GID=102,
        UNSPEC=103,
        NID=104,
        L32=105,
        L64=106,
        LP=107,
        EUI48=108,
        EUI64=109,
        TKEY=249,
        TSIG=250,
        IXFR=251,
        AXFR=252,
        MAILB=253,
        MAILA=254,
        STAR=255,
        URI=256,
        CAA=257,
        TA=32768,
        DLV=32769,
    )


def Class(name):
    '''
    return a construct to parse/build a DNS CLASS field.

    Example:
    >> Class('class').parse('\x00\x01')
    >>> 'IN'
    >>> Class('class').build('HS')
    >>> '\0x00\x04'

    :param name: the name of the field
    :type name: string
    :returns: a construct to parse/build a DNS CLASS field
    :rtype: construct.adapters.MappingAdapter
    '''
    return Enum(
        UBInt16(name),
        IN=1,       # internet
        CH=3,       # Chaos
        HS=4,       # Hesiod
        ANY=255,
    )


# used for DNS questions
QNAME = Label('qname')
QTYPE = Type('qtype')
QCLASS = Class('qclass')

# used for DNS answers
NAME = Label('name')
TYPE = Type('type')
CLASS = Class('class')


def Query(name):
    '''
    return a construct to parse/build a DNS Query structure.

    Example:
    >>> Query('questions').parse(
    ...     '\x05hello\x00'
    ...     '\x00\x01'
    ...     '\x00\x01'
    ... )
    Container({'qclass': 'IN', 'qtype': 'A', 'qname': ['hello', '']})

    :param name: the name of the field
    :type name: string
    :returns: a construct to parse/build a DNS Query structure
    :rtype: construct.core.Struct
    '''
    return Struct(
        name,
        QNAME,
        QTYPE,
        QCLASS,
    )


TTL = UBInt32('ttl')
RDLENGTH = UBInt16('rdlength')


class MovingPointer(Pointer):
    '''
    A Pointer that moves forward
    '''

    def __init__(self, offsetfunc, subcon, offset=None, whence=os.SEEK_CUR):
        Pointer.__init__(self, offsetfunc, subcon)
        self._ptr_offset = offset
        self._ptr_whence = whence

    def _parse(self, stream, context):
        origpos = stream.tell()
        newpos = self.offsetfunc(context)
        stream.seek(newpos, 2 if newpos < 0 else 0)
        obj = self.subcon._parse(stream, context)
        if self._ptr_offset is not None:
            if self._ptr_whence == os.SEEK_CUR:
                stream.seek(origpos + self._ptr_offset, os.SEEK_SET)
            elif self._ptr_whence == os.SEEK_SET:
                stream.seek(origpos, os.SEEK_SET)
            else:
                raise ValueError('Invalid whence parameter: {}'
                                 .format(self._ptr_whence))
        return obj

    def _build(self, obj, stream, context):
        origpos = stream.tell()
        newpos = self.offsetfunc(context)
        stream.seek(newpos, 2 if newpos < 0 else 0)
        obj = self.subcon._build(obj, stream, context)
        if self._ptr_offset is not None:
            if self._ptr_whence == os.SEEK_CUR:
                stream.seek(origpos + self._ptr_offset, os.SEEK_SET)
            elif self._ptr_whence == os.SEEK_SET:
                stream.seek(origpos, os.SEEK_SET)
            else:
                raise ValueError('Invalid whence parameter: {}'
                                 .format(self._ptr_whence))
        return obj


# no more and no less than the IP adapter from Construct's docs
class IPV4AddressAdapter(Adapter):
    '''
    A representation of IP address.
    '''

    def _encode(self, obj, context):
        return ''.join(chr(int(b)) for b in obj.split('.'))

    def _decode(self, obj, context):
        return '.'.join(str(ord(b)) for b in obj)


def IPV4Address(name):
    return IPV4AddressAdapter(Bytes(name, 4))


# A Resource Record Name structure. Supports DNS pointer compression through the
# MovingPointer class
RRNAME = Struct(
    'name',
    Anchor('_start'),
    Union(
        'length_or_offset',
        UBInt8('length'),   # regular label
        UBInt16('offset'),  # compression pointer
    ),
    IfThenElse(
        'name',
        this.length_or_offset.length & 0xc0 == 0xc0,
        # compression pointer
        MovingPointer(
            lambda ctx: ctx.length_or_offset.offset & ~0xc000,
            Label('name'),
            offset=1,
            whence=os.SEEK_CUR,
        ),
        # regular label
        MovingPointer(this._start, Label('name')),
    ),
)


# An RData structure. Every field defines its own format for Rdata.
RDATA = Switch(
    'rdata',
    this.type,
    {
        # TODO implement more rdata types
        'TXT': PascalString('rdata'),
        'A': IPV4Address('ip'),
    },
    default=Bytes('rdata', this.rdlength),
)


# A Resource Record structure
def ResourceRecord(name):
    return Struct(
        name,
        Embed(RRNAME),
        TYPE,
        CLASS,
        TTL,
        RDLENGTH,
        RDATA,
    )

# The DNS packet header itself, combining all of the above
DNSHeader = Struct(
    'DNSHeader',
    Anchor('packet_start'),
    UBInt16('identification'),
    BitStruct(
        'flags_and_codes',
        Enum(
            BitField('qr', 1),  # query/response
            QUERY=0,
            RESPONSE=1,
        ),
        Nibble('opcode'),   # opcode
        Enum(
            Flag('aa'),     # authoritative answer
            NON_AUTHORITATIVE=0,
            AUTHORITATIVE=1,
        ),
        Enum(
            Flag('tc'),     # truncated
            NOT_TRUNCATED=0,
            TRUNCATED=1,
        ),
        Enum(
            Flag('rd'),     # recursion desired
            RECURSION_NOT_DESIRED=0,
            RECURSION_DESIRED=1,
        ),
        Enum(
            Flag('ra'),     # recursion available
            RECURSION_NOT_AVAILABLE=0,
            RECURSION_AVAILABLE=1,
        ),
        BitField('z', 1),   # zero
        Enum(
            Flag('ad'),     # authenticated data
            NOT_AUTHENTICATED=0,
            AUTHENTICATED=1,
        ),
        Enum(
            Flag('cd'),     # checking disabled
            CHECKING_ENABLED=0,
            CHECKING_DISABLED=1,
        ),
        Enum(
            Nibble('rcode'),    # return code
            No_Error=0,
            Format_Error=1,
            Server_Failure=2,
            Name_Error=3,
            Not_Implemented=4,
            Refused=5,
            YXDomain=6,
            YXRRSet=7,
            NXRRSet=8,
            NotAuth=9,
            NotZone=10,
            # 11-15 undefined
            BADVERS=16,
            BADKEY=17,
            BADTIME=18,
            BADMODE=19,
            BADNAME=20,
            BADALG=21,
            BADTRUNC=22,
            # 23-3840 undefined
            # 3841-4095 private use
            # 4096-65534 undefined
            # 65535 undefined
        ),
    ),
    UBInt16('total_questions'),
    UBInt16('total_answer_rrs'),
    UBInt16('total_authority_rrs'),
    UBInt16('total_additional_rrs'),
    Array(this.total_questions, Query('questions')),
    Array(this.total_answer_rrs, ResourceRecord('answers')),
    Array(this.total_authority_rrs, ResourceRecord('authority')),
    Array(this.total_additional_rrs, ResourceRecord('additional')),
)
