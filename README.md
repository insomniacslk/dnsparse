# dnsparse
A library to parse and build DNS packets, based on Construct

This library is a collection of modules, classes and functions aimed to parse
and build DNS packets.

# Example usage

    from dnsparse.dnsheader import DNSHeader
    
    data = (
      '\x102\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00' '\x00\x10\x00\x01\x06google\x03com\x00\x00\x10\x00\x01\x00\x00\x01'
    '\x0e\x00\x10\x0fv=spf1 ptr ?all'
    )
    packet = DNSHeader.parse(data)
    print packet.questions
    print packet.answers

will print

    [
        Container:
            qname = ['google', 'com', '']
            qtype = 'TXT'
            qclass = 'IN'
    ]
    [
        Container:
            length_or_offset = Container:
                length = 6
                offset = 1639
            name = ['google', 'com', '']
            type = 'TXT'
            class = 'IN'
            ttl = 270
            rdlength = 16
            rdata = 'v=spf1 ptr ?all'
    ]


See tests or source code for more usage examples

# Running tests

Requires pytest

run

    PYTHONPATH=. py.test -v

# Just that?
Better documentation coming soon
