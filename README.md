# dnsparse
A library to parse and build DNS packets, based on Construct

This library is a collection of modules, classes and functions aimed to parse
and build DNS packets.

# Example usage

    data = (
      '\x102\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00' '\x00\x10\x00\x01\x06google\x03com\x00\x00\x10\x00\x01\x00\x00\x01'
     '\x0e\x00\x10\x0fv=spf1 ptr ?all'
     )
     packet = DNSHeader.parse(data)
     print packet.questions
     print packet.answers

See tests or source code for more usage hints

# Running tests

Requires pytest

run

    PYTHONPATH=. py.test -v

# Just that?
Better documentation coming soon
