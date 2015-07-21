from dnsparse.dnsheader import (
    DNSHeader,
    Query,
    ResourceRecord,
    QNAME,
    QTYPE,
    QCLASS,
    RRNAME,
)

# TODO test malformed packets


def test_qname():
    qname = QNAME.parse(
        '\x05GRIMM'         # start of label
        '\x0butelsystems'
        '\x05local'
        '\x00'              # end of label
    )
    assert qname == ['GRIMM', 'utelsystems', 'local', '']


def test_qtype():
    assert QTYPE.parse('\x00\x01') == 'A'


def test_qclass():
    assert QCLASS.parse('\x00\x01') == 'IN'


def test_rrname():
    rr = RRNAME.parse(
        '\x05hello'     # rr name
        '\x00'          # end of rr name
    )
    assert rr.name == ['hello', '']


def test_rrname_compressed():
    rr = RRNAME.parse(
        '\xc0\x02'      # ptr to absolute offset 2
        '\x05hello'     # rr name
        '\x00'          # end of rr name
    )
    assert rr.name == ['hello', '']


def test_resource_record():
    rr = ResourceRecord('answers').parse(
        '\x05hello\x00'     # rr name
        '\x00\x01'          # type
        '\x00\x01'          # class
        '\x00\x00\x00\x0a'  # ttl
        '\x00\x04'          # rdlength
        '\x01\x02\x03\x04'              # rdata
    )
    assert rr.name == ['hello', '']
    assert rr.type == 'A'
    assert rr['class'] == 'IN'
    assert rr.ttl == 10
    assert rr.rdlength == 4
    assert rr.rdata == '1.2.3.4'


def test_txt():
    dns = DNSHeader.parse(
        '\x102\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00'
        '\x00\x10\x00\x01\x06google\x03com\x00\x00\x10\x00\x01\x00\x00\x01'
        '\x0e\x00\x10\x0fv=spf1 ptr ?all')
    assert dns.identification == 4146
    assert dns.total_questions == 1
    assert dns.total_answer_rrs == 1
    assert len(dns.answers) == 1
    assert dns.answers[0].rdata == 'v=spf1 ptr ?all'


def test_query():
    query = Query('name').parse(
        '\x05GRIMM'         # start of label
        '\x0butelsystems'
        '\x05local'
        '\x00'              # end of label
        '\x00\x01'          # type A
        '\x00\x01'          # class IN
    )
    assert query.qtype == 'A'
    assert query.qclass == 'IN'
    assert query.qname == ['GRIMM', 'utelsystems', 'local', '']


def test_dns_compression():
    packet = (
        '\x97\xc9'  # identification
        '\x81\x80'  # flags and codes
        '\x00\x01'  # total questions
        '\x00\x06'  # total answer RRs
        '\x00\x00'  # total authority RRs
        '\x00\x00'  # total additional RRs
        # questions
        '\x06google\x03com\x00'     # qname
        '\x00\x01'                  # qtype
        '\x00\x01'                  # qclass
        # Answers
        # answer #1
        '\xc0\x0c'          # pointer to absolute offset 0x0c
        '\x00\x01'          # type A
        '\x00\x01'          # class IN
        '\x00\x00\x01\x16'  # ttl 278
        '\x00\x04'          # rdlength
        'J}\x18q'           # rdata, IP address
        # answer #2
        '\xc0\x0c'          # pointer to absolute offset 0x0c
        '\x00\x01'          # type A
        '\x00\x01'          # class IN
        '\x00\x00\x01\x16'  # ttl 278
        '\x00\x04'          # rdlength
        'J}\x18f'           # rdata, IP address
        # answer #3
        '\xc0\x0c'          # pointer to absolute offset 0x0c
        '\x00\x01'          # type A
        '\x00\x01'          # class IN
        '\x00\x00\x01\x16'  # ttl 278
        '\x00\x04'          # rdlength
        'J}\x18\x8a'        # rdata, IP address
        # answer #4
        '\xc0\x0c'          # pointer to absolute offset 0x0c
        '\x00\x01'          # type A
        '\x00\x01'          # class IN
        '\x00\x00\x01\x16'  # ttl 278
        '\x00\x04'          # rdlength
        'J}\x18\x8b'        # rdata, IP address
        # answer #5
        '\xc0\x0c'          # pointer to absolute offset 0x0c
        '\x00\x01'          # type A
        '\x00\x01'          # class IN
        '\x00\x00\x01\x16'  # ttl 278
        '\x00\x04'          # rdlength
        'J}\x18d'           # rdata, IP address
        # answer #6
        '\xc0\x0c'          # pointer to absolute offset 0x0c
        '\x00\x01'          # type A
        '\x00\x01'          # class IN
        '\x00\x00\x01\x16'  # ttl 278
        '\x00\x04'          # rdlength
        'J}\x18e'           # rdata, IP address
    )
    dns = DNSHeader.parse(packet)

    # check questions
    assert len(dns.questions) == 1
    question = dns.questions[0]
    assert question.qtype == 'A'
    assert question.qclass == 'IN'
    assert question.qname == ['google', 'com', '']

    # check answer RRs
    assert len(dns.answers) == 6

    answer0 = dns.answers[0]
    assert answer0.name == ['google', 'com', '']
    assert answer0.ttl == 278
    assert answer0.type == 'A'
    assert answer0['class'] == 'IN'
    assert answer0.rdlength == 4
    assert answer0.rdata == '74.125.24.113'

    answer1 = dns.answers[1]
    assert answer1.name == ['google', 'com', '']
    assert answer1.ttl == 278
    assert answer1.type == 'A'
    assert answer1['class'] == 'IN'
    assert answer1.rdlength == 4
    assert answer1.rdata == '74.125.24.102'

    answer2 = dns.answers[2]
    assert answer2.name == ['google', 'com', '']
    assert answer2.ttl == 278
    assert answer2.type == 'A'
    assert answer2['class'] == 'IN'
    assert answer2.rdlength == 4
    assert answer2.rdata == '74.125.24.138'

    answer3 = dns.answers[3]
    assert answer3.name == ['google', 'com', '']
    assert answer3.ttl == 278
    assert answer3.type == 'A'
    assert answer3['class'] == 'IN'
    assert answer3.rdlength == 4
    assert answer3.rdata == '74.125.24.139'

    answer4 = dns.answers[4]
    assert answer4.name == ['google', 'com', '']
    assert answer4.ttl == 278
    assert answer4.type == 'A'
    assert answer4['class'] == 'IN'
    assert answer4.rdlength == 4
    assert answer4.rdata == '74.125.24.100'

    answer5 = dns.answers[5]
    assert answer5.name == ['google', 'com', '']
    assert answer5.ttl == 278
    assert answer5.type == 'A'
    assert answer5['class'] == 'IN'
    assert answer5.rdlength == 4
    assert answer5.rdata == '74.125.24.101'

    # check authority RRs
    assert len(dns.authority) == 0

    # check additional RRs
    assert len(dns.additional) == 0
