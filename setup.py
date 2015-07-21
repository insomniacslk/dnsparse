from distutils.core import setup

import dnsparse


setup(
    name='dnsparse',
    version=dnsparse.__version__,
    description=dnsparse.__description__,
    author=dnsparse.__author__,
    author_email=dnsparse.__email__,
    url='https://github.com/insomniacslk/dnsparse',
    packages=['dnsparse'],
)
