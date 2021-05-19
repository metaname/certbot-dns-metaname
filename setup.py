from setuptools import find_packages
from setuptools import setup

setup(
    name="certbot-dns-metaname",
    version="0.0.2",
    description="Certbot DNS plugin for the Metaname API",
    url="https://github.com/metaname/certbot-dns-metaname",
    author="Metaname",
    author_email="support@metaname.nz",
    license="Apache License 2.0",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=["certbot", "zope.interface", "requests"],
    entry_points={
        "certbot.plugins": ["dns-metaname = certbot_dns_metaname:Authenticator"]
    },
)
