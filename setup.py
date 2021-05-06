from setuptools import find_packages
from setuptools import setup

requirements = ["certbot"]

setup(
    name="certbot-dns-metaname",
    version="0",
    description="Certbot DNS plugin for the Metaname API",
    url="http://example.invalid/",
    author="Michael Fincham",
    author_email="michael@hotplate.co.nz",
    license="Proprietary",
    python_requires=">=3.6",
    classifiers=[
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "certbot.plugins": [
            "dns-metaname = certbot_dns_metaname:Authenticator"
        ]
    },
    test_suite="",
)
