import re

from glob import glob
from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

_pkg_name = 'pyeudiw'

with open(f'{_pkg_name}/__init__.py', 'r') as fd:
    VERSION = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE).group(1)

setup(
    name=_pkg_name,
    version=VERSION,
    description="Python toolchain for building an OpenID4VP RP with a SATOSA backend compliant to the Italian Wallet Solution.",
    long_description=readme(),
    long_description_content_type='text/markdown',
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: 3.15",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    url='https://github.com/italia/eudi-wallet-it-python',
    author='Giuseppe De Marco',
    author_email='demarcog83@gmail.com',
    license='License :: OSI Approved :: Apache Software License',
    # scripts=[f'{_pkg_name}/bin/{_pkg_name}'],
    packages=[f"{_pkg_name}"],
    package_dir={f"{_pkg_name}": f"{_pkg_name}"},
    package_data={f"{_pkg_name}": [
            i.replace(f'{_pkg_name}/', '')
            for i in glob(f'{_pkg_name}/**', recursive=True)
        ]
    },
    install_requires=[
        "cryptojwt>=1.9,<1.10",
        "pydantic>=2.11.9,<3.0.0",
        "pyqrcode>=1.2,<1.3",
        "pem>=23.1,<23.2",
        "cryptography>=45.0.0,<46.0.0"
    ],
    extras_require={
        "satosa": [
            "Pillow>=11.1.0,<12.0.0",
            "device_detector>=5.0,<6",
            "satosa>=8.4,<8.6",
            "jinja2>=3.1.5,<4.0.0",
            "pymongo>=4.10.1,<5.0.0",
            "requests>=2.32.3,<3.0.0",
            "pymdoccbor>=0.9.0,<2.0.0"
        ],
        "federation": [
            "asyncio>=3.4.3,<4.0.0",
            "aiohttp>=3.11.11,<4.0.0"
        ],
        "test": [
            "pytest-mock",
        ]
    }
)
