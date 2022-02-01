# Automatically generated from poetry/pyproject.toml
# flake8: noqa
# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['c7n_kube',
 'c7n_kube.actions',
 'c7n_kube.resources',
 'c7n_kube.resources.apps',
 'c7n_kube.resources.core']

package_data = \
{'': ['*']}

install_requires = \
['argcomplete (>=2.0.0,<3.0.0)',
 'attrs (>=21.4.0,<22.0.0)',
 'boto3 (>=1.20.37,<2.0.0)',
 'botocore (>=1.23.37,<2.0.0)',
 'c7n (>=0.9.15,<0.10.0)',
 'docutils (>=0.17.1,<0.18.0)',
 'importlib-metadata (>=4.10.1,<5.0.0)',
 'importlib-resources (>=5.4.0,<6.0.0)',
 'jmespath (>=0.10.0,<0.11.0)',
 'jsonschema (>=4.4.0,<5.0.0)',
 'kubernetes>=10.0.1,<11.0.0',
 'pyrsistent (>=0.18.1,<0.19.0)',
 'python-dateutil (>=2.8.2,<3.0.0)',
 'pyyaml (>=6.0,<7.0)',
 's3transfer (>=0.5.0,<0.6.0)',
 'six (>=1.16.0,<2.0.0)',
 'tabulate (>=0.8.9,<0.9.0)',
 'typing-extensions (>=4.0.1,<5.0.0)',
 'urllib3 (>=1.26.8,<2.0.0)',
 'zipp (>=3.7.0,<4.0.0)']

setup_kwargs = {
    'name': 'c7n-kube',
    'version': '0.2.14',
    'description': 'Cloud Custodian - Kubernetes Provider',
    'license': 'Apache-2.0',
    'classifiers': [
        'License :: OSI Approved :: Apache Software License',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Distributed Computing'
    ],
    'long_description': '# Custodian Kubernetes Support\n\n\nWork in Progress - Not Ready For Use.\n\n',
    'long_description_content_type': 'text/markdown',
    'author': 'Cloud Custodian Project',
    'author_email': None,
    'maintainer': None,
    'maintainer_email': None,
    'url': 'https://cloudcustodian.io',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'python_requires': '>=3.7,<4.0',
}


setup(**setup_kwargs)
