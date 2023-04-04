# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Supplemental tooling for managing custodian packaging.

Has various workarounds for poetry
"""
from collections import defaultdict
import click
import os
import sys
import tomli as toml
from pathlib import Path


def envbool(value):
    if not value:
        return False
    value = value.lower()
    if value == 'true':
        return True
    elif value == 'yes':
        return True
    return False


POETRY_DEBUG = envbool(os.environ.get('POETRY_DEBUG'))


@click.group()
def cli():
    """Custodian Python Packaging Utility

    some simple tooling to sync poetry files to setup/pip
    """

    # if we're using poetry from git, have a flag to prevent the user installed
    # one from getting precedence.
    if POETRY_DEBUG:
        return

    # If there is a global installation of poetry, prefer that.
    poetry_python_lib = Path(os.path.expanduser('~/.poetry/lib'))
    if poetry_python_lib.exists():
        sys.path.insert(0, os.path.realpath(poetry_python_lib))
        # poetry env vendored deps
        sys.path.insert(
            0,
            os.path.join(
                poetry_python_lib,
                'poetry',
                '_vendor',
                'py{}.{}'.format(sys.version_info.major, sys.version_info.minor),
            ),
        )

    # If there is a global installation of poetry, prefer that.
    cur_poetry_python_lib = Path(os.path.expanduser('~/.local/share/pypoetry/venv/lib'))
    if cur_poetry_python_lib.exists():
        sys.path.insert(
            0, str(list(cur_poetry_python_lib.glob('*'))[0] / "site-packages")
        )

    osx_poetry_python_lib = Path(
        os.path.expanduser('~/Library/Application Support/pypoetry/venv/lib')
    )
    if osx_poetry_python_lib.exists():
        sys.path.insert(
            0, str(list(osx_poetry_python_lib.glob('*'))[0] / "site-packages")
        )


# Override the poetry base template as all our readmes files
# are in markdown format.
#
# Pull request submitted upstream to correctly autodetect
# https://github.com/python-poetry/poetry/pull/1994
#
SETUP_TEMPLATE = """\
# -*- coding: utf-8 -*-
from setuptools import setup

{before}
setup_kwargs = {{
    'name': {name!r},
    'version': {version!r},
    'description': {description!r},
    'license': 'Apache-2.0',
    'classifiers': [
        'License :: OSI Approved :: Apache Software License',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Distributed Computing'
    ],
    'long_description': {long_description!r},
    'long_description_content_type': 'text/markdown',
    'author': 'Cloud Custodian Project',
    'author_email': 'cloud-custodian@googlegroups.com',
    'project_urls': {{
       'Homepage': {url!r},
       'Documentation': 'https://cloudcustodian.io/docs/',
       'Source': 'https://github.com/cloud-custodian/cloud-custodian',
       'Issue Tracker': 'https://github.com/cloud-custodian/cloud-custodian/issues',
    }},
    {extra}
}}
{after}

setup(**setup_kwargs)
"""


@cli.command()
@click.option('-p', '--package-dir', type=click.Path())
@click.option('-f', '--version-file', type=click.Path())
def gen_version_file(package_dir, version_file):
    with open(Path(str(package_dir)) / 'pyproject.toml', 'rb') as f:
        data = toml.load(f)
    version = data['tool']['poetry']['version']
    with open(version_file, 'w') as fh:
        fh.write('# Generated via tools/dev/poetrypkg.py\n')
        fh.write('version = "{}"\n'.format(version))


@cli.command()
@click.option('-p', '--package-dir', type=click.Path())
def gen_setup(package_dir):
    """Generate a setup suitable for dev compatibility with pip."""
    from poetry.core.masonry.builders import sdist
    from poetry.factory import Factory

    factory = Factory()
    poetry = factory.create_poetry(package_dir)

    # the alternative to monkey patching is carrying forward a
    # 100 line method. See SETUP_TEMPLATE comments above.
    sdist.SETUP = SETUP_TEMPLATE

    class SourceDevBuilder(sdist.SdistBuilder):
        # to enable poetry with a monorepo, we have internal deps
        # as source path dev dependencies, when we go to generate
        # setup.py we need to ensure that the source deps are
        # recorded faithfully.

        @classmethod
        def convert_dependencies(cls, package, dependencies):
            reqs, default = super().convert_dependencies(package, dependencies)
            resolve_source_deps(poetry, package, reqs)
            return reqs, default

    builder = SourceDevBuilder(poetry, None, None)
    setup_content = builder.build_setup()

    with open(os.path.join(package_dir, 'setup.py'), 'wb') as fh:
        fh.write(b'# Automatically generated from poetry/pyproject.toml\n')
        fh.write(b'# flake8: noqa\n')
        fh.write(setup_content)


@cli.command()
@click.option('-p', '--package-dir', type=click.Path())
@click.option('-o', '--output', default='setup.py')
@click.option('-x', '--exclude', multiple=True)
@click.option('-r', '--remove', multiple=True)
def gen_frozensetup(package_dir, output, exclude, remove):
    """Generate a frozen setup suitable for distribution."""
    from poetry.core.masonry.builders import sdist
    from poetry.factory import Factory

    factory = Factory()
    poetry = factory.create_poetry(package_dir)

    sdist.SETUP = SETUP_TEMPLATE

    class FrozenBuilder(sdist.SdistBuilder):
        @classmethod
        def convert_dependencies(cls, package, dependencies):
            reqs, default = locked_deps(package, poetry, exclude, remove)
            resolve_source_deps(poetry, package, reqs, frozen=True)
            return reqs, default

    builder = FrozenBuilder(poetry, None, None)
    setup_content = builder.build_setup()

    with open(os.path.join(package_dir, output), 'wb') as fh:
        fh.write(b'# Automatically generated from pyproject.toml\n')
        fh.write(b'# flake8: noqa\n')
        fh.write(setup_content)


def resolve_source_deps(poetry, package, reqs, frozen=False):
    # find any source path dev deps and them and their recursive
    # deps to reqs
    if poetry.local_config['name'] not in (package.name, package.pretty_name):
        return

    source_deps = []
    for dep_name, info in poetry.local_config.get('dev-dependencies', {}).items():
        if isinstance(info, dict) and 'path' in info:
            source_deps.append(dep_name)
    if not source_deps:
        return

    from poetry.core.packages.dependency import Dependency

    # normalize deps by lowercasing all the keys
    dep_map = {d['name'].lower(): d for d in poetry.locker.lock_data['package']}
    seen = set(source_deps)
    seen.add('setuptools')

    prefix = '' if frozen else '^'
    while source_deps:
        dep = source_deps.pop()
        dep = dep.lower()
        if dep not in dep_map:
            dep = dep.replace('_', '-')
        if dep not in dep_map:
            dep = dep.replace('-', '_')
        version = dep_map[dep]['version']
        reqs.append(Dependency(dep, '{}{}'.format(prefix, version)).to_pep_508())
        for cdep, cversion in dep_map[dep].get('dependencies', {}).items():
            if cdep in seen:
                continue
            source_deps.append(cdep)
            seen.add(cdep)


def locked_deps(package, poetry, exclude=(), remove=()):
    from poetry_plugin_export.walker import get_project_dependency_packages

    reqs = []
    deps = get_project_dependency_packages(
        locker=poetry._locker,
        project_requires=package.requires,
        root_package_name=package.name,
        project_python_marker=package.python_marker,
        extras=package.extras)

    project_deps = {r.name: r for r in poetry.package.requires}
    extra_reqs = defaultdict(list)

    for dep_pkg in deps:
        p = dep_pkg.package
        d = dep_pkg.dependency

        if p.name in exclude and p.name in project_deps:
            reqs.append(project_deps[p.name].to_pep_508())
            continue
        if p.name in remove:
            continue

        line = "{}=={}".format(p.name, p.version)
        requirement = d.to_pep_508(with_extras=False)
        if ';' in requirement:
            line += "; {}".format(requirement.split(";")[1].strip())
        if not p.optional:
            reqs.append(line)
        for extra in (p.name in project_deps and project_deps[p.name].in_extras or []):
            extra_reqs[extra].append(line)

    return reqs, dict(extra_reqs)


if __name__ == '__main__':
    cli()
