from setuptools import setup, find_packages

import gimme_airflow_creds

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='gimme aws creds',
    version=gimme_airflow_creds.version,
    install_requires=requirements,
    author='Ann Wallace',
    author_email='ann.wallace@nike.com',
    description="A CLI to get temporary AWS credentials from Okta",
    url='https://github.com/Nike-Inc/gimme-airflow-creds',
    license='Apache License, v2.0',
    packages=find_packages(exclude=('tests', 'docs')),
    test_suite="tests",
    scripts=['bin/gimme-airflow-creds', 'bin/gimme-airflow-creds.cmd'],
    classifiers=[
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
        'License :: OSI Approved :: Apache Software License'
    ]
)
