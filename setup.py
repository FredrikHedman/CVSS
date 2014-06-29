from setuptools import setup, find_packages
from codecs import open  # To use a consistent encoding
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='cvss',
    version='1.20.1',

    description='CVSS calculator for CVSS version 2.10',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/FredrikHedman/CVSS',

    # Author details
    author='Fredrik Hedman',
    author_email='cvss@noruna.se',

    # Choose your license
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    # What does your project relate to?
    keywords='CVSS, Common Vulnerability Scoring System, IT-Security',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    # packages=find_packages(),
    packages=find_packages(exclude=['examples', 'misc', 'tests*']),

    # List run-time dependencies here.  These will be installed by pip
    # when your project is installed. For an analysis of
    # "install_requires" vs pip's requirements files see:
    # https://packaging.python.org/en/latest/technical.html#install-requires-vs-requirements-files
    install_requires=['docopt', 'flake8', 'pep8'],

    include_package_data=True,
    entry_points={
        'console_scripts': [
            'cvss=cvss.cvss:main',
        ],
    },
)
