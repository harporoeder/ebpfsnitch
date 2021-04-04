from setuptools import setup, find_packages

setup(
   name='ebpfsnitch',
   version='0.2.0',
   description='UI for eBPFSnitch',
   author='Harpo Roeder',
   author_email='roederharpo@protonmail.ch',
   packages=find_packages(),
   include_package_data=True,
   install_requires=['PyQt5'],
   scripts=['bin/ebpfsnitch']
)
