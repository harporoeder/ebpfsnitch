from setuptools import setup, find_packages

setup(
   name='ebpfsnitch',
   version='0.1.0',
   description='UI for eBPFSnitch',
   author='Harpo Roeder',
   author_email='roederharpo@protonmail.ch',
   packages=find_packages(),
   install_requires=['PyQt5'],
   package_data={'': ['*.*']},
   data_files=[('/usr/share/icons/hicolor/64x64/apps', ['ebpfsnitch.png'])],
   scripts=['ebpfsnitch']
)
