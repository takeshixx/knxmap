import sys
from setuptools import setup

install_require = []

if sys.version_info.major < 3:
    print('Python 2 is not supported')
    sys.exit(1)
elif sys.version_info.major > 2 and \
                sys.version_info.minor < 4:
    print('Python 3.4 or newer is required')
    sys.exit(1)

setup(name='KNXmap',
      version='0.10.0',
      packages=['knxmap',
                'knxmap.bus',
                'knxmap.usb',
                'knxmap.data',
                'knxmap.messages'],
      entry_points={
          'console_scripts': ['knxmap=knxmap.main:main']},
      install_requires=install_require,
      url='https://github.com/takeshixx/knxmap',
      license='GNU GPLv3',
      author='takeshix',
      author_email='knxmap@adversec.com',
      description='KNXnet/IP network and bus mapper')
