from setuptools import setup


setup(
    name='Sina',
    version='0.1',
    url='http://github.com/douban/sina',
    license='New BSD',
    author='xutao',
    author_email='xutao@douban.com',
    description='A GIT Smart HTTP Server WSGI Implementation.',
    long_description=__doc__,
    packages=['sina'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
)
