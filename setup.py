from setuptools import setup

setup(
	name='keepass-kdf-analysis',
	version='1.0',
	packages=['keepass-kdf-analysis'],
	url='https://github.com/subject-1407/keepass-kdf-analysis',
	license='MIT License',
	author='subject',
	author_email='subject@threepixels.de',
	description='Analysis tool for KeePass 2 databases.',
	install_requires = [
		'pycryptodome>=3.18.0',
	],
	python_requires = ">=3.8"
)
