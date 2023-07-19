[![Tests](https://github.com//ckanext-sse/workflows/Tests/badge.svg?branch=main)](https://github.com//ckanext-sse/actions)

# ckanext-sse

**TODO:** Put a description of your extension here:  What does it do? What features does it have? Consider including some screenshots or embedding a video!

A CKAN extension for Southern Electricity Networks CKAN project. 

## Installation

**TODO:** Add any additional install steps to the list below.
   For example installing any non-Python dependencies or adding any required
   config settings.

To install ckanext-sse:

1. Activate your CKAN virtual environment, for example:

     . /usr/lib/ckan/default/bin/activate

2. Clone the source and install it on the virtualenv

    git clone https://github.com//ckanext-sse.git
    cd ckanext-sse
    pip install -e .
	pip install -r requirements.txt

3. Add `sse` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:

    sudo service nginx reload

## Developer installation

To install ckanext-sse for development, activate your CKAN virtualenv and
do:

    git clone https://github.com//ckanext-sse.git
    cd ckanext-sse
    python setup.py develop
    pip install -r dev-requirements.txt


## Tests

To run the tests, do:

    pytest --ckan-ini=test.ini
