#!/bin/sh

VERSION=15.1.0
INITIAL_ENV=bootstrap
INSTALL_URL=https://pypi.python.org/packages/d4/0c/9840c08189e030873387a73b90ada981885010dd9aea134d6de30cd24cb8/virtualenv-15.1.0.tar.gz#md5=44e19f4134906fe2d75124427dc9b716
PYTHON=`which python`

curl -o virtualenv-$VERSION.tar.gz $INSTALL_URL 
tar xzf virtualenv-$VERSION.tar.gz
$PYTHON virtualenv-$VERSION/virtualenv.py $INITIAL_ENV
$INITIAL_ENV/bin/pip install virtualenv-$VERSION.tar.gz
$INITIAL_ENV/bin/virtualenv -p python3.6 env
rm -rf bootstrap $INITIAL_ENV/bin/virtualenv py-env1 virtualenv-$VERSION.tar.gz

source env/bin/activate
python setup.py install
