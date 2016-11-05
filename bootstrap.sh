#!/bin/bash

autoreconf
libtoolize --force --copy
aclocal
autoconf
automake --add-missing
./configure
make
