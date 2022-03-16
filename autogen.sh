#!/bin/sh

# run this script first if the source was checked out from Github.

autoreconf -f
automake --add-missing --copy
autoreconf -f

