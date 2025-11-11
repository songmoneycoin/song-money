#!/bin/bash  
# exit when any command fails
set -e

coinpath=$1

echo "compiling coin qt wallet from provided coin source directory $coinpath"

cd $coinpath

echo "stripping out problematic path"

PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') # strip out problematic Windows %PATH% imported var

cd depends

make HOST=x86_64-w64-mingw32

echo 'entering into main directory..'

cd ..

echo 'executing autogen.sh script..'

./autogen.sh # not required when building from tarball

echo "setting config parameter before compiling qt wallet"

#CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/

CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --disable-hardening --prefix=`pwd`/depends/x86_64-w64-mingw32

echo "Compiling main qt wallet source..."

make
