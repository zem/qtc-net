#!/bin/bash

TARGET=www/pod
rm -r $TARGET
mkdir $TARGET
cd lib
find qtc -name "*.pm" | (
	while read file
	do
		modname=`echo ${file%.pm} | sed -e 's?/?::?g'` 
		pod2html $file > ../${TARGET}/${modname}.html
	done
)
