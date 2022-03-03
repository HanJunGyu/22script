#!/bin/bash

 

FILE1=nosetuid.txt

FILE3=tmp3.txt

 

cat << EOF

================================================

[ OK ] : SetUID 비트가 존재하지 않음. 안전함

[ WARN ] : 불필요한 SetUID 비트가 존재함.

================================================

 

EOF

 

cat nosetuid.txt | while read FILE2

do

if [ -e $FILE2 ] ; then

ls -l $FILE2 | awk '{print $1}' | grep -i 's' > $FILE3

if [ $? -eq 0 ] ; then

echo "[ WARN ] : $FILE2 (`cat $FILE3`)"

else

echo "[ OK ] : $FILE2"

fi

else

echo "[ file not found ] : $FILE2"

fi

done
