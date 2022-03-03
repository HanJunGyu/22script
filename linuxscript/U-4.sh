#!/bin/bash

 

. function.sh

 

BAR

CODE [U-04] 패스워드 파일 보호

cat << EOF >> $RESULT

[양호]: 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우

[취약]: 쉐도우 패스워드를 사용하지 않고, 패스워드를 암호화하여 저장하지 않는 경우

EOF

BAR

 

FILE1=/etc/passwd

FILE2=/etc/shadow

 

if [ -f $FILE1 -a -f $FILE2 ] ; then

OK 쉐도우 패스워드를 사용하며, 패스워드가 암호화되어 있습니다.

else

WARN 쉘도우 패스워드 파일을 사용하지 않습니다.

fi

 

cat $RESULT

echo; echo
