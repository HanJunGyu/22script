#!/bin/bash

 

. function.sh

TMP1=`SCRIPTNAME`.log

> $TMP1

 

BAR

CODE [U-05] root 이외의 UID가 '0' 금지

cat << EOF >> $RESULT

[양호]: root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우

[취약]: root 계정과 동일한 UID를 갖는 계정이 존재하는 경우

EOF

BAR

 

FILE1=/etc/passwd

 

echo "[root 사용자와 동일한 UID를 갖는 계정들]" > $TMP1

awk -F: '$3 == "0" {print $1 " = 0"}' $FILE1 >> $TMP1

NUM=`cat $TMP1 | wc -l`

if [ $NUM -ge 3 ] ; then

WARN root 계정과 동일한 UID를 갖는 계정이 존재합니다.

INFO $TMP1 파일을 점검합니다.

else

OK root 계정과 동일한 UID를 갖는 계정은 없습니다.

fi

 

cat $RESULT

echo; echo
