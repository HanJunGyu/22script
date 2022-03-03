
#!/bin/bash

 

. function.sh

TMP1=`SCRIPTNAME`.log

> $TMP1

TMP2=$(mktemp)

 

BAR

CODE [U-07] 패스워드 최소 길이 설정

cat << EOF >> $RESULT

[양호]: 암호의 최소 길이가 8글자 이상

[취약]: 암호의 최소 길이가 7글자 미만

EOF

BAR

 

LOGINDEFSFILE=/etc/login.defs \

grep PASS_MIN_LEN $LOGINDEFSFILE | egrep -v '^#|^$' >> $TMP2

NUM=$(cat $TMP2 | awk '{print $2}')

if [ $NUM -ge 7 ] ; then

OK 암호의 최소 길이가 8글자 이상입니다.

else

WARN 암호의 최소 길이가 7글자 이하입니다.

INFO $TMP1 파일을 참고하십시오.

echo "=============================================================" >> $TMP1

echo "1. /etc/login.defs 파일 내용 중 PASS_MIN_LEN 설정 부분입니다." >> $TMP1

echo "" >> $TMP1

cat $TMP2 >> $TMP1

echo "=============================================================" >> $TMP1

fi

 

cat $RESULT

echo ; echo
