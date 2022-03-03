
#!/bin/bash



. function.sh



TMP1=$(SCRIPTNAME).log

> $TMP1



BAR

CODE '[U-24] SUID, SGID, Sticky bit 설정 파일 점검'

cat << EOF >> $RESULT

[양호]: 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우

[취약]: 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있는 경우

EOF

BAR



FILE1=nosetuid.txt

TMP2=/tmp/tmp2 && >/tmp/tmp2

TMP3=/tmp/tmp3 && >/tmp/tmp3

cat $FILE1 | while read LINE

do

if [ -f $LINE ] ; then

ls -lL $LINE | awk '{print $1}' | grep -i 's' >$TMP3 2>&1

if [ $? -eq 0 ] ; then

echo "[`cat $TMP3`] : $LINE" >> $TMP2

fi

fi

done



if [ -s $TMP2 ] ; then

WARN 주요 파일의 권한에 SUID, SGID가 존재합니다.

INFO $TMP1 파일의 정보를 확인합니다.

cat << EOF >> $TMP1

다음은 SUID,SGID가 제거 되어 있어야 하는 파일 목록 입니다.

============================================

$(cat $FILE1)





다음은 SUID,SGID 점검한 결과입니다.

============================================

$(cat $TMP2)

EOF

else

OK 주요 파일의 권한에 SUID, SGID가 존재하지 않습니다.

fi



cat $RESULT

echo ; echo
