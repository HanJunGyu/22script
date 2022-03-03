#!/bin/bash

. function.sh
TMP1=`SCRIPTNAME`.log
> $TMP1
TMP2=$(mktemp)
TMP3=$(mktemp)

>$TMP2
>$TMP3


BAR
CODE "[U-18] SUID, SGID, Sticky bit 설정 파일 점검"
cat << EOF >> $RESULT
양호: 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우
취약: 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있는 경우
EOF
BAR

echo "[U-18] Checking.... Please wait...."

NOTSETUIDFILE=nosetuid.txt
cat $NOTSETUIDFILE | while read i
do
	if [ -e $i ] ; then # -e 파일이 존재하면 참
		FILEPERM=$(ls -l $i | awk '{print $1}' | grep 's')
		if  [ ! -z $FILEPERM ] ; then # 문자열의 길이가 0이면 참
			echo "[+] $i $FILEPERM" >> $TMP2
		else
			echo "[*] $i" >> $TMP2
		fi
	else
		echo "[-] $i" >> $TMP2
	fi
done

find / -xdev -user root -type f \( -perm -4000 -o -perm -2000 \) -ls \
	| awk '{print $3, $11}' 2>/dev/null > $TMP3

if grep -q '[+]' $TMP2; then
	WARN 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있습니다.
	INFO $TMP1 파일의 내용을 참고 하십시오.
	cat <<- EOF >> $TMP1
==============================================================
1. 다음 내용은 주요 파일의 권한에 SUID/SGID에 대한 설정 여부입니다.
* [+] 파일이 존재하고, SUID 및 SGID 설정된 경우
* [*] 파일이 존재하지만 SUID 및 SGID 설정되지 않은 경우
* [-] 파일이 존재하지 않는 경우

$(cat $TMP2)

2. 다음은 시스템내의 SUID/SGID 전체 파일 목록입니다.

$(cat $TMP3)
==============================================================
	EOF
else
	OK 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않습니다.
fi

cat $RESULT
echo ; echo
