#!/bin/bash

. function.sh
TMP1=`SCRIPTNAME`.log
> $TMP1
> /tmp/tmp1
> /tmp/tmp2
> /tmp/tmp3

# /tmp/grouplist 사용자가 속한 전체 그룹
#root
#adm
#bin ...

#for i in `cat /etc/passwd | awk -F: '{print $1}'`
for i in $(cat /etc/group | awk -F: '{print $1}')
do
	#id -Gn $i | grep -w root
	CNT=0
	MAX=`wc -l < /etc/passwd`
	for j in `cat /etc/passwd | awk -F: '{print $1}'`
	do
		id -Gn $j | grep -q -w $i
		if [ $? -eq 0 ] ; then # 정상적으로 수행(찾은경우) 되면
			echo "Found : $j"
			continue 2 #2 반복구문 위의 위, 즉 처음 시작 반복문으로 돌아가란 뜻
		else
			CNT=`expr $CNT + 1` # passwd 맥스값은 라인 카운트=전체 카운트 갯수
			if [ $CNT -ge $MAX ] ; then
				echo $i >> /tmp/tmp3
			fi
		fi
	done
done

cat /tmp/tmp3


=======================================================================================


#!/bin/bash


> /tmp/tmp1
> /tmp/tmp2
> /tmp/tmp3

for i in `cat /etc/passwd | awk -F: '{print $1}'`
do
	#echo $i
	for z in `id -Gn $i`
	do
		echo $z >> /tmp/tmp1
	done
done
sort -u /tmp/tmp1 > /tmp/tmp2


for j in `cat /etc/group | awk -F: '{print $1}'`
do
	if ! grep -q -w $j /tmp/tmp2 ; then #/tmp/tmp1에는 사용자가 속한 전체 이름이 들어있는데
		# echo $j     					# 매칭이 안되는걸 출력하라고!
	    grep '$j' /etc/group >> /tmp/tmp3 # j는 조건을 갖췄을때의 그룹의 이름
	fi
done


# 중복제거 명령어 uniq 사용. uniq은 sort 작업을 꼭 먼저 해줘야 한다! 
# 먼저 중복 있는지 확인! grep mail | /tmp/tmp1
# sort -u 옵션은 중복 되는걸 하나로 표기해줌!
# sort /tmp/tmp1 | uniq -d # -d = duplecate  / 중복 확인 커맨드
# sort -u /tmp/tmp1 > /tmp/tmp2
