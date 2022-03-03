#!/bin/bash

FILE=/root/bin/bash_history
TMP1=/tmp/tmp1
TMP2=/tmp/tmp2
> $TMP1
> $TMP2

grep -n '^#' $FILE | awk -F: '{print $1}' > $TMP1
LastLine=$(tail -1 $TMP1) ; echo $LastLine
sed -i '$d' $TMP1 # 마지막 줄을 지워라


for N in $(cat $TMP1)
do
	if [ $N -ne $LastLine ] ; then
		sed -n "$N,/^#/p" $FILE | sed '$d' > $TMP2 
                    #1번부터 다음 번째 #(번호)까지 프린트해라. 그 값의 마지막 값을 지워라.
		TIME=$(sed -n '1p' $TMP2 | cut -c2-) # 첫 번째 라인을 출력
		echo "------- $(date -d "@${TIME}") --------" 	
		sed '1d' $TMP2 #첫 번째 라인을 삭제하고 출력
	else
		sed -n "$N,\$p" $FILE > $TMP2 #앞에건 변수 뒤에건 아님
        TIME=$(sed -n '1p' $TMP2 | cut -c2-)
        echo "------- $(date -d "@${TIME}") -------"
        sed -n '2,$p' $TMP2

	fi
done
