#!/bin/bash

if [ $# -ne 1 ];then
    echo "Usage : $0 <-user01/.bash_history>"
    exit 1
fi

FILE1=$1

TMP1=/tmp/tmp1
TMP2=/tmp/tmp2
TMP3=/tmp/tmp3
> $TMP1
> $TMP2
> $TMP3

cat $FILE1 | egrep '^#' | cut -c2- > $TMP1
cat $TMP1 | while read TIME
do
    /root/bin/time.sh $TIME >> $TMP2
done

cat $FILE1 | egrep -v '^#' >> $TMP3

paste $TMP2 $TMP3
