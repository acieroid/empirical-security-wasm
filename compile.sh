#!/bin/sh
python compile.py $@
result=$?
if [ $result = 0 ]; then
    echo $1 > compilation-success.txt
elif [ $result = 1 ]; then
    echo $1 > compilation-failure.txt
else
    echo $1 > compilation-disagreement.txt
fi
