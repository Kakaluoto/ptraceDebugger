#!/bin/bash

if [ $# == 0 ]		# $# means the number of parameters
then
    echo 'current ASLR level:'
    cat /proc/sys/kernel/randomize_va_space
    echo 'use option "-h" for help.'
elif [ $# == 1 ]
then
    if [ $1 == 0 ]
    then 
        sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
        echo "change ASLR level to:"
        cat /proc/sys/kernel/randomize_va_space
    elif [ $1 == 1 ]
    then
        sudo bash -c "echo 1 > /proc/sys/kernel/randomize_va_space"
        echo "change ASLR level to:"
        cat /proc/sys/kernel/randomize_va_space
    elif [ $1 == 2 ]
    then
        sudo bash -c "echo 2 > /proc/sys/kernel/randomize_va_space"
        echo "change ASLR level to:"
        cat /proc/sys/kernel/randomize_va_space
    elif [ $1 == "-h" ]
    then
        echo ""
        echo "### bash ./ASLR"
        echo "-->   show current ASLR level."
        echo ""
        echo "### bash ./ASLR -h"
        echo "-->   show help info."
        echo ""
        echo "### bash ./ASLR 0"
        echo "-->   change ASLR level to 0."
        echo ""
        echo "### bash ./ASLR 1"
        echo "-->   change ASLR level to 1."
        echo ""
        echo "### bash ./ASLR 2"
        echo "-->   change ASLR level to 2."
        echo ""
    else
        echo "syntax error!"
        echo 'use option "-h" for help.'
    fi
else
    echo "syntax error!"
    echo 'use option "-h" for help.'
fi
