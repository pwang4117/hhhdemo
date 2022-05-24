#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source $THIS_DIR/../env.sh

function exec() {
    echo "$@" | $CLI_PATH | grep 'RuntimeCmd: .' | sed -e 's/^RuntimeCmd: //'
}

echo
echo "### Config registers ###"
exec "register_read process_hhh.cfg_threshold_reg 0"
exec "register_read process_hhh.cfg_prefixes_reg 0"
exec "register_read process_hhh.cfg_prefixes_reg 1"
exec "register_read process_hhh.cfg_timeouts_reg 0"
exec "register_read process_hhh.cfg_timeouts_reg 1"

#echo
#echo "### Data registers ###"
#for index in {0..64}; do
#    exec "register_read process_hhh.vld_timestamp_reg $index"
#    exec "register_read process_hhh.cnt_timestamp_reg $index"
#    exec "register_read process_hhh.cnt_value_reg $index"
#done
