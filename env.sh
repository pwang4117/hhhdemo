THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# vvvvvvvvvv EDIT THIS vvvvvvvvvv

BMV2_PATH=$THIS_DIR/../../bmv2
# e.g. BMV2_PATH=$THIS_DIR/../bmv2

P4C_PATH=$THIS_DIR/../../p4c
# e.g P4C_BM_PATH=$THIS_DIR/../p4c

P4C_BM_PATH=$THIS_DIR/../../p4c-bmv2
# e.g P4C_BM_PATH=$THIS_DIR/../p4c-bmv2

# ^^^^^^^^^^ EDIT THIS ^^^^^^^^^^

# Path to new P4C compiler (P4_16 compliant)
P4C=$P4C_PATH/build/p4c-bm2-ss

# Path to old P4C-BM compiler
P4C_BM=$P4C_BM_PATH/p4c_bm/__main__.py

# Path to single switch Mininet script
SSMN=$THIS_DIR/tools/mininet/single_switch_mininet.py

# Path to BMv2 of simple switch
SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

# Path to BMv2 CLI interface
CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py

# Path to nanomsg client
NMSGC_PATH=$BMV2_PATH/tools/nanomsg_client.py

# Path to BMv2 Python interface
export PYTHONPATH=$PYTHONPATH:$BMV2_PATH/tools/
