#!/usr/bin/env python2

import sys
import nnpy
import struct
import argparse
import bmpy_utils as utils

parser = argparse.ArgumentParser(description='HHH digest controller')
parser.add_argument('--thrift-port', help='Thrift server port for switch control',
                    type=int, action="store", default=9090)
parser.add_argument('--thrift-ip', help='Thrift server IP address for switch control',
                    type=str, action="store", default='localhost')

args = parser.parse_args()

##
#  Header message class
##
class HDRMsg(object):
    def __init__(self, client, msg):
        self.struct = struct.Struct("<4siiiQI4s")
        self.client = client
        self.msg = msg
        self.extract()

    def extract(self):
        (_, self.switch_id, self.cxt_id, self.list_id, self.buffer_id, self.num_samples, _) \
            = self.struct.unpack_from(self.msg)

    def data(self):
        return self.msg[self.struct.size:]

    def confirm(self):
        self.client.bm_learning_ack_buffer(self.cxt_id, self.list_id, self.buffer_id)

    def __str__(self):
        return "switch_id: %d, cxt_id: %d, list_id: %d, buffer_id: %u, num_samples: %u" % \
            (self.switch_id, self.cxt_id, self.list_id, self.buffer_id, self.num_samples)

##
#  HHH message class
##
class HHHMsg(object):
    def __init__(self, msg):
        self.struct = struct.Struct("!IIHI4sb")
        self.msg = msg
        self.extract()

    def extract(self):
        (self.value, self.vector, htimestamp, ltimestamp, self.prefix_found, self.prefix_len) = self.struct.unpack_from(self.msg)
        self.timestamp = ltimestamp | htimestamp << 32
        self.hhh = (self.vector & (0x00000001 << (32-self.prefix_len))) > 0

    def data(self):
        return self.msg[self.struct.size:]        

    def __str__(self):
        return "timestamp: %u" % (self.timestamp) \
            + ", vector: 0x%08x" % (self.vector) \
            + ", hhh: %d" % (self.hhh) \
            + ", prefix_found: " + ".".join("{:d}".format(ord(c)) for c in self.prefix_found) \
            + ", prefix_len: %u" % (self.prefix_len) \
            + ", value: %u" % (self.value)

##
#  HHH message class
##
def main():
    client = utils.thrift_connect_standard(args.thrift_ip, args.thrift_port)
    swinfo = client.bm_mgmt_get_info()
    socket = swinfo.notifications_socket

    sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
    sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, 'LEA')
    sub.connect(socket)

    while True:
        msg = sub.recv()

        h = HDRMsg(client, msg)
        d = h.data()
        print h

        for i in range(0, h.num_samples):
            m = HHHMsg(d)
            d = m.data()
            print "\t", m

        h.confirm()

if __name__ == "__main__":
    main()
