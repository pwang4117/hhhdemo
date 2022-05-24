#include <core.p4>
#include <v1model.p4>

#include "includes/parser.p4"
#include "includes/deparser.p4"

/*/
|*| User constants
/*/

// Predefined threshold for HHH detection
#define HHH_THRESHOLD 10000

// Number of stages
#define HHH_TABCOUNT 32

// Active timeout (10s)
#define HHH_ATIMEOUT 48w10000000

// Inactive timeout (1min)
#define HHH_ITIMEOUT 48w60000000

// First prefix length
#define HHH_FIRSTLEN 16

// Last prefix length
#define HHH_LASTLEN 32

// Lookup table size in each stage
#define HHH_TABSIZE 32w8192

/*/
|*| Computed constants
/*/

// Size of registers
#define HHH_REGSIZE HHH_TABSIZE*HHH_TABCOUNT+1

// Bitvector length
#define HHH_VECSIZE 32

/*/
|*| HHH metadata type
/*/
struct hhh_metadata_t {
    bit<HHH_VECSIZE> vector;  // bitvector of valid stages

    bit<32> threshold;  // threshold configuration
    bit<48> atimeout;   // active timeout configuration
    bit<48> itimeout;   // inactive timeout configuration
    bit<8>  firstlen;   // first prefix length configuration
    bit<8>  lastlen;    // last prefix length configuration

    bit<32> hash_00_idx;  // computed index for stage 00
    bit<32> hash_01_idx;  // computed index for stage 01
    bit<32> hash_02_idx;  // computed index for stage 02
    bit<32> hash_03_idx;  // computed index for stage 03
    bit<32> hash_04_idx;  // computed index for stage 04
    bit<32> hash_05_idx;  // computed index for stage 05
    bit<32> hash_06_idx;  // computed index for stage 06
    bit<32> hash_07_idx;  // computed index for stage 07
    bit<32> hash_08_idx;  // computed index for stage 08
    bit<32> hash_09_idx;  // computed index for stage 09
    bit<32> hash_10_idx;  // computed index for stage 10
    bit<32> hash_11_idx;  // computed index for stage 11
    bit<32> hash_12_idx;  // computed index for stage 12
    bit<32> hash_13_idx;  // computed index for stage 13
    bit<32> hash_14_idx;  // computed index for stage 14
    bit<32> hash_15_idx;  // computed index for stage 15
    bit<32> hash_16_idx;  // computed index for stage 16
    bit<32> hash_17_idx;  // computed index for stage 17
    bit<32> hash_18_idx;  // computed index for stage 18
    bit<32> hash_19_idx;  // computed index for stage 19
    bit<32> hash_20_idx;  // computed index for stage 20
    bit<32> hash_21_idx;  // computed index for stage 21
    bit<32> hash_22_idx;  // computed index for stage 22
    bit<32> hash_23_idx;  // computed index for stage 23
    bit<32> hash_24_idx;  // computed index for stage 24
    bit<32> hash_25_idx;  // computed index for stage 25
    bit<32> hash_26_idx;  // computed index for stage 26
    bit<32> hash_27_idx;  // computed index for stage 27
    bit<32> hash_28_idx;  // computed index for stage 28
    bit<32> hash_29_idx;  // computed index for stage 29
    bit<32> hash_30_idx;  // computed index for stage 30
    bit<32> hash_31_idx;  // computed index for stage 31
    bit<32> hash_32_idx;  // computed index for stage 32

    bit<32> curr_prf;  // current (found) prefix
    bit<32> curr_val;  // current (found) prefix value
    bit<32> next_prf;  // next prefix
    bit<32> next_val;  // next prefix value

    bit<8>  prev_len;  // parent prefix length
    bit<32> prev_idx;  // parent prefix index
    bit<8>  curr_len;  // current (found) prefix length
    bit<32> curr_idx;  // current (found) prefix index
    bit<8>  next_len;  // next prefix length
    bit<32> next_idx;  // next prefix index

    bit<1> timeout;  // did current (found) prefix expire?

    bit<32> digestval; // WORKAROUD, temp field
}

/*/
|*| HHH digest type
/*/
struct hhh_digest_t {
    bit<32> value;
    bit<32> vector;
    bit<48> timestamp;
    bit<32> prefix_found;
    bit<8>  prefix_len;
}

/*/
|*| HHH processing control block
/*/
control process_hhh(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // HHH metadata instance
    hhh_metadata_t hhh;

    // HHH memory registers (validity timestamp, counters)
    register<bit<48>>(HHH_REGSIZE) vld_timestamp_reg;
    register<bit<48>>(HHH_REGSIZE) cnt_timestamp_reg;
    register<bit<32>>(HHH_REGSIZE) cnt_value_reg;

    // HHH config registers (perfixes, timeouts, threshold)
    register<bit<8>>(2) cfg_prefixes_reg;
    register<bit<48>>(2) cfg_timeouts_reg;
    register<bit<32>>(1) cfg_threshold_reg;

    // HHH init action
    @name("init") action init() {
        bit<48> timestamp;

        // Read configuration registers, set default values
        cfg_threshold_reg.read(hhh.threshold, 0); if (hhh.threshold == 0) { hhh.threshold = HHH_THRESHOLD; }
        cfg_timeouts_reg.read(hhh.atimeout, 0); if (hhh.atimeout == 0) { hhh.atimeout = HHH_ATIMEOUT; }
        cfg_timeouts_reg.read(hhh.itimeout, 1); if (hhh.itimeout == 0) { hhh.itimeout = HHH_ITIMEOUT; }
        cfg_prefixes_reg.read(hhh.firstlen, 0); if (hhh.firstlen == 0) { hhh.firstlen = HHH_FIRSTLEN; }
        cfg_prefixes_reg.read(hhh.lastlen, 1); if (hhh.lastlen == 0) { hhh.lastlen = HHH_LASTLEN; }

        // WORKAROUD, ensure that timestamp has minimal value
        meta.intrinsic.ingress_global_timestamp = meta.intrinsic.ingress_global_timestamp + hhh.itimeout;

        // Compute hashes for different prefix lenghts
        hhh.hash_00_idx = HHH_REGSIZE-1;
        hash(hhh.hash_01_idx, (0x00000001 < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  0*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0x80000000) >> 31 }, HHH_TABSIZE);
        hash(hhh.hash_02_idx, (0x00000003 < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  1*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xC0000000) >> 30 }, HHH_TABSIZE);
        hash(hhh.hash_03_idx, (0x00000007 < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  2*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xE0000000) >> 29 }, HHH_TABSIZE);
        hash(hhh.hash_04_idx, (0x0000000F < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  3*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xF0000000) >> 28 }, HHH_TABSIZE);
        hash(hhh.hash_05_idx, (0x0000001F < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  4*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xF8000000) >> 27 }, HHH_TABSIZE);
        hash(hhh.hash_06_idx, (0x0000003F < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  5*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFC000000) >> 26 }, HHH_TABSIZE);
        hash(hhh.hash_07_idx, (0x0000007F < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  6*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFE000000) >> 25 }, HHH_TABSIZE);
        hash(hhh.hash_08_idx, (0x000000FF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  7*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFF000000) >> 24 }, HHH_TABSIZE);
        hash(hhh.hash_09_idx, (0x000001FF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  8*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFF800000) >> 23 }, HHH_TABSIZE);
        hash(hhh.hash_10_idx, (0x000003FF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32,  9*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFC00000) >> 22 }, HHH_TABSIZE);
        hash(hhh.hash_11_idx, (0x000007FF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 10*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFE00000) >> 21 }, HHH_TABSIZE);
        hash(hhh.hash_12_idx, (0x00000FFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 11*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFF00000) >> 20 }, HHH_TABSIZE);
        hash(hhh.hash_13_idx, (0x00001FFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 12*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFF80000) >> 19 }, HHH_TABSIZE);
        hash(hhh.hash_14_idx, (0x00003FFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 13*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFC0000) >> 18 }, HHH_TABSIZE);
        hash(hhh.hash_15_idx, (0x00007FFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 14*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFE0000) >> 17 }, HHH_TABSIZE);
        hash(hhh.hash_16_idx, (0x0000FFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 15*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFF0000) >> 16 }, HHH_TABSIZE);
        hash(hhh.hash_17_idx, (0x0001FFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 16*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFF8000) >> 15 }, HHH_TABSIZE);
        hash(hhh.hash_18_idx, (0x0003FFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 17*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFC000) >> 14 }, HHH_TABSIZE);
        hash(hhh.hash_19_idx, (0x0007FFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 18*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFE000) >> 13 }, HHH_TABSIZE);
        hash(hhh.hash_20_idx, (0x000FFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 19*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFF000) >> 12 }, HHH_TABSIZE);
        hash(hhh.hash_21_idx, (0x001FFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 20*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFF800) >> 11 }, HHH_TABSIZE);
        hash(hhh.hash_22_idx, (0x003FFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 21*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFC00) >> 10 }, HHH_TABSIZE);
        hash(hhh.hash_23_idx, (0x007FFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 22*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFE00) >>  9 }, HHH_TABSIZE);
        hash(hhh.hash_24_idx, (0x00FFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 23*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFF00) >>  8 }, HHH_TABSIZE);
        hash(hhh.hash_25_idx, (0x01FFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 24*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFF80) >>  7 }, HHH_TABSIZE);
        hash(hhh.hash_26_idx, (0x03FFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 25*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFFC0) >>  6 }, HHH_TABSIZE);
        hash(hhh.hash_27_idx, (0x07FFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 26*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFFE0) >>  5 }, HHH_TABSIZE);
        hash(hhh.hash_28_idx, (0x0FFFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 27*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFFF0) >>  4 }, HHH_TABSIZE);
        hash(hhh.hash_29_idx, (0x1FFFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 28*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFFF8) >>  3 }, HHH_TABSIZE);
        hash(hhh.hash_30_idx, (0x3FFFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 29*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFFFC) >>  2 }, HHH_TABSIZE);
        hash(hhh.hash_31_idx, (0x7FFFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 30*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFFFE) >>  1 }, HHH_TABSIZE);
        hash(hhh.hash_32_idx, (0xFFFFFFFF < HHH_TABSIZE) ? HashAlgorithm.identity : HashAlgorithm.crc32, 31*HHH_TABSIZE, { (hdr.ipv4.srcAddr & 0xFFFFFFFF) >>  0 }, HHH_TABSIZE);

        // Read validity bits and construct bitvectors
        hhh.vector = 0;
        vld_timestamp_reg.read(timestamp, hhh.hash_01_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x80000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_02_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x40000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_03_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x20000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_04_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x10000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_05_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x08000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_06_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x04000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_07_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x02000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_08_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x01000000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_09_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00800000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_10_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00400000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_11_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00200000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_12_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00100000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_13_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00080000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_14_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00040000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_15_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00020000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_16_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00010000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_17_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00008000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_18_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00004000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_19_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00002000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_20_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00001000; }
        vld_timestamp_reg.read(timestamp, hhh.hash_21_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000800; }
        vld_timestamp_reg.read(timestamp, hhh.hash_22_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000400; }
        vld_timestamp_reg.read(timestamp, hhh.hash_23_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000200; }
        vld_timestamp_reg.read(timestamp, hhh.hash_24_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000100; }
        vld_timestamp_reg.read(timestamp, hhh.hash_25_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000080; }
        vld_timestamp_reg.read(timestamp, hhh.hash_26_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000040; }
        vld_timestamp_reg.read(timestamp, hhh.hash_27_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000020; }
        vld_timestamp_reg.read(timestamp, hhh.hash_28_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000010; }
        vld_timestamp_reg.read(timestamp, hhh.hash_29_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000008; }
        vld_timestamp_reg.read(timestamp, hhh.hash_30_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000004; }
        vld_timestamp_reg.read(timestamp, hhh.hash_31_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000002; }
        vld_timestamp_reg.read(timestamp, hhh.hash_32_idx); if (timestamp + hhh.itimeout > meta.intrinsic.ingress_global_timestamp) { hhh.vector = hhh.vector | 32w0x00000001; }
    }

    // HHH action read data
    @name("read_data") action read_data() {
        bit<48> curr_vld_timestamp;
        bit<48> curr_cnt_timestamp;
        bit<48> next_cnt_timestamp;

        // Read counter timestamps
        cnt_timestamp_reg.read(curr_cnt_timestamp, hhh.curr_idx);
        cnt_timestamp_reg.read(next_cnt_timestamp, hhh.next_idx);

        // Read validity timestamp
        vld_timestamp_reg.read(curr_vld_timestamp, hhh.curr_idx);

        // Read counter values
        cnt_value_reg.read(hhh.curr_val, hhh.curr_idx);
        cnt_value_reg.read(hhh.next_val, hhh.next_idx);

        // Invalidate values if necessary
        if (curr_vld_timestamp > curr_cnt_timestamp) { hhh.curr_val = 0; }
        if (curr_vld_timestamp > next_cnt_timestamp) { hhh.next_val = 0; }

        // Check timeout
        hhh.timeout = ((curr_vld_timestamp + hhh.atimeout <= meta.intrinsic.ingress_global_timestamp) ? 1w0b1 : 1w0b0);

        // Build prefixes
        hhh.curr_prf = hdr.ipv4.srcAddr & (((bit<32>) 0xFFFFFFFF >> (32-hhh.curr_len)) << (32-hhh.curr_len));
        hhh.next_prf = hdr.ipv4.srcAddr & (((bit<32>) 0xFFFFFFFF >> (32-hhh.next_len)) << (32-hhh.next_len));
    }

    // HHH action write data
    @name("write_data") action write_data() {

        // Write values
        cnt_value_reg.write(hhh.curr_idx, hhh.curr_val);
        cnt_value_reg.write(hhh.next_idx, hhh.next_val);

        // Write timestamps
        cnt_timestamp_reg.write(hhh.curr_idx, meta.intrinsic.ingress_global_timestamp);
        cnt_timestamp_reg.write(hhh.next_idx, meta.intrinsic.ingress_global_timestamp);
    }

    // HHH generic action to choose prefix index according the length
    @name("index") action index(out bit<32> pref_idx, bit<8> pref_len) {

        /* Unknown value */ { pref_idx = hhh.hash_00_idx; }
        if (pref_len ==  1) { pref_idx = hhh.hash_01_idx; } else
        if (pref_len ==  2) { pref_idx = hhh.hash_02_idx; } else
        if (pref_len ==  3) { pref_idx = hhh.hash_03_idx; } else
        if (pref_len ==  4) { pref_idx = hhh.hash_04_idx; } else
        if (pref_len ==  5) { pref_idx = hhh.hash_05_idx; } else
        if (pref_len ==  6) { pref_idx = hhh.hash_06_idx; } else
        if (pref_len ==  7) { pref_idx = hhh.hash_07_idx; } else
        if (pref_len ==  8) { pref_idx = hhh.hash_08_idx; } else
        if (pref_len ==  9) { pref_idx = hhh.hash_09_idx; } else
        if (pref_len == 10) { pref_idx = hhh.hash_10_idx; }
        if (pref_len == 11) { pref_idx = hhh.hash_11_idx; } else
        if (pref_len == 12) { pref_idx = hhh.hash_12_idx; } else
        if (pref_len == 13) { pref_idx = hhh.hash_13_idx; } else
        if (pref_len == 14) { pref_idx = hhh.hash_14_idx; } else
        if (pref_len == 15) { pref_idx = hhh.hash_15_idx; } else
        if (pref_len == 16) { pref_idx = hhh.hash_16_idx; } else
        if (pref_len == 17) { pref_idx = hhh.hash_17_idx; } else
        if (pref_len == 18) { pref_idx = hhh.hash_18_idx; } else
        if (pref_len == 19) { pref_idx = hhh.hash_19_idx; } else
        if (pref_len == 20) { pref_idx = hhh.hash_20_idx; }
        if (pref_len == 21) { pref_idx = hhh.hash_21_idx; } else
        if (pref_len == 22) { pref_idx = hhh.hash_22_idx; } else
        if (pref_len == 23) { pref_idx = hhh.hash_23_idx; } else
        if (pref_len == 24) { pref_idx = hhh.hash_24_idx; } else
        if (pref_len == 25) { pref_idx = hhh.hash_25_idx; } else
        if (pref_len == 26) { pref_idx = hhh.hash_26_idx; } else
        if (pref_len == 27) { pref_idx = hhh.hash_27_idx; } else
        if (pref_len == 28) { pref_idx = hhh.hash_28_idx; } else
        if (pref_len == 29) { pref_idx = hhh.hash_29_idx; } else
        if (pref_len == 30) { pref_idx = hhh.hash_30_idx; }
        if (pref_len == 31) { pref_idx = hhh.hash_31_idx; } else
        if (pref_len == 32) { pref_idx = hhh.hash_32_idx; }
    }

    // HHH generic found action
    @name("found") action found(bit<8> prev_len, bit<8> curr_len, bit<8> next_len) {
        hhh.prev_len = prev_len;
        hhh.curr_len = curr_len;
        hhh.next_len = next_len;
        if (hhh.next_len == 0) hhh.next_len = hhh.firstlen;
        if (hhh.curr_len == hhh.firstlen) hhh.prev_len = 0;
        if (hhh.curr_len == hhh.lastlen) hhh.next_len = hhh.lastlen;
        index(hhh.prev_idx, hhh.prev_len);
        index(hhh.curr_idx, hhh.curr_len);
        index(hhh.next_idx, hhh.next_len);
        read_data();
    }

    // HHH keep rule action
    @name("keep") action keep() {

        // Inform controller
        hhh.digestval = hhh.curr_val;
        digest<hhh_digest_t>(0, {
            hhh.digestval,
            hhh.vector,
            meta.intrinsic.ingress_global_timestamp,
            hhh.curr_prf,
            hhh.curr_len
        });

        // Update counters
        hhh.curr_val = standard_metadata.packet_length;
        hhh.next_val = standard_metadata.packet_length;
        write_data();

        // Refresh timestamp
        vld_timestamp_reg.write(hhh.curr_idx, meta.intrinsic.ingress_global_timestamp);
    }

    // HHH collapse rule action
    @name("collapse") action collapse() {

        // Update counters
        hhh.curr_val = standard_metadata.packet_length;
        hhh.next_val = standard_metadata.packet_length;
        write_data();

        // Invalidate current prefix timestamp
        vld_timestamp_reg.write(hhh.curr_idx, 0);

        // Refresh previous prefix timestamp
        vld_timestamp_reg.write(hhh.prev_idx, meta.intrinsic.ingress_global_timestamp);
    }

    // HHH expand rule action
    @name("expand") action expand() {

        // Inform controller
        hhh.digestval = hhh.curr_val;
        digest<hhh_digest_t>(0, {
            hhh.digestval,
            hhh.vector,
            meta.intrinsic.ingress_global_timestamp,
            hhh.next_prf,
            hhh.next_len
        });

        // Update counters
        hhh.curr_val = hhh.curr_val - hhh.next_val;
        hhh.next_val = 0;
        write_data();

        // Validate next prefix timestamp
        vld_timestamp_reg.write(hhh.next_idx, meta.intrinsic.ingress_global_timestamp);
    }

    // HHH update action
    @name("update") action update() {

        // Update counters
        hhh.curr_val = hhh.curr_val + standard_metadata.packet_length;
        hhh.next_val = hhh.next_val + standard_metadata.packet_length;
        write_data();
    }

    // HHH init table
    @name("init_tab") table init_tab {
        actions = { init; }
        default_action = init();
    }

    // HHH lookup table
    @name("lookup_tab") table lookup_tab {
        actions = { found; }
        default_action = found(0, 0, 0);
        key = { hhh.vector: ternary; }
    }

    // HHH keep rule table
    @name("keep_tab") table keep_tab {
        actions = { keep; }
        default_action = keep;
    }

    // HHH collapse rule table
    @name("collapse_tab") table collapse_tab {
        actions = { collapse; }
        default_action = collapse;
    }

    // HHH expand rule table
    @name("expand_tab") table expand_tab {
        actions = { expand; }
        default_action = expand;
    }

    // HHH update table
    @name("update_tab") table update_tab {
        actions = { update; }
        default_action = update();
    }

    apply {
        // Init phase:
        //  -> compute hashes, building bit vectors
        init_tab.apply();

        // Lookup phase:
        //  -> searching for prefix, reading counter values
        lookup_tab.apply();

        // Rule timeout?
        if (hhh.timeout == 1) {
            // Keep rule?
            if (hhh.curr_val >= hhh.threshold && hhh.curr_len != 0) {
                keep_tab.apply();
            // Collapse rule?
            } else {
                collapse_tab.apply();
            }
        // Expand rule?
        } else if (hhh.next_val + standard_metadata.packet_length >= hhh.threshold && hhh.curr_len != hhh.lastlen) {
            expand_tab.apply();
        // Basic update?
        } else {
            update_tab.apply();
        }
    }
}

/*/
|*| Ingress control block
/*/
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_hhh") process_hhh() process_hhh_0;

    apply {
        // Process HHH if IP header valid
        if (hdr.ipv4.isValid()) {   // TODO: IPv6 support?!
            process_hhh_0.apply(hdr, meta, standard_metadata);
        }
    }
}

/*/
|*| Egress control block
/*/
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

/*/
|*| Switch package instantiation
/*/
V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
