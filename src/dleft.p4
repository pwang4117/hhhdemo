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

#define HASH_ENTRY_SIZE 66

// Lookup table size in each stage // TODO update tabsize for new hash entry
#define HHH_TABSIZE 32w8192 

/*/
|*| Computed constants
/*/

// Size of registers
#define HHH_REGSIZE HHH_TABSIZE*HHH_TABCOUNT+1

// Bitvector length
#define HHH_VECSIZE 32

// extend ip to 33 bits
#define EXTENDER 0x100000000

/*/
|*| HHH metadata type
/*/
struct hhh_metadata_t {
    bit<HHH_VECSIZE> vector;  // bitvector of valid stages

    bit<HASH_ENTRY_SIZE> new_hash_entry;

    bit<33> cur_prefix;  // 33 bit encoded matching prefix
    bit<8> cur_len; 

    bit<32> crc_idx; 
    bit<32> rand_idx; 

    bit<1> need_table_query;
    bit<32> next_hop;

    bit<4> hash_hits; // [crc_read][rand_read][crc_write][rand_write] (use to detect hits and collision

    // CRC Hash indices
    bit<32> crc_hash_00_idx;  // computed index for stage 00
    bit<32> crc_hash_01_idx;  // computed index for stage 01
    bit<32> crc_hash_02_idx;  // computed index for stage 02
    bit<32> crc_hash_03_idx;  // computed index for stage 03
    bit<32> crc_hash_04_idx;  // computed index for stage 04
    bit<32> crc_hash_05_idx;  // computed index for stage 05
    bit<32> crc_hash_06_idx;  // computed index for stage 06
    bit<32> crc_hash_07_idx;  // computed index for stage 07
    bit<32> crc_hash_08_idx;  // computed index for stage 08
    bit<32> crc_hash_09_idx;  // computed index for stage 09
    bit<32> crc_hash_10_idx;  // computed index for stage 10
    bit<32> crc_hash_11_idx;  // computed index for stage 11
    bit<32> crc_hash_12_idx;  // computed index for stage 12
    bit<32> crc_hash_13_idx;  // computed index for stage 13
    bit<32> crc_hash_14_idx;  // computed index for stage 14
    bit<32> crc_hash_15_idx;  // computed index for stage 15
    bit<32> crc_hash_16_idx;  // computed index for stage 16
    bit<32> crc_hash_17_idx;  // computed index for stage 17
    bit<32> crc_hash_18_idx;  // computed index for stage 18
    bit<32> crc_hash_19_idx;  // computed index for stage 19
    bit<32> crc_hash_20_idx;  // computed index for stage 20
    bit<32> crc_hash_21_idx;  // computed index for stage 21
    bit<32> crc_hash_22_idx;  // computed index for stage 22
    bit<32> crc_hash_23_idx;  // computed index for stage 23
    bit<32> crc_hash_24_idx;  // computed index for stage 24
    bit<32> crc_hash_25_idx;  // computed index for stage 25
    bit<32> crc_hash_26_idx;  // computed index for stage 26
    bit<32> crc_hash_27_idx;  // computed index for stage 27
    bit<32> crc_hash_28_idx;  // computed index for stage 28
    bit<32> crc_hash_29_idx;  // computed index for stage 29
    bit<32> crc_hash_30_idx;  // computed index for stage 30
    bit<32> crc_hash_31_idx;  // computed index for stage 31
    bit<32> crc_hash_32_idx;  // computed index for stage 32

    // Random Hash indices
    bit<32> rand_hash_00_idx;  // computed index for stage 00
    bit<32> rand_hash_01_idx;  // computed index for stage 01
    bit<32> rand_hash_02_idx;  // computed index for stage 02
    bit<32> rand_hash_03_idx;  // computed index for stage 03
    bit<32> rand_hash_04_idx;  // computed index for stage 04
    bit<32> rand_hash_05_idx;  // computed index for stage 05
    bit<32> rand_hash_06_idx;  // computed index for stage 06
    bit<32> rand_hash_07_idx;  // computed index for stage 07
    bit<32> rand_hash_08_idx;  // computed index for stage 08
    bit<32> rand_hash_09_idx;  // computed index for stage 09
    bit<32> rand_hash_10_idx;  // computed index for stage 10
    bit<32> rand_hash_11_idx;  // computed index for stage 11
    bit<32> rand_hash_12_idx;  // computed index for stage 12
    bit<32> rand_hash_13_idx;  // computed index for stage 13
    bit<32> rand_hash_14_idx;  // computed index for stage 14
    bit<32> rand_hash_15_idx;  // computed index for stage 15
    bit<32> rand_hash_16_idx;  // computed index for stage 16
    bit<32> rand_hash_17_idx;  // computed index for stage 17
    bit<32> rand_hash_18_idx;  // computed index for stage 18
    bit<32> rand_hash_19_idx;  // computed index for stage 19
    bit<32> rand_hash_20_idx;  // computed index for stage 20
    bit<32> rand_hash_21_idx;  // computed index for stage 21
    bit<32> rand_hash_22_idx;  // computed index for stage 22
    bit<32> rand_hash_23_idx;  // computed index for stage 23
    bit<32> rand_hash_24_idx;  // computed index for stage 24
    bit<32> rand_hash_25_idx;  // computed index for stage 25
    bit<32> rand_hash_26_idx;  // computed index for stage 26
    bit<32> rand_hash_27_idx;  // computed index for stage 27
    bit<32> rand_hash_28_idx;  // computed index for stage 28
    bit<32> rand_hash_29_idx;  // computed index for stage 29
    bit<32> rand_hash_30_idx;  // computed index for stage 30
    bit<32> rand_hash_31_idx;  // computed index for stage 31
    bit<32> rand_hash_32_idx;  // computed index for stage 32
}

/*/
|*| HHH digest type
/*/
struct hhh_digest_t {
    bit<32> srcAddr;
    bit<1> need_table_query;
    bit<33> cur_prefix;
    bit<32> next_hop;
    bit<4> hash_hits;
}

/*/
|*| HHH processing control block
/*/
control process_hhh(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // HHH metadata instance
    hhh_metadata_t hhh;

    // prefix hash registers // TODO how to initialize to 0
    register<bit<HASH_ENTRY_SIZE>>(HHH_REGSIZE) crc_hash_reg;
    register<bit<HASH_ENTRY_SIZE>>(HHH_REGSIZE) rand_hash_reg;


    // HHH init action
    @name("hash_compute") action hash_compute() {

        // Compute crc hashes for different prefix lenghts
        hhh.crc_hash_00_idx = HHH_REGSIZE-1;
        hash(hhh.crc_hash_01_idx, HashAlgorithm.crc32,  0*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 31 }, HHH_TABSIZE);
        hash(hhh.crc_hash_02_idx, HashAlgorithm.crc32,  1*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 30 }, HHH_TABSIZE);
        hash(hhh.crc_hash_03_idx, HashAlgorithm.crc32,  2*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 29 }, HHH_TABSIZE);
        hash(hhh.crc_hash_04_idx, HashAlgorithm.crc32,  3*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 28 }, HHH_TABSIZE);
        hash(hhh.crc_hash_05_idx, HashAlgorithm.crc32,  4*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 27 }, HHH_TABSIZE);
        hash(hhh.crc_hash_06_idx, HashAlgorithm.crc32,  5*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 26 }, HHH_TABSIZE);
        hash(hhh.crc_hash_07_idx, HashAlgorithm.crc32,  6*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 25 }, HHH_TABSIZE);
        hash(hhh.crc_hash_08_idx, HashAlgorithm.crc32,  7*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 24 }, HHH_TABSIZE);
        hash(hhh.crc_hash_09_idx, HashAlgorithm.crc32,  8*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 23 }, HHH_TABSIZE);
        hash(hhh.crc_hash_10_idx, HashAlgorithm.crc32,  9*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 22 }, HHH_TABSIZE);
        hash(hhh.crc_hash_11_idx, HashAlgorithm.crc32, 10*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 21 }, HHH_TABSIZE);
        hash(hhh.crc_hash_12_idx, HashAlgorithm.crc32, 11*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 20 }, HHH_TABSIZE);
        hash(hhh.crc_hash_13_idx, HashAlgorithm.crc32, 12*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 19 }, HHH_TABSIZE);
        hash(hhh.crc_hash_14_idx, HashAlgorithm.crc32, 13*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 18 }, HHH_TABSIZE);
        hash(hhh.crc_hash_15_idx, HashAlgorithm.crc32, 14*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 17 }, HHH_TABSIZE);
        hash(hhh.crc_hash_16_idx, HashAlgorithm.crc32, 15*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 16 }, HHH_TABSIZE);
        hash(hhh.crc_hash_17_idx, HashAlgorithm.crc32, 16*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 15 }, HHH_TABSIZE);
        hash(hhh.crc_hash_18_idx, HashAlgorithm.crc32, 17*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 14 }, HHH_TABSIZE);
        hash(hhh.crc_hash_19_idx, HashAlgorithm.crc32, 18*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 13 }, HHH_TABSIZE);
        hash(hhh.crc_hash_20_idx, HashAlgorithm.crc32, 19*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 12 }, HHH_TABSIZE);
        hash(hhh.crc_hash_21_idx, HashAlgorithm.crc32, 20*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 11 }, HHH_TABSIZE);
        hash(hhh.crc_hash_22_idx, HashAlgorithm.crc32, 21*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 10 }, HHH_TABSIZE);
        hash(hhh.crc_hash_23_idx, HashAlgorithm.crc32, 22*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  9 }, HHH_TABSIZE);
        hash(hhh.crc_hash_24_idx, HashAlgorithm.crc32, 23*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  8 }, HHH_TABSIZE);
        hash(hhh.crc_hash_25_idx, HashAlgorithm.crc32, 24*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  7 }, HHH_TABSIZE);
        hash(hhh.crc_hash_26_idx, HashAlgorithm.crc32, 25*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  6 }, HHH_TABSIZE);
        hash(hhh.crc_hash_27_idx, HashAlgorithm.crc32, 26*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  5 }, HHH_TABSIZE);
        hash(hhh.crc_hash_28_idx, HashAlgorithm.crc32, 27*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  4 }, HHH_TABSIZE);
        hash(hhh.crc_hash_29_idx, HashAlgorithm.crc32, 28*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  3 }, HHH_TABSIZE);
        hash(hhh.crc_hash_30_idx, HashAlgorithm.crc32, 29*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  2 }, HHH_TABSIZE);
        hash(hhh.crc_hash_31_idx, HashAlgorithm.crc32, 30*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  1 }, HHH_TABSIZE);
        hash(hhh.crc_hash_32_idx, HashAlgorithm.crc32, 31*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  0 }, HHH_TABSIZE);

        // Compute rand hashes for different prefix lenghts
        hhh.rand_hash_00_idx = HHH_REGSIZE-1;
        hash(hhh.rand_hash_01_idx, HashAlgorithm.identity,  0*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 31 }, HHH_TABSIZE);
        hash(hhh.rand_hash_02_idx, HashAlgorithm.identity,  1*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 30 }, HHH_TABSIZE);
        hash(hhh.rand_hash_03_idx, HashAlgorithm.identity,  2*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 29 }, HHH_TABSIZE);
        hash(hhh.rand_hash_04_idx, HashAlgorithm.identity,  3*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 28 }, HHH_TABSIZE);
        hash(hhh.rand_hash_05_idx, HashAlgorithm.identity,  4*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 27 }, HHH_TABSIZE);
        hash(hhh.rand_hash_06_idx, HashAlgorithm.identity,  5*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 26 }, HHH_TABSIZE);
        hash(hhh.rand_hash_07_idx, HashAlgorithm.identity,  6*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 25 }, HHH_TABSIZE);
        hash(hhh.rand_hash_08_idx, HashAlgorithm.identity,  7*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 24 }, HHH_TABSIZE);
        hash(hhh.rand_hash_09_idx, HashAlgorithm.identity,  8*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 23 }, HHH_TABSIZE);
        hash(hhh.rand_hash_10_idx, HashAlgorithm.identity,  9*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 22 }, HHH_TABSIZE);
        hash(hhh.rand_hash_11_idx, HashAlgorithm.identity, 10*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 21 }, HHH_TABSIZE);
        hash(hhh.rand_hash_12_idx, HashAlgorithm.identity, 11*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 20 }, HHH_TABSIZE);
        hash(hhh.rand_hash_13_idx, HashAlgorithm.identity, 12*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 19 }, HHH_TABSIZE);
        hash(hhh.rand_hash_14_idx, HashAlgorithm.identity, 13*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 18 }, HHH_TABSIZE);
        hash(hhh.rand_hash_15_idx, HashAlgorithm.identity, 14*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 17 }, HHH_TABSIZE);
        hash(hhh.rand_hash_16_idx, HashAlgorithm.identity, 15*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 16 }, HHH_TABSIZE);
        hash(hhh.rand_hash_17_idx, HashAlgorithm.identity, 16*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 15 }, HHH_TABSIZE);
        hash(hhh.rand_hash_18_idx, HashAlgorithm.identity, 17*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 14 }, HHH_TABSIZE);
        hash(hhh.rand_hash_19_idx, HashAlgorithm.identity, 18*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 13 }, HHH_TABSIZE);
        hash(hhh.rand_hash_20_idx, HashAlgorithm.identity, 19*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 12 }, HHH_TABSIZE);
        hash(hhh.rand_hash_21_idx, HashAlgorithm.identity, 20*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 11 }, HHH_TABSIZE);
        hash(hhh.rand_hash_22_idx, HashAlgorithm.identity, 21*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >> 10 }, HHH_TABSIZE);
        hash(hhh.rand_hash_23_idx, HashAlgorithm.identity, 22*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  9 }, HHH_TABSIZE);
        hash(hhh.rand_hash_24_idx, HashAlgorithm.identity, 23*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  8 }, HHH_TABSIZE);
        hash(hhh.rand_hash_25_idx, HashAlgorithm.identity, 24*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  7 }, HHH_TABSIZE);
        hash(hhh.rand_hash_26_idx, HashAlgorithm.identity, 25*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  6 }, HHH_TABSIZE);
        hash(hhh.rand_hash_27_idx, HashAlgorithm.identity, 26*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  5 }, HHH_TABSIZE);
        hash(hhh.rand_hash_28_idx, HashAlgorithm.identity, 27*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  4 }, HHH_TABSIZE);
        hash(hhh.rand_hash_29_idx, HashAlgorithm.identity, 28*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  3 }, HHH_TABSIZE);
        hash(hhh.rand_hash_30_idx, HashAlgorithm.identity, 29*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  2 }, HHH_TABSIZE);
        hash(hhh.rand_hash_31_idx, HashAlgorithm.identity, 30*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  1 }, HHH_TABSIZE);
        hash(hhh.rand_hash_32_idx, HashAlgorithm.identity, 31*HHH_TABSIZE, { (EXTENDER | hdr.ipv4.srcAddr) >>  0 }, HHH_TABSIZE);
}

    // HHH init action
    @name("hash_lookup") action hash_lookup() {

        // Read validity bits and construct bitvectors
        bit<HASH_ENTRY_SIZE> hash_val;
        hhh.vector = 0;
        
        // hash_entry format: [33 bits encoded prefix][1 bit longer exists][32 bits next hop]

        crc_hash_reg.read(hash_val, hhh.crc_hash_01_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 31 ) { hhh.vector = hhh.vector | 32w0x80000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_02_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 30 ) { hhh.vector = hhh.vector | 32w0x40000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_03_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 29 ) { hhh.vector = hhh.vector | 32w0x20000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_04_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 28 ) { hhh.vector = hhh.vector | 32w0x10000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_05_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 27 ) { hhh.vector = hhh.vector | 32w0x08000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_06_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 26 ) { hhh.vector = hhh.vector | 32w0x04000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_07_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 25 ) { hhh.vector = hhh.vector | 32w0x02000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_08_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 24 ) { hhh.vector = hhh.vector | 32w0x01000000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_09_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 23 ) { hhh.vector = hhh.vector | 32w0x00800000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_10_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 22 ) { hhh.vector = hhh.vector | 32w0x00400000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_11_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 21 ) { hhh.vector = hhh.vector | 32w0x00200000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_12_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 20 ) { hhh.vector = hhh.vector | 32w0x00100000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_13_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 19 ) { hhh.vector = hhh.vector | 32w0x00080000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_14_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 18 ) { hhh.vector = hhh.vector | 32w0x00040000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_15_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 17 ) { hhh.vector = hhh.vector | 32w0x00020000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_16_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 16 ) { hhh.vector = hhh.vector | 32w0x00010000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_17_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 15 ) { hhh.vector = hhh.vector | 32w0x00008000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_18_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 14 ) { hhh.vector = hhh.vector | 32w0x00004000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_19_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 13 ) { hhh.vector = hhh.vector | 32w0x00002000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_20_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 12 ) { hhh.vector = hhh.vector | 32w0x00001000; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_21_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 11 ) { hhh.vector = hhh.vector | 32w0x00000800; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_22_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 10 ) { hhh.vector = hhh.vector | 32w0x00000400; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_23_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 9 ) { hhh.vector = hhh.vector | 32w0x00000200; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_24_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 8 ) { hhh.vector = hhh.vector | 32w0x00000100; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_25_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 7 ) { hhh.vector = hhh.vector | 32w0x00000080; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_26_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 6 ) { hhh.vector = hhh.vector | 32w0x00000040; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_27_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 5 ) { hhh.vector = hhh.vector | 32w0x00000020; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_28_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 4 ) { hhh.vector = hhh.vector | 32w0x00000010; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_29_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 3 ) { hhh.vector = hhh.vector | 32w0x00000008; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_30_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 2 ) { hhh.vector = hhh.vector | 32w0x00000004; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_31_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 1 ) { hhh.vector = hhh.vector | 32w0x00000002; }
        crc_hash_reg.read(hash_val, hhh.crc_hash_32_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 0 ) { hhh.vector = hhh.vector | 32w0x00000001; }
   
         rand_hash_reg.read(hash_val, hhh.rand_hash_01_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 31 ) { hhh.vector = hhh.vector | 32w0x80000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_02_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 30 ) { hhh.vector = hhh.vector | 32w0x40000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_03_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 29 ) { hhh.vector = hhh.vector | 32w0x20000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_04_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 28 ) { hhh.vector = hhh.vector | 32w0x10000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_05_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 27 ) { hhh.vector = hhh.vector | 32w0x08000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_06_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 26 ) { hhh.vector = hhh.vector | 32w0x04000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_07_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 25 ) { hhh.vector = hhh.vector | 32w0x02000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_08_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 24 ) { hhh.vector = hhh.vector | 32w0x01000000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_09_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 23 ) { hhh.vector = hhh.vector | 32w0x00800000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_10_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 22 ) { hhh.vector = hhh.vector | 32w0x00400000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_11_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 21 ) { hhh.vector = hhh.vector | 32w0x00200000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_12_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 20 ) { hhh.vector = hhh.vector | 32w0x00100000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_13_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 19 ) { hhh.vector = hhh.vector | 32w0x00080000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_14_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 18 ) { hhh.vector = hhh.vector | 32w0x00040000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_15_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 17 ) { hhh.vector = hhh.vector | 32w0x00020000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_16_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 16 ) { hhh.vector = hhh.vector | 32w0x00010000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_17_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 15 ) { hhh.vector = hhh.vector | 32w0x00008000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_18_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 14 ) { hhh.vector = hhh.vector | 32w0x00004000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_19_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 13 ) { hhh.vector = hhh.vector | 32w0x00002000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_20_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 12 ) { hhh.vector = hhh.vector | 32w0x00001000; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_21_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 11 ) { hhh.vector = hhh.vector | 32w0x00000800; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_22_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 10 ) { hhh.vector = hhh.vector | 32w0x00000400; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_23_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 9 ) { hhh.vector = hhh.vector | 32w0x00000200; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_24_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 8 ) { hhh.vector = hhh.vector | 32w0x00000100; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_25_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 7 ) { hhh.vector = hhh.vector | 32w0x00000080; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_26_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 6 ) { hhh.vector = hhh.vector | 32w0x00000040; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_27_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 5 ) { hhh.vector = hhh.vector | 32w0x00000020; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_28_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 4 ) { hhh.vector = hhh.vector | 32w0x00000010; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_29_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 3 ) { hhh.vector = hhh.vector | 32w0x00000008; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_30_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 2 ) { hhh.vector = hhh.vector | 32w0x00000004; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_31_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 1 ) { hhh.vector = hhh.vector | 32w0x00000002; }
        rand_hash_reg.read(hash_val, hhh.rand_hash_32_idx); if (hash_val[64:33] == (EXTENDER | hdr.ipv4.srcAddr) >> 0 ) { hhh.vector = hhh.vector | 32w0x00000001; }
 
   }

     // Get CRC Hash index for current length
     @name("crc_index") action crc_index(out bit<32> crc_idx, bit<8> pref_len) {

        /* Unknown value */ { crc_idx = hhh.crc_hash_00_idx; }
        if (pref_len ==  1) { crc_idx = hhh.crc_hash_01_idx; } else
        if (pref_len ==  2) { crc_idx = hhh.crc_hash_02_idx; } else
        if (pref_len ==  3) { crc_idx = hhh.crc_hash_03_idx; } else
        if (pref_len ==  4) { crc_idx = hhh.crc_hash_04_idx; } else
        if (pref_len ==  5) { crc_idx = hhh.crc_hash_05_idx; } else
        if (pref_len ==  6) { crc_idx = hhh.crc_hash_06_idx; } else
        if (pref_len ==  7) { crc_idx = hhh.crc_hash_07_idx; } else
        if (pref_len ==  8) { crc_idx = hhh.crc_hash_08_idx; } else
        if (pref_len ==  9) { crc_idx = hhh.crc_hash_09_idx; } else
        if (pref_len == 10) { crc_idx = hhh.crc_hash_10_idx; }
        if (pref_len == 11) { crc_idx = hhh.crc_hash_11_idx; } else
        if (pref_len == 12) { crc_idx = hhh.crc_hash_12_idx; } else
        if (pref_len == 13) { crc_idx = hhh.crc_hash_13_idx; } else
        if (pref_len == 14) { crc_idx = hhh.crc_hash_14_idx; } else
        if (pref_len == 15) { crc_idx = hhh.crc_hash_15_idx; } else
        if (pref_len == 16) { crc_idx = hhh.crc_hash_16_idx; } else
        if (pref_len == 17) { crc_idx = hhh.crc_hash_17_idx; } else
        if (pref_len == 18) { crc_idx = hhh.crc_hash_18_idx; } else
        if (pref_len == 19) { crc_idx = hhh.crc_hash_19_idx; } else
        if (pref_len == 20) { crc_idx = hhh.crc_hash_20_idx; }
        if (pref_len == 21) { crc_idx = hhh.crc_hash_21_idx; } else
        if (pref_len == 22) { crc_idx = hhh.crc_hash_22_idx; } else
        if (pref_len == 23) { crc_idx = hhh.crc_hash_23_idx; } else
        if (pref_len == 24) { crc_idx = hhh.crc_hash_24_idx; } else
        if (pref_len == 25) { crc_idx = hhh.crc_hash_25_idx; } else
        if (pref_len == 26) { crc_idx = hhh.crc_hash_26_idx; } else
        if (pref_len == 27) { crc_idx = hhh.crc_hash_27_idx; } else
        if (pref_len == 28) { crc_idx = hhh.crc_hash_28_idx; } else
        if (pref_len == 29) { crc_idx = hhh.crc_hash_29_idx; } else
        if (pref_len == 30) { crc_idx = hhh.crc_hash_30_idx; }
        if (pref_len == 31) { crc_idx = hhh.crc_hash_31_idx; } else
        if (pref_len == 32) { crc_idx = hhh.crc_hash_32_idx; }
    }


    // HHH generic action to choose prefix index according the length
    @name("rand_index") action rand_index(out bit<32> rand_idx, bit<8> pref_len) {

        /* Unknown value */ { rand_idx = hhh.rand_hash_00_idx; }
        if (pref_len ==  1) { rand_idx = hhh.rand_hash_01_idx; } else
        if (pref_len ==  2) { rand_idx = hhh.rand_hash_02_idx; } else
        if (pref_len ==  3) { rand_idx = hhh.rand_hash_03_idx; } else
        if (pref_len ==  4) { rand_idx = hhh.rand_hash_04_idx; } else
        if (pref_len ==  5) { rand_idx = hhh.rand_hash_05_idx; } else
        if (pref_len ==  6) { rand_idx = hhh.rand_hash_06_idx; } else
        if (pref_len ==  7) { rand_idx = hhh.rand_hash_07_idx; } else
        if (pref_len ==  8) { rand_idx = hhh.rand_hash_08_idx; } else
        if (pref_len ==  9) { rand_idx = hhh.rand_hash_09_idx; } else
        if (pref_len == 10) { rand_idx = hhh.rand_hash_10_idx; }
        if (pref_len == 11) { rand_idx = hhh.rand_hash_11_idx; } else
        if (pref_len == 12) { rand_idx = hhh.rand_hash_12_idx; } else
        if (pref_len == 13) { rand_idx = hhh.rand_hash_13_idx; } else
        if (pref_len == 14) { rand_idx = hhh.rand_hash_14_idx; } else
        if (pref_len == 15) { rand_idx = hhh.rand_hash_15_idx; } else
        if (pref_len == 16) { rand_idx = hhh.rand_hash_16_idx; } else
        if (pref_len == 17) { rand_idx = hhh.rand_hash_17_idx; } else
        if (pref_len == 18) { rand_idx = hhh.rand_hash_18_idx; } else
        if (pref_len == 19) { rand_idx = hhh.rand_hash_19_idx; } else
        if (pref_len == 20) { rand_idx = hhh.rand_hash_20_idx; }
        if (pref_len == 21) { rand_idx = hhh.rand_hash_21_idx; } else
        if (pref_len == 22) { rand_idx = hhh.rand_hash_22_idx; } else
        if (pref_len == 23) { rand_idx = hhh.rand_hash_23_idx; } else
        if (pref_len == 24) { rand_idx = hhh.rand_hash_24_idx; } else
        if (pref_len == 25) { rand_idx = hhh.rand_hash_25_idx; } else
        if (pref_len == 26) { rand_idx = hhh.rand_hash_26_idx; } else
        if (pref_len == 27) { rand_idx = hhh.rand_hash_27_idx; } else
        if (pref_len == 28) { rand_idx = hhh.rand_hash_28_idx; } else
        if (pref_len == 29) { rand_idx = hhh.rand_hash_29_idx; } else
        if (pref_len == 30) { rand_idx = hhh.rand_hash_30_idx; }
        if (pref_len == 31) { rand_idx = hhh.rand_hash_31_idx; } else
        if (pref_len == 32) { rand_idx = hhh.rand_hash_32_idx; }
    }

    @name("parse_hash_val") action parse_hash_val(bit<HASH_ENTRY_SIZE> hash_val) {
        
        hhh.need_table_query = 1;

        bit<33> prefix = hash_val[65:33];
        bit<1> longer_exists = hash_val[32:32];
        bit<32> next_hop = hash_val[31:0];

        if(hash_val > 0) {hhh.hash_hits[3:3] = 1;} // TODO update hash hit depending if it is crc or rand

        if(prefix == hhh.cur_prefix && longer_exists == 0 ) {
            hhh.need_table_query = 0;
            hhh.next_hop = next_hop;
        }
    }


    // HHH generic found action
    @name("found_hash_lpm") action found_hash_lpm(bit<8> cur_len) {
        hhh.cur_len = cur_len;        
        hhh.cur_prefix =  (bit<33>)((EXTENDER | hdr.ipv4.srcAddr) >> (32-hhh.cur_len)); 
        crc_index(hhh.crc_idx, hhh.cur_len);
        rand_index(hhh.rand_idx, hhh.cur_len);
    }


    // Match from LPM table found
    @name("lpm_table_match") action lpm_table_match(bit<8> cur_len, bit<1> longer_exists, bit<32> next_hop) {
        hhh.cur_len = cur_len;
        hhh.next_hop = next_hop;
        
        // compute hhh.hash_entry by concatenation
        hhh.cur_prefix =  (bit<33>)((EXTENDER | hdr.ipv4.srcAddr) >> (32-hhh.cur_len)); 
        hhh.new_hash_entry = hhh.cur_prefix ++ longer_exists ++ next_hop; 

    }

    // Compute Hash Indexes for each length
    @name("compute_tab") table compute_tab {
        actions = { hash_compute; }
        default_action = hash_compute();
    }
   
    // Perform Hash Lookup for each length
    @name("hash_tab") table hash_tab {
        actions = { hash_lookup; }
        default_action = hash_lookup();
    }
   

    // HHH priority encoder table
    @name("pe_table") table pe_tab {
        actions = { found_hash_lpm; }
        default_action = found_hash_lpm(0);
        key = { hhh.vector: ternary; }
    }


    // HHH lookup table
    @name("lookup_tab") table lookup_tab {
        actions = { lpm_table_match; }
        default_action = lpm_table_match(0, 0, 0);
        key = { hdr.ipv4.srcAddr: lpm; }
    }

    apply {
    
        hhh.need_table_query = 1;    
        hhh.next_hop = 0;
        hhh.cur_prefix = 0;
        hhh.cur_len = 0;

        // Compute hash indices
        compute_tab.apply();

        // Index into Hash Tables
        hash_tab.apply(); 
        
        
        bit<HASH_ENTRY_SIZE> temp;
        

        crc_hash_reg.read(temp, hhh.crc_idx);
        parse_hash_val(temp);

        if(hhh.need_table_query == 1) {
            rand_hash_reg.read(temp, hhh.rand_idx);
            parse_hash_val(temp);
        }

        // Find Hashed Longest Match
        pe_tab.apply();

        temp = 0;

        // Search prefix table and add to hash (if necessary)
        if(hhh.need_table_query == 1) {
            lookup_tab.apply();
           
            crc_hash_reg.read(temp, hhh.crc_idx);
            if(temp ==  0) {

                // Write to CRC Hash
                crc_hash_reg.write(hhh.crc_idx, hhh.new_hash_entry);

            } else{

                hhh.hash_hits[1:1] = 1;
                rand_hash_reg.read(temp, hhh.rand_idx);
            
                if(temp == 0) {
                    // Write to Random Hash
                    rand_hash_reg.write(hhh.rand_idx, hhh.new_hash_entry);        
                } else{
                
                    hhh.hash_hits[0:0] = 1;
                    // TODO: what to do in case of double collision?
            
                 }
            }
        }

        // Inform controller
        digest<hhh_digest_t>(0, {
            hdr.ipv4.srcAddr,
            hhh.need_table_query,
            hhh.cur_prefix,
            hhh.next_hop,
            hhh.hash_hits
        });

        // hdr.ipv4.dstAddr = hhh.next_hop;
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
