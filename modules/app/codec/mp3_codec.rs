// MP3 codec kernel for unified decoder.
//
// Pipeline (mirrors minimp3.h, lieff/minimp3, CC0):
//   bitstream → frame buffer → side info → main_data → scalefactors
//   → huffman → requantize (f32) → MS-stereo → reorder → antialias
//   → IMDCT (long/short) → change_sign → DCT-II → synthesis → PCM i16
//
// DSP layer uses f32 throughout to match minimp3's reference behaviour
// bit-for-bit (modulo rounding). All targets (rp2350 / bcm2712 / wasm32)
// have hardware f32 FPU; no soft-float overhead.

use super::abi::SyscallTable;
use super::{POLL_IN, POLL_OUT, E_AGAIN, IOCTL_NOTIFY, drain_pending, track_pending, dev_log, dev_channel_ioctl, fmt_u32_raw, fmt_i16_raw};

// ============================================================================
// Section 1: Constants, BitReader
// ============================================================================

const IO_BUF_SIZE: usize = 256;
const SAMPLES_PER_FRAME: usize = 1152;
const SUBBANDS: usize = 32;
const GRANULE_SAMPLES: usize = 576;

/// MP3 decoder phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Mp3Phase {
    Sync = 0,
    Frame = 1,
    Decode = 2,
}

// --- BitReader (pointer-based, no slices) ---
#[repr(C)]
struct BitReader {
    data: *const u8,
    data_len: usize,
    byte_pos: usize,
    bit_pos: u8,
}

fn br_new(data: *const u8, len: usize) -> BitReader {
    BitReader { data, data_len: len, byte_pos: 0, bit_pos: 0 }
}

fn br_bit_position(r: &BitReader) -> usize {
    r.byte_pos * 8 + r.bit_pos as usize
}

fn br_bits_remaining(r: &BitReader) -> usize {
    if r.byte_pos >= r.data_len { return 0; }
    (r.data_len - r.byte_pos) * 8 - r.bit_pos as usize
}

/// Read a single bit. Returns 0 or 1, or -1 on error.
fn br_read_bit(r: &mut BitReader) -> i32 {
    if r.byte_pos >= r.data_len { return -1; }
    let byte = unsafe { *r.data.add(r.byte_pos) };
    let bit = ((byte >> (7 - r.bit_pos)) & 1) as i32;
    r.bit_pos += 1;
    if r.bit_pos >= 8 {
        r.bit_pos = 0;
        r.byte_pos += 1;
    }
    bit
}

/// Read up to 25 bits. Returns value or -1 on error.
fn br_read_bits(r: &mut BitReader, count: u8) -> i32 {
    if count == 0 { return 0; }
    if br_bits_remaining(r) < count as usize { return -1; }
    let mut result: u32 = 0;
    let mut remaining = count;
    while remaining > 0 {
        let bits_in_current = 8 - r.bit_pos;
        let bits_to_read = if remaining < bits_in_current { remaining } else { bits_in_current };
        let shift = bits_in_current - bits_to_read;
        let mask = ((1u16 << bits_to_read) - 1) as u8;
        let byte = unsafe { *r.data.add(r.byte_pos) };
        let bits = (byte >> shift) & mask;
        result = (result << bits_to_read) | bits as u32;
        remaining -= bits_to_read;
        r.bit_pos += bits_to_read;
        if r.bit_pos >= 8 {
            r.bit_pos = 0;
            r.byte_pos += 1;
        }
    }
    result as i32
}

fn br_skip_bits(r: &mut BitReader, count: usize) -> i32 {
    if br_bits_remaining(r) < count { return -1; }
    let total_bits = r.bit_pos as usize + count;
    r.byte_pos += total_bits / 8;
    r.bit_pos = (total_bits - (total_bits / 8) * 8) as u8;
    0
}

// ============================================================================
// Section 2: Frame header parsing
// ============================================================================

static BITRATE_TABLE: [u16; 16] = [
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
];

static SAMPLE_RATE_TABLE: [u32; 4] = [44100, 48000, 32000, 0];

const SLEN_TABLE: [(u8, u8); 16] = [
    (0, 0), (0, 1), (0, 2), (0, 3), (3, 0), (1, 1), (1, 2), (1, 3),
    (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3), (4, 2), (4, 3),
];

const PRETAB: [i32; 22] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 3, 2, 0,
];

/// Parse header from 4 bytes at ptr. Returns frame_size or 0 on error.
/// Also writes sample_rate, channels, channel_mode, mode_extension, has_crc.
fn parse_header(
    ptr: *const u8,
    out_sample_rate: &mut u32,
    out_channels: &mut u8,
    out_channel_mode: &mut u8,
    out_mode_ext: &mut u8,
    out_has_crc: &mut u8,
    out_frame_size: &mut usize,
) -> i32 {
    unsafe {
        let b0 = *ptr.add(0);
        let b1 = *ptr.add(1);
        let b2 = *ptr.add(2);
        let b3 = *ptr.add(3);

        if b0 != 0xFF || (b1 & 0xE0) != 0xE0 { return -1; }

        let version_bits = (b1 >> 3) & 0x03;
        let layer_bits = (b1 >> 1) & 0x03;
        let protection_bit = b1 & 0x01;

        if version_bits != 3 { return -8; }
        if layer_bits != 1 { return -8; }

        let bitrate_index = ((b2 >> 4) & 0x0F) as usize;
        let sample_rate_index = ((b2 >> 2) & 0x03) as usize;
        let padding = (b2 & 0x02) != 0;

        if bitrate_index >= 16 { return -2; }
        let bitrate_kbps = *BITRATE_TABLE.as_ptr().add(bitrate_index);
        if bitrate_kbps == 0 { return -2; }

        if sample_rate_index >= 4 { return -2; }
        let sample_rate = *SAMPLE_RATE_TABLE.as_ptr().add(sample_rate_index);
        if sample_rate == 0 { return -2; }

        let channel_mode_bits = (b3 >> 6) & 0x03;
        let mode_extension = (b3 >> 4) & 0x03;

        let channels = if channel_mode_bits == 3 { 1u8 } else { 2u8 };

        let frame_size = (144 * (bitrate_kbps as u32) * 1000 / sample_rate) as usize
            + if padding { 1 } else { 0 };

        *out_sample_rate = sample_rate;
        *out_channels = channels;
        *out_channel_mode = channel_mode_bits;
        *out_mode_ext = mode_extension;
        *out_has_crc = if protection_bit == 0 { 1 } else { 0 };
        *out_frame_size = frame_size;

        0
    }
}

// ============================================================================
// Section 3: Huffman tables (tree-based, CC0 public domain)
// ============================================================================

static LINBITS: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 2, 3, 4, 6, 8, 10, 13,
    4, 5, 6, 7, 8, 9, 11, 13,
];

// Packed Huffman tree (CC0 public domain, identical to minimp3's tabs[])
#[rustfmt::skip]
static TABS: [i16; 2164] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    785,785,785,785,784,784,784,784,513,513,513,513,513,513,513,513,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
    -255,1313,1298,1282,785,785,785,785,784,784,784,784,769,769,769,769,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,290,288,
    -255,1313,1298,1282,769,769,769,769,529,529,529,529,529,529,529,529,528,528,528,528,528,528,528,528,512,512,512,512,512,512,512,512,290,288,
    -253,-318,-351,-367,785,785,785,785,784,784,784,784,769,769,769,769,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,819,818,547,547,275,275,275,275,561,560,515,546,289,274,288,258,
    -254,-287,1329,1299,1314,1312,1057,1057,1042,1042,1026,1026,784,784,784,784,529,529,529,529,529,529,529,529,769,769,769,769,768,768,768,768,563,560,306,306,291,259,
    -252,-413,-477,-542,1298,-575,1041,1041,784,784,784,784,769,769,769,769,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,-383,-399,1107,1092,1106,1061,849,849,789,789,1104,1091,773,773,1076,1075,341,340,325,309,834,804,577,577,532,532,516,516,832,818,803,816,561,561,531,531,515,546,289,289,288,258,
    -252,-429,-493,-559,1057,1057,1042,1042,529,529,529,529,529,529,529,529,784,784,784,784,769,769,769,769,512,512,512,512,512,512,512,512,-382,1077,-415,1106,1061,1104,849,849,789,789,1091,1076,1029,1075,834,834,597,581,340,340,339,324,804,833,532,532,832,772,818,803,817,787,816,771,290,290,290,290,288,258,
    -253,-349,-414,-447,-463,1329,1299,-479,1314,1312,1057,1057,1042,1042,1026,1026,785,785,785,785,784,784,784,784,769,769,769,769,768,768,768,768,-319,851,821,-335,836,850,805,849,341,340,325,336,533,533,579,579,564,564,773,832,578,548,563,516,321,276,306,291,304,259,
    -251,-572,-733,-830,-863,-879,1041,1041,784,784,784,784,769,769,769,769,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,-511,-527,-543,1396,1351,1381,1366,1395,1335,1380,-559,1334,1138,1138,1063,1063,1350,1392,1031,1031,1062,1062,1364,1363,1120,1120,1333,1348,881,881,881,881,375,374,359,373,343,358,341,325,791,791,1123,1122,-703,1105,1045,-719,865,865,790,790,774,774,1104,1029,338,293,323,308,-799,-815,833,788,772,818,803,816,322,292,307,320,561,531,515,546,289,274,288,258,
    -251,-525,-605,-685,-765,-831,-846,1298,1057,1057,1312,1282,785,785,785,785,784,784,784,784,769,769,769,769,512,512,512,512,512,512,512,512,1399,1398,1383,1367,1382,1396,1351,-511,1381,1366,1139,1139,1079,1079,1124,1124,1364,1349,1363,1333,882,882,882,882,807,807,807,807,1094,1094,1136,1136,373,341,535,535,881,775,867,822,774,-591,324,338,-671,849,550,550,866,864,609,609,293,336,534,534,789,835,773,-751,834,804,308,307,833,788,832,772,562,562,547,547,305,275,560,515,290,290,
    -252,-397,-477,-557,-622,-653,-719,-735,-750,1329,1299,1314,1057,1057,1042,1042,1312,1282,1024,1024,785,785,785,785,784,784,784,784,769,769,769,769,-383,1127,1141,1111,1126,1140,1095,1110,869,869,883,883,1079,1109,882,882,375,374,807,868,838,881,791,-463,867,822,368,263,852,837,836,-543,610,610,550,550,352,336,534,534,865,774,851,821,850,805,593,533,579,564,773,832,578,578,548,548,577,577,307,276,306,291,516,560,259,259,
    -250,-2107,-2507,-2764,-2909,-2974,-3007,-3023,1041,1041,1040,1040,769,769,769,769,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,-767,-1052,-1213,-1277,-1358,-1405,-1469,-1535,-1550,-1582,-1614,-1647,-1662,-1694,-1726,-1759,-1774,-1807,-1822,-1854,-1886,1565,-1919,-1935,-1951,-1967,1731,1730,1580,1717,-1983,1729,1564,-1999,1548,-2015,-2031,1715,1595,-2047,1714,-2063,1610,-2079,1609,-2095,1323,1323,1457,1457,1307,1307,1712,1547,1641,1700,1699,1594,1685,1625,1442,1442,1322,1322,-780,-973,-910,1279,1278,1277,1262,1276,1261,1275,1215,1260,1229,-959,974,974,989,989,-943,735,478,478,495,463,506,414,-1039,1003,958,1017,927,942,987,957,431,476,1272,1167,1228,-1183,1256,-1199,895,895,941,941,1242,1227,1212,1135,1014,1014,490,489,503,487,910,1013,985,925,863,894,970,955,1012,847,-1343,831,755,755,984,909,428,366,754,559,-1391,752,486,457,924,997,698,698,983,893,740,740,908,877,739,739,667,667,953,938,497,287,271,271,683,606,590,712,726,574,302,302,738,736,481,286,526,725,605,711,636,724,696,651,589,681,666,710,364,467,573,695,466,466,301,465,379,379,709,604,665,679,316,316,634,633,436,436,464,269,424,394,452,332,438,363,347,408,393,448,331,422,362,407,392,421,346,406,391,376,375,359,1441,1306,-2367,1290,-2383,1337,-2399,-2415,1426,1321,-2431,1411,1336,-2447,-2463,-2479,1169,1169,1049,1049,1424,1289,1412,1352,1319,-2495,1154,1154,1064,1064,1153,1153,416,390,360,404,403,389,344,374,373,343,358,372,327,357,342,311,356,326,1395,1394,1137,1137,1047,1047,1365,1392,1287,1379,1334,1364,1349,1378,1318,1363,792,792,792,792,1152,1152,1032,1032,1121,1121,1046,1046,1120,1120,1030,1030,-2895,1106,1061,1104,849,849,789,789,1091,1076,1029,1090,1060,1075,833,833,309,324,532,532,832,772,818,803,561,561,531,560,515,546,289,274,288,258,
    -250,-1179,-1579,-1836,-1996,-2124,-2253,-2333,-2413,-2477,-2542,-2574,-2607,-2622,-2655,1314,1313,1298,1312,1282,785,785,785,785,1040,1040,1025,1025,768,768,768,768,-766,-798,-830,-862,-895,-911,-927,-943,-959,-975,-991,-1007,-1023,-1039,-1055,-1070,1724,1647,-1103,-1119,1631,1767,1662,1738,1708,1723,-1135,1780,1615,1779,1599,1677,1646,1778,1583,-1151,1777,1567,1737,1692,1765,1722,1707,1630,1751,1661,1764,1614,1736,1676,1763,1750,1645,1598,1721,1691,1762,1706,1582,1761,1566,-1167,1749,1629,767,766,751,765,494,494,735,764,719,749,734,763,447,447,748,718,477,506,431,491,446,476,461,505,415,430,475,445,504,399,460,489,414,503,383,474,429,459,502,502,746,752,488,398,501,473,413,472,486,271,480,270,-1439,-1455,1357,-1471,-1487,-1503,1341,1325,-1519,1489,1463,1403,1309,-1535,1372,1448,1418,1476,1356,1462,1387,-1551,1475,1340,1447,1402,1386,-1567,1068,1068,1474,1461,455,380,468,440,395,425,410,454,364,467,466,464,453,269,409,448,268,432,1371,1473,1432,1417,1308,1460,1355,1446,1459,1431,1083,1083,1401,1416,1458,1445,1067,1067,1370,1457,1051,1051,1291,1430,1385,1444,1354,1415,1400,1443,1082,1082,1173,1113,1186,1066,1185,1050,-1967,1158,1128,1172,1097,1171,1081,-1983,1157,1112,416,266,375,400,1170,1142,1127,1065,793,793,1169,1033,1156,1096,1141,1111,1155,1080,1126,1140,898,898,808,808,897,897,792,792,1095,1152,1032,1125,1110,1139,1079,1124,882,807,838,881,853,791,-2319,867,368,263,822,852,837,866,806,865,-2399,851,352,262,534,534,821,836,594,594,549,549,593,593,533,533,848,773,579,579,564,578,548,563,276,276,577,576,306,291,516,560,305,305,275,259,
    -251,-892,-2058,-2620,-2828,-2957,-3023,-3039,1041,1041,1040,1040,769,769,769,769,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,-511,-527,-543,-559,1530,-575,-591,1528,1527,1407,1526,1391,1023,1023,1023,1023,1525,1375,1268,1268,1103,1103,1087,1087,1039,1039,1523,-604,815,815,815,815,510,495,509,479,508,463,507,447,431,505,415,399,-734,-782,1262,-815,1259,1244,-831,1258,1228,-847,-863,1196,-879,1253,987,987,748,-767,493,493,462,477,414,414,686,669,478,446,461,445,474,429,487,458,412,471,1266,1264,1009,1009,799,799,-1019,-1276,-1452,-1581,-1677,-1757,-1821,-1886,-1933,-1997,1257,1257,1483,1468,1512,1422,1497,1406,1467,1496,1421,1510,1134,1134,1225,1225,1466,1451,1374,1405,1252,1252,1358,1480,1164,1164,1251,1251,1238,1238,1389,1465,-1407,1054,1101,-1423,1207,-1439,830,830,1248,1038,1237,1117,1223,1148,1236,1208,411,426,395,410,379,269,1193,1222,1132,1235,1221,1116,976,976,1192,1162,1177,1220,1131,1191,963,963,-1647,961,780,-1663,558,558,994,993,437,408,393,407,829,978,813,797,947,-1743,721,721,377,392,844,950,828,890,706,706,812,859,796,960,948,843,934,874,571,571,-1919,690,555,689,421,346,539,539,944,779,918,873,932,842,903,888,570,570,931,917,674,674,-2575,1562,-2591,1609,-2607,1654,1322,1322,1441,1441,1696,1546,1683,1593,1669,1624,1426,1426,1321,1321,1639,1680,1425,1425,1305,1305,1545,1668,1608,1623,1667,1592,1638,1666,1320,1320,1652,1607,1409,1409,1304,1304,1288,1288,1664,1637,1395,1395,1335,1335,1622,1636,1394,1394,1319,1319,1606,1621,1392,1392,1137,1137,1137,1137,345,390,360,375,404,373,1047,-2751,-2767,-2783,1062,1121,1046,-2799,1077,-2815,1106,1061,789,789,1105,1104,263,355,310,340,325,354,352,262,339,324,1091,1076,1029,1090,1060,1075,833,833,788,788,1088,1028,818,818,803,803,561,561,531,531,816,771,546,546,289,274,288,258,
    -253,-317,-381,-446,-478,-509,1279,1279,-811,-1179,-1451,-1756,-1900,-2028,-2189,-2253,-2333,-2414,-2445,-2511,-2526,1313,1298,-2559,1041,1041,1040,1040,1025,1025,1024,1024,1022,1007,1021,991,1020,975,1019,959,687,687,1018,1017,671,671,655,655,1016,1015,639,639,758,758,623,623,757,607,756,591,755,575,754,559,543,543,1009,783,-575,-621,-685,-749,496,-590,750,749,734,748,974,989,1003,958,988,973,1002,942,987,957,972,1001,926,986,941,971,956,1000,910,985,925,999,894,970,-1071,-1087,-1102,1390,-1135,1436,1509,1451,1374,-1151,1405,1358,1480,1420,-1167,1507,1494,1389,1342,1465,1435,1450,1326,1505,1310,1493,1373,1479,1404,1492,1464,1419,428,443,472,397,736,526,464,464,486,457,442,471,484,482,1357,1449,1434,1478,1388,1491,1341,1490,1325,1489,1463,1403,1309,1477,1372,1448,1418,1433,1476,1356,1462,1387,-1439,1475,1340,1447,1402,1474,1324,1461,1371,1473,269,448,1432,1417,1308,1460,-1711,1459,-1727,1441,1099,1099,1446,1386,1431,1401,-1743,1289,1083,1083,1160,1160,1458,1445,1067,1067,1370,1457,1307,1430,1129,1129,1098,1098,268,432,267,416,266,400,-1887,1144,1187,1082,1173,1113,1186,1066,1050,1158,1128,1143,1172,1097,1171,1081,420,391,1157,1112,1170,1142,1127,1065,1169,1049,1156,1096,1141,1111,1155,1080,1126,1154,1064,1153,1140,1095,1048,-2159,1125,1110,1137,-2175,823,823,1139,1138,807,807,384,264,368,263,868,838,853,791,867,822,852,837,866,806,865,790,-2319,851,821,836,352,262,850,805,849,-2399,533,533,835,820,336,261,578,548,563,577,532,532,832,772,562,562,547,547,305,275,560,515,290,290,288,258,
];

// Table number to offset mapping into TABS
static TABINDEX: [i16; 32] = [
    0,32,64,98,0,132,180,218,292,364,426,538,648,746,0,1126,
    1460,1460,1460,1460,1460,1460,1460,1460,1842,1842,1842,1842,1842,1842,1842,1842,
];

// Count1 table A (table 32)
static TAB32: [u8; 28] = [
    130,162,193,209,44,28,76,140,9,9,9,9,9,9,9,9,
    190,254,222,238,126,94,157,157,109,61,173,205,
];

// Count1 table B (table 33)
static TAB33: [u8; 16] = [
    252,236,220,204,188,172,156,140,124,108,92,76,60,44,28,12,
];

// ============================================================================
// Section 3b: Cached bitstream reader + tree-based Huffman decode
// ============================================================================

#[repr(C)]
struct BsCached {
    cache: u32,
    sh: i32,
    next: *const u8,
    limit: *const u8,
}

fn bs_cached_new(data: *const u8, byte_offset: usize, data_len: usize) -> BsCached {
    unsafe {
        let start = data.add(byte_offset);
        let limit = data.add(data_len);
        let mut cache: u32 = 0;
        let avail = if data_len > byte_offset { data_len - byte_offset } else { 0 };
        let init_bytes = if avail > 4 { 4 } else { avail };
        let mut i: usize = 0;
        while i < init_bytes {
            cache |= (*start.add(i) as u32) << (24 - (i << 3));
            i += 1;
        }
        let next = start.add(init_bytes);
        let sh = 24 - (init_bytes as i32) * 8;
        BsCached { cache, sh, next, limit }
    }
}

impl BsCached {
    #[inline(always)]
    fn peek(&self, n: u32) -> u32 {
        self.cache >> (32 - n)
    }

    #[inline(always)]
    fn flush(&mut self, n: u32) {
        self.cache <<= n;
        self.sh += n as i32;
    }

    #[inline(always)]
    fn check(&mut self) {
        unsafe {
            while self.sh >= 0 {
                if self.next < self.limit {
                    self.cache |= (*self.next as u32) << self.sh as u32;
                    self.next = self.next.add(1);
                }
                self.sh -= 8;
            }
        }
    }
}

/// Decode one (x, y) pair from the Huffman tree.
fn decode_pair_tree(bs: &mut BsCached, tab_num: u8, linbits: u8) -> (i32, i32) {
    unsafe {
        let codebook = TABS.as_ptr().add(*TABINDEX.as_ptr().add(tab_num as usize) as usize);
        let mut w: u32 = 5;
        let mut leaf = *codebook.add(bs.peek(w) as usize) as i32;
        while leaf < 0 {
            bs.flush(w);
            w = (leaf & 7) as u32;
            let idx = bs.peek(w) as i32 - (leaf >> 3);
            leaf = *codebook.add(idx as usize) as i32;
        }
        bs.flush((leaf >> 8) as u32);

        let mut vals = [leaf & 0x0F, (leaf >> 4) & 0x0F];
        let mut j: usize = 0;
        while j < 2 {
            let mut lsb = *vals.as_ptr().add(j);
            if lsb != 0 {
                if linbits > 0 && lsb == 15 {
                    lsb += bs.peek(linbits as u32) as i32;
                    bs.flush(linbits as u32);
                    bs.check();
                }
                if (bs.cache >> 31) != 0 { lsb = -lsb; }
                bs.flush(1);
            }
            *vals.as_mut_ptr().add(j) = lsb;
            j += 1;
        }

        bs.check();
        (*vals.as_ptr().add(0), *vals.as_ptr().add(1))
    }
}

/// Decode one count1 quad (v, w, x, y) from table A or B.
fn decode_quad_tree(bs: &mut BsCached, use_table_b: bool) -> (i32, i32, i32, i32) {
    unsafe {
        let codebook: *const u8 = if use_table_b { TAB33.as_ptr() } else { TAB32.as_ptr() };
        let mut leaf = *codebook.add(bs.peek(4) as usize) as i32;
        if (leaf & 8) == 0 {
            let extra_bits = (leaf & 3) as u32;
            let base = (leaf >> 3) as u32;
            let idx = base + (bs.cache << 4 >> (32 - extra_bits));
            leaf = *codebook.add(idx as usize) as i32;
        }
        bs.flush((leaf & 7) as u32);

        let mut v: i32 = 0;
        let mut w: i32 = 0;
        let mut x: i32 = 0;
        let mut y: i32 = 0;

        if (leaf & 128) != 0 { v = if (bs.cache >> 31) != 0 { -1 } else { 1 }; bs.flush(1); }
        if (leaf & 64)  != 0 { w = if (bs.cache >> 31) != 0 { -1 } else { 1 }; bs.flush(1); }
        if (leaf & 32)  != 0 { x = if (bs.cache >> 31) != 0 { -1 } else { 1 }; bs.flush(1); }
        if (leaf & 16)  != 0 { y = if (bs.cache >> 31) != 0 { -1 } else { 1 }; bs.flush(1); }

        bs.check();
        (v, w, x, y)
    }
}

// ============================================================================
// Section 4: Spectral data decoding (tree-based Huffman)
// ============================================================================

/// Compute the line boundary covered by the first `n_sfb_windows` entries of
/// the granule's sfbtab. For long blocks the sfbtab is the long-band table
/// (one entry per SFB). For pure short, each SFB has 3 windows of the same
/// width. For mixed, the first 8 SFBs are long widths, then short widths × 3
/// starting at SFB index 3.
fn region_boundary_lines(
    n_sfb_windows: usize,
    block_type: u8,
    mixed: bool,
    sample_rate: u32,
) -> usize {
    unsafe {
        if block_type != 2 {
            let t = get_sfb_table(sample_rate);
            let i = n_sfb_windows.min(22);
            return *t.add(i);
        }
        if !mixed {
            let widths = get_sfb_short_widths(sample_rate);
            let mut lines = 0usize;
            let mut walked = 0usize;
            let mut sfb = 0usize;
            while walked < n_sfb_windows && sfb < 13 {
                let w = *widths.add(sfb) as usize;
                if w == 0 { break; }
                let mut win = 0;
                while win < 3 && walked < n_sfb_windows {
                    lines += w;
                    walked += 1;
                    win += 1;
                }
                sfb += 1;
            }
            return lines;
        }
        // Mixed: first 8 long SFBs (MPEG-1), then short × 3 starting at sfb=3.
        let t = get_sfb_table(sample_rate);
        let n_long: usize = 8;
        if n_sfb_windows <= n_long {
            return *t.add(n_sfb_windows);
        }
        let mut lines = *t.add(n_long);
        let widths = get_sfb_short_widths(sample_rate);
        let mut walked = n_long;
        let mut sfb = 3usize;
        while walked < n_sfb_windows && sfb < 13 {
            let w = *widths.add(sfb) as usize;
            if w == 0 { break; }
            let mut win = 0;
            while win < 3 && walked < n_sfb_windows {
                lines += w;
                walked += 1;
                win += 1;
            }
            sfb += 1;
        }
        lines
    }
}

/// Decode all spectral data for one granule/channel using tree-based Huffman.
/// Output is raw signed integer quanta (sign(is) * |is|). pow_4_3 and gain are
/// applied later in requantize().
fn decode_spectral_data(
    reader: &mut BitReader,
    big_values: u16,
    table_select: *const u8,
    region0_count: u8,
    region1_count: u8,
    count1table_select: bool,
    part2_3_length: u16,
    output: *mut i32,
    block_type: u8,
    mixed: bool,
    sample_rate: u32,
) -> i32 {
    unsafe {
        let mut i: usize = 0;
        while i < 576 { *output.add(i) = 0; i += 1; }

        // Region boundaries: minimp3 walks `region_count[i] + 1` SFB-windows
        // per region. The line boundary depends on the block type's sfbtab.
        let region0_end_raw = region_boundary_lines(
            region0_count as usize + 1, block_type, mixed, sample_rate);
        let region1_end_raw = region_boundary_lines(
            region0_count as usize + region1_count as usize + 2, block_type, mixed, sample_rate);
        let region0_end = if region0_end_raw < big_values as usize * 2 { region0_end_raw } else { big_values as usize * 2 };
        let region1_end = if region1_end_raw < big_values as usize * 2 { region1_end_raw } else { big_values as usize * 2 };
        let big_values_end = big_values as usize * 2;

        let start_bit = br_bit_position(reader);
        let part2_3_end = start_bit + part2_3_length as usize;

        let byte_off = reader.byte_pos;
        let bit_off = reader.bit_pos as u32;
        let mut bs = bs_cached_new(reader.data, byte_off, reader.data_len);
        if bit_off > 0 { bs.flush(bit_off); }
        bs.check();

        let regions: [(usize, usize, u8); 3] = [
            (0, region0_end, *table_select.add(0)),
            (region0_end, region1_end, *table_select.add(1)),
            (region1_end, big_values_end, *table_select.add(2)),
        ];

        let mut ri: usize = 0;
        while ri < 3 {
            let (rstart, rend, tab) = *regions.as_ptr().add(ri);
            if rend > rstart && tab != 0 && tab != 4 && tab != 14 {
                let linbits = *LINBITS.as_ptr().add(tab as usize);
                let mut pos = rstart;
                while pos + 1 < rend {
                    let (x, y) = decode_pair_tree(&mut bs, tab, linbits);
                    *output.add(pos) = x;
                    *output.add(pos + 1) = y;
                    pos += 2;
                }
            }
            ri += 1;
        }

        let mut pos = big_values_end;
        let bs_byte_dist = bs.next.offset_from(reader.data.add(byte_off)) as usize;
        let mut bits_used = (bs_byte_dist * 8) as i32 + bs.sh + 8 + bit_off as i32;

        while pos + 3 < 576 {
            if (start_bit as i32 + bits_used as i32) >= part2_3_end as i32 { break; }

            let (v, w, x, y) = decode_quad_tree(&mut bs, count1table_select);
            *output.add(pos) = v;
            *output.add(pos + 1) = w;
            *output.add(pos + 2) = x;
            *output.add(pos + 3) = y;
            pos += 4;

            let bd2 = bs.next.offset_from(reader.data.add(byte_off)) as usize;
            bits_used = (bd2 * 8) as i32 + bs.sh + 8 + bit_off as i32;
        }

        let consumed_total = part2_3_length as usize;
        reader.byte_pos = (start_bit + consumed_total) >> 3;
        reader.bit_pos = ((start_bit + consumed_total) & 7) as u8;

        0
    }
}

// ============================================================================
// Section 5: Requantize tables (float, mirrors minimp3 L3_pow_43 / g_pow43)
// ============================================================================

// g_pow43[129+16] from minimp3.h — table holds [-16..-1, 0..128] values of x^(4/3).
// Indexed as G_POW43[16 + lsb] for lsb in [-16..128].
static G_POW43: [f32; 145] = [
    0.0,-1.0,-2.519842,-4.326749,-6.349604,-8.549880,-10.902724,-13.390518,
    -16.000000,-18.720754,-21.544347,-24.463781,-27.473142,-30.567351,-33.741992,-36.993181,
    0.0,1.0,2.519842,4.326749,6.349604,8.549880,10.902724,13.390518,
    16.000000,18.720754,21.544347,24.463781,27.473142,30.567351,33.741992,36.993181,
    40.317474,43.711787,47.173345,50.699631,54.288352,57.937408,61.644865,65.408941,
    69.227979,73.100443,77.024898,81.000000,85.024491,89.097188,93.216975,97.382800,
    101.593667,105.848633,110.146801,114.487321,118.869381,123.292209,127.755065,132.257246,
    136.798076,141.376907,145.993119,150.646117,155.335327,160.060199,164.820202,169.614826,
    174.443577,179.305980,184.201575,189.129918,194.090580,199.083145,204.107210,209.162385,
    214.248292,219.364564,224.510845,229.686789,234.892058,240.126328,245.389280,250.680604,
    256.000000,261.347174,266.721841,272.123723,277.552547,283.008049,288.489971,293.998060,
    299.532071,305.091761,310.676898,316.287249,321.922592,327.582707,333.267377,338.976394,
    344.709550,350.466646,356.247482,362.051866,367.879608,373.730522,379.604427,385.501143,
    391.420496,397.362314,403.326427,409.312672,415.320884,421.350905,427.402579,433.475750,
    439.570269,445.685987,451.822757,457.980436,464.158883,470.357960,476.577530,482.817459,
    489.077615,495.357868,501.658090,507.978156,514.317941,520.677324,527.056184,533.454404,
    539.871867,546.308458,552.764065,559.238575,565.731879,572.243870,578.774440,585.323483,
    591.890898,598.476581,605.080431,611.702349,618.342238,625.000000,631.675540,638.368763,645.079578,
];

/// L3_pow_43 from minimp3.h, ported verbatim. Returns x^(4/3) for non-negative x.
#[inline]
fn l3_pow_43(x: i32) -> f32 {
    if x < 129 { return unsafe { *G_POW43.as_ptr().add((16 + x) as usize) }; }
    let mut mult: f32 = 256.0;
    let mut xv = x;
    if xv < 1024 { mult = 16.0; xv <<= 3; }
    // sign tracks the rounding direction for the lookup index
    let sign = (2i32.wrapping_mul(xv) & 64) as i32;
    let num = (xv & 63) - sign;
    let den = (xv & !63) + sign;
    let frac = (num as f32) / (den as f32);
    let idx = (16 + ((xv + sign) >> 6)) as usize;
    let lookup = unsafe { *G_POW43.as_ptr().add(idx) };
    lookup * (1.0 + frac * ((4.0 / 3.0) + frac * (2.0 / 9.0))) * mult
}

/// L3_ldexp_q2: y * 2^(exp_q2 / 4) using float arithmetic, no float pow().
/// Mirrors minimp3's L3_ldexp_q2.
fn l3_ldexp_q2(mut y: f32, mut exp_q2: i32) -> f32 {
    const G_EXPFRAC: [f32; 4] = [9.31322575e-10, 7.83145814e-10, 6.58544508e-10, 5.53767716e-10];
    loop {
        let e = if exp_q2 > 30 * 4 { 30 * 4 } else { exp_q2 };
        let pow_part = (1u32 << 30) >> ((e >> 2) as u32);
        y *= unsafe { *G_EXPFRAC.as_ptr().add((e & 3) as usize) } * pow_part as f32;
        exp_q2 -= e;
        if exp_q2 <= 0 { break; }
    }
    y
}

// ============================================================================
// Section 6: Scalefactor band tables
// ============================================================================

/// Long-block scalefactor band boundaries (line offsets). 23 entries; 0 and 576
/// are sentinels.
static SFB_LONG_44100: [usize; 23] = [
    0, 4, 8, 12, 16, 20, 24, 30, 36, 44, 52, 62, 74, 90, 110, 134, 162, 196, 238, 288, 342, 418, 576,
];
static SFB_LONG_48000: [usize; 23] = [
    0, 4, 8, 12, 16, 20, 24, 30, 36, 42, 50, 60, 72, 88, 106, 128, 156, 190, 230, 276, 330, 384, 576,
];
static SFB_LONG_32000: [usize; 23] = [
    0, 4, 8, 12, 16, 20, 24, 30, 36, 44, 54, 66, 82, 102, 126, 156, 194, 240, 296, 364, 448, 550, 576,
];

fn get_sfb_table(sample_rate: u32) -> *const usize {
    if sample_rate == 48000 { SFB_LONG_48000.as_ptr() }
    else if sample_rate == 32000 { SFB_LONG_32000.as_ptr() }
    else { SFB_LONG_44100.as_ptr() }
}

// Short-block scalefactor band widths (13 entries, zero-terminated). Each entry
// is the width of ONE window (multiplied by 3 windows total).
static SFB_SHORT_W_48000: [u8; 14] = [4,4,4,4,6,6,10,12,14,16,20,26,66, 0];
static SFB_SHORT_W_44100: [u8; 14] = [4,4,4,4,6,8,10,12,14,18,22,30,56, 0];
static SFB_SHORT_W_32000: [u8; 14] = [4,4,4,4,6,8,12,16,20,26,34,42,12, 0];

fn get_sfb_short_widths(sample_rate: u32) -> *const u8 {
    if sample_rate == 48000 { SFB_SHORT_W_48000.as_ptr() }
    else if sample_rate == 32000 { SFB_SHORT_W_32000.as_ptr() }
    else { SFB_SHORT_W_44100.as_ptr() }
}

/// Compute long-block SFB widths from the boundary table (22 widths).
fn long_sfb_widths(sample_rate: u32, out: &mut [u8; 22]) {
    let t = get_sfb_table(sample_rate);
    let mut i: usize = 0;
    while i < 22 {
        let a = unsafe { *t.add(i) };
        let b = unsafe { *t.add(i + 1) };
        out[i] = (b - a) as u8;
        i += 1;
    }
}

// ============================================================================
// Section 7: Requantize (f32 output, per-band gain * pow_4_3)
//
// Mirrors minimp3 L3_decode_scalefactors gain-exp arithmetic, applied to our
// existing scalefactor decode (`Mp3State::scalefactors`). The output `freq` is
// signed float; sign comes from the integer quanta sign.
// ============================================================================

/// Apply requantization to the 576 spectral samples of one granule/channel.
///
/// - `is`: signed integer quanta from huffman (size 576)
/// - `freq`: output f32 spectral samples (size 576)
/// - `scf`: 39 scalefactor bytes for this granule/channel (already includes the
///   raw `iscf` values from the bitstream; preflag/pretab and subblock_gain are
///   added here)
/// - `global_gain`, `scalefac_scale`, `preflag`: from side info
/// - `block_type` ∈ {0,1,3} long-like, 2 short (pure or mixed)
/// - `mixed`: mixed_block_flag (only meaningful when block_type==2)
/// - `subblock_gain[3]`: short-block per-window gain (block_type==2)
/// - `sample_rate`, `ms_stereo`: needed for gain adjustment
fn requantize(
    is: *const i32,
    freq: *mut f32,
    scf: *const u8,
    global_gain: u8,
    scalefac_scale: bool,
    block_type: u8,
    mixed: bool,
    subblock_gain: *const u8,
    preflag: bool,
    sample_rate: u32,
    ms_stereo: bool,
) {
    unsafe {
        // gain_exp = global_gain + BITS_DEQUANTIZER_OUT*4 - 210 - (MS?2:0)
        //          = global_gain - 4 - 210 - (MS?2:0)
        // BITS_DEQUANTIZER_OUT = -1 in minimp3 → factor of 1/2 in output domain.
        let ms_adj: i32 = if ms_stereo { 2 } else { 0 };
        let gain_exp = global_gain as i32 - 4 - 210 - ms_adj;
        // MAX_SCF = 255 + BITS_DEQUANTIZER_OUT*4 - 210 = 41
        // MAX_SCFI = (MAX_SCF + 3) & ~3 = 44 (rounded UP to multiple of 4)
        // gain = ldexp_q2(1 << (MAX_SCFI/4), MAX_SCFI - gain_exp) = ldexp_q2(2^11, 44 - gain_exp)
        let gain_base = l3_ldexp_q2((1u32 << 11) as f32, 44 - gain_exp);

        let scf_shift = if scalefac_scale { 2u32 } else { 1u32 };

        if block_type == 2 && !mixed {
            // PURE SHORT BLOCK
            // 13 short SFBs × 3 windows. SFB index → scf slot = sfb*3 + win.
            // Widths: SFB_SHORT_W_RATE[sfb] for each window.
            let widths = get_sfb_short_widths(sample_rate);
            let mut pos: usize = 0;
            let mut sfb: usize = 0;
            while sfb < 13 {
                let w = *widths.add(sfb) as usize;
                if w == 0 { break; }
                let mut win: usize = 0;
                while win < 3 {
                    let scf_slot = sfb * 3 + win;
                    let sf_val: i32 = if scf_slot < 39 { *scf.add(scf_slot) as i32 } else { 0 };
                    // subblock_gain folded via *8 in the exponent.
                    let sbg = *subblock_gain.add(win) as i32 * 8;
                    let exp_q2 = ((sf_val as i32) << scf_shift) + sbg;
                    let band_gain = l3_ldexp_q2(gain_base, exp_q2);
                    let mut k: usize = 0;
                    while k < w {
                        let q = *is.add(pos + k);
                        if q == 0 {
                            *freq.add(pos + k) = 0.0;
                        } else if q > 0 {
                            *freq.add(pos + k) = band_gain * l3_pow_43(q);
                        } else {
                            *freq.add(pos + k) = -band_gain * l3_pow_43(-q);
                        }
                        k += 1;
                    }
                    pos += w;
                    win += 1;
                }
                sfb += 1;
            }
            while pos < GRANULE_SAMPLES { *freq.add(pos) = 0.0; pos += 1; }
        } else if block_type == 2 && mixed {
            // MIXED BLOCK — long bands 0..7 (lines 0..35 for 44.1/48k; 0..71 for 32k),
            // then short SFBs starting where long bands end.
            // For 32 kHz the spec uses 4 long bands (8 SFBs at this rate produce
            // 4 polyphase subbands × 18 lines = 72 lines); for 44.1/48 it's 2
            // subbands × 18 = 36 lines.
            //
            // We compute "long_sfb_count" = number of long SFBs covered by the
            // mixed long-portion: 8 for 44.1/48, and per minimp3 for 32 kHz
            // the first 4 polyphase subbands cover SFBs 0..11 (72 lines).
            // Look up the actual boundary at line `n_long_lines` to find the
            // matching SFB count.
            let long_table = get_sfb_table(sample_rate);
            let n_long_subbands = if sample_rate == 32000 { 4 } else { 2 };
            let n_long_lines = n_long_subbands * 18;
            // Find long_sfb_count such that long_table[long_sfb_count] == n_long_lines
            let mut long_sfb_count: usize = 0;
            while long_sfb_count < 22 {
                if *long_table.add(long_sfb_count + 1) >= n_long_lines { break; }
                long_sfb_count += 1;
            }
            long_sfb_count += 1; // make it count, not last-index

            // Pass A: long bands 0..long_sfb_count-1
            let mut pos: usize = 0;
            let mut sfb: usize = 0;
            while sfb < long_sfb_count {
                let a = *long_table.add(sfb);
                let b = *long_table.add(sfb + 1);
                let w = b - a;
                let sf_val: i32 = if sfb < 39 { *scf.add(sfb) as i32 } else { 0 };
                // Note: mixed blocks do NOT use preflag (only pure long blocks do).
                let exp_q2 = (sf_val as i32) << scf_shift;
                let band_gain = l3_ldexp_q2(gain_base, exp_q2);
                let mut k: usize = 0;
                while k < w {
                    let q = *is.add(pos + k);
                    if q == 0 {
                        *freq.add(pos + k) = 0.0;
                    } else if q > 0 {
                        *freq.add(pos + k) = band_gain * l3_pow_43(q);
                    } else {
                        *freq.add(pos + k) = -band_gain * l3_pow_43(-q);
                    }
                    k += 1;
                }
                pos += w;
                sfb += 1;
            }

            // Pass B: short SFBs starting at the same line position (`pos`).
            // For 44.1/48k: long covers 36 lines (SFBs 0..7); short SFBs cover
            // remaining 540 lines, indexed sfb_short = 3..12. For 32k: similar but
            // long covers 72 lines.
            //
            // Scalefactor slot mapping for short part in mixed (matches
            // decode_scalefactors): scf[long_sfb_count + (sfb_short - first_short)*3 + win].
            //
            // first_short = sfb index of the first short band beyond the long
            // portion. For 44.1/48k long covers up to line 36 = SFB_SHORT[0..2]*3
            // = 4*3+4*3+4*3 = 36 ✓ — so first_short = 3.
            // For 32k long covers 72 lines = SFB_SHORT[0..5]*3 = 4+4+4+4+6+8 wait
            // let me check: SFB_SHORT_W_32000[0..5] = [4,4,4,4,6,8]. Sum = 30
            // × 3 windows = 90 — doesn't match 72. So 32k mixed doesn't cleanly
            // map this way; minimp3 punts and rebases sfbtab at sfb_short = 3
            // regardless. Match that.
            let widths = get_sfb_short_widths(sample_rate);
            let first_short: usize = 3;
            let mut sfb_short: usize = first_short;
            let mut scf_base: usize = long_sfb_count;
            while sfb_short < 13 {
                let w = *widths.add(sfb_short) as usize;
                if w == 0 { break; }
                let mut win: usize = 0;
                while win < 3 {
                    let scf_slot = scf_base + win;
                    let sf_val: i32 = if scf_slot < 39 { *scf.add(scf_slot) as i32 } else { 0 };
                    let sbg = *subblock_gain.add(win) as i32 * 8;
                    let exp_q2 = ((sf_val as i32) << scf_shift) + sbg;
                    let band_gain = l3_ldexp_q2(gain_base, exp_q2);
                    let mut k: usize = 0;
                    while k < w {
                        if pos + k >= GRANULE_SAMPLES { break; }
                        let q = *is.add(pos + k);
                        if q == 0 {
                            *freq.add(pos + k) = 0.0;
                        } else if q > 0 {
                            *freq.add(pos + k) = band_gain * l3_pow_43(q);
                        } else {
                            *freq.add(pos + k) = -band_gain * l3_pow_43(-q);
                        }
                        k += 1;
                    }
                    pos += w;
                    win += 1;
                }
                scf_base += 3;
                sfb_short += 1;
            }
            while pos < GRANULE_SAMPLES { *freq.add(pos) = 0.0; pos += 1; }
        } else {
            // LONG BLOCK (block_type 0/1/3 with no mixed flag).
            let long_table = get_sfb_table(sample_rate);
            let mut pos: usize = 0;
            let mut sfb: usize = 0;
            while sfb < 22 {
                let a = *long_table.add(sfb);
                let b = *long_table.add(sfb + 1);
                let w = b - a;
                let sf_val: i32 = if sfb < 39 { *scf.add(sfb) as i32 } else { 0 };
                let sf_eff = if preflag && sfb < 21 {
                    sf_val + *PRETAB.as_ptr().add(sfb)
                } else {
                    sf_val
                };
                let exp_q2 = (sf_eff as i32) << scf_shift;
                let band_gain = l3_ldexp_q2(gain_base, exp_q2);
                let mut k: usize = 0;
                while k < w {
                    if pos + k >= GRANULE_SAMPLES { break; }
                    let q = *is.add(pos + k);
                    if q == 0 {
                        *freq.add(pos + k) = 0.0;
                    } else if q > 0 {
                        *freq.add(pos + k) = band_gain * l3_pow_43(q);
                    } else {
                        *freq.add(pos + k) = -band_gain * l3_pow_43(-q);
                    }
                    k += 1;
                }
                pos += w;
                sfb += 1;
            }
            while pos < GRANULE_SAMPLES { *freq.add(pos) = 0.0; pos += 1; }
        }
    }
}

// ============================================================================
// Section 8: MS stereo (just add/subtract; the 1/sqrt(2) is in the gain_exp)
// ============================================================================

fn process_ms_stereo(freq_lines: *mut f32) {
    unsafe {
        let right = freq_lines.add(GRANULE_SAMPLES);
        let mut i: usize = 0;
        while i < GRANULE_SAMPLES {
            let m = *freq_lines.add(i);
            let s = *right.add(i);
            *freq_lines.add(i) = m + s;
            *right.add(i) = m - s;
            i += 1;
        }
    }
}

// ============================================================================
// Section 9: Reorder short blocks (window-interleave at stride 3)
// ============================================================================

/// Reorder short-block spectral values from SFB-sequential to window-interleaved.
/// Uses `scratch` as temporary (must be ≥ 540 f32 / 576 to be safe).
fn reorder_short(grbuf: *mut f32, scratch: *mut f32, sfb_widths: *const u8, nbands_to_reorder: usize) {
    unsafe {
        let mut src = grbuf;
        let mut dst_count: usize = 0;
        let mut wi: usize = 0;
        let mut samples_left = nbands_to_reorder * 18; // safety bound
        loop {
            let len = *sfb_widths.add(wi) as usize;
            if len == 0 { break; }
            if dst_count + 3 * len > samples_left { break; }
            let mut i: usize = 0;
            while i < len {
                *scratch.add(dst_count) = *src.add(i);
                *scratch.add(dst_count + 1) = *src.add(len + i);
                *scratch.add(dst_count + 2) = *src.add(2 * len + i);
                dst_count += 3;
                i += 1;
            }
            src = src.add(3 * len);
            wi += 1;
        }
        let mut i: usize = 0;
        while i < dst_count { *grbuf.add(i) = *scratch.add(i); i += 1; }
    }
}

// ============================================================================
// Section 10: Antialiasing butterflies (ISO 11172-3 §2.4.3.4)
// ============================================================================

// minimp3 g_aa[0] = cs (positive cosine coefs), g_aa[1] = ca (positive sine).
static AA_CS: [f32; 8] = [
    0.85749293, 0.88174200, 0.94962865, 0.98331459, 0.99551782, 0.99916056, 0.99989920, 0.99999316,
];
static AA_CA: [f32; 8] = [
    0.51449576, 0.47173197, 0.31337745, 0.18191320, 0.09457419, 0.04096558, 0.01419856, 0.00369997,
];

fn antialias_butterflies(freq: *mut f32, nbands: usize) {
    // nbands = number of butterfly pairs to perform.
    // Pair n acts on subband seam between subband n and n+1 (lines 17±i, 18+i).
    unsafe {
        let mut sb: usize = 0;
        while sb < nbands {
            let base = sb * 18;
            let mut i: usize = 0;
            while i < 8 {
                let upper_idx = base + 17 - i;  // d in minimp3
                let lower_idx = base + 18 + i;  // u in minimp3
                if lower_idx >= GRANULE_SAMPLES { break; }
                let u = *freq.add(lower_idx);
                let d = *freq.add(upper_idx);
                let cs = *AA_CS.as_ptr().add(i);
                let ca = *AA_CA.as_ptr().add(i);
                *freq.add(lower_idx) = u * cs - d * ca;
                *freq.add(upper_idx) = u * ca + d * cs;
                i += 1;
            }
            sb += 1;
        }
    }
}

// ============================================================================
// Section 11: IMDCT (long-36 and short-12)
// ============================================================================

// minimp3 g_twid9
static G_TWID9: [f32; 18] = [
    0.73727734, 0.79335334, 0.84339145, 0.88701083, 0.92387953, 0.95371695,
    0.97629601, 0.99144486, 0.99904822, 0.67559021, 0.60876143, 0.53729961,
    0.46174861, 0.38268343, 0.30070580, 0.21643961, 0.13052619, 0.04361938,
];

// minimp3 g_mdct_window[0] = long block window
static MDCT_WIN_LONG: [f32; 18] = [
    0.99904822, 0.99144486, 0.97629601, 0.95371695, 0.92387953, 0.88701083,
    0.84339145, 0.79335334, 0.73727734, 0.04361938, 0.13052619, 0.21643961,
    0.30070580, 0.38268343, 0.46174861, 0.53729961, 0.60876143, 0.67559021,
];

// minimp3 g_mdct_window[1] = stop block window (block_type == 3)
static MDCT_WIN_STOP: [f32; 18] = [
    1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    0.99144486, 0.92387953, 0.79335334,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.13052619, 0.38268343, 0.60876143,
];

/// 9-point DCT-III used by IMDCT-36. Mirrors minimp3 L3_dct3_9.
#[inline]
fn l3_dct3_9(y: *mut f32) {
    unsafe {
        let mut s0 = *y.add(0);
        let s2 = *y.add(2);
        let mut s4 = *y.add(4);
        let mut s6 = *y.add(6);
        let mut s8 = *y.add(8);

        let t0 = s0 + s6 * 0.5;
        s0 -= s6;
        let t4 = (s4 + s2) * 0.93969262;
        let t2 = (s8 + s2) * 0.76604444;
        s6 = (s4 - s8) * 0.17364818;
        s4 += s8 - s2;

        let s2_new = s0 - s4 * 0.5;
        *y.add(4) = s4 + s0;
        s8 = t0 - t2 + s6;
        s0 = t0 - t4 + t2;
        s4 = t0 + t4 - s6;

        let s1 = *y.add(1);
        let mut s3 = *y.add(3);
        let s5 = *y.add(5);
        let s7 = *y.add(7);

        s3 *= 0.86602540;
        let t0b = (s5 + s1) * 0.98480775;
        let t4b = (s5 - s7) * 0.34202014;
        let t2b = (s1 + s7) * 0.64278761;
        let s1_new = (s1 - s5 - s7) * 0.86602540;

        let s5_new = t0b - s3 - t2b;
        let s7_new = t4b - s3 - t0b;
        let s3_new = t4b + s3 - t2b;

        *y.add(0) = s4 - s7_new;
        *y.add(1) = s2_new + s1_new;
        *y.add(2) = s0 - s3_new;
        *y.add(3) = s8 + s5_new;
        *y.add(5) = s8 - s5_new;
        *y.add(6) = s0 + s3_new;
        *y.add(7) = s2_new - s1_new;
        *y.add(8) = s4 + s7_new;
    }
}

/// IMDCT-36 with overlap-add and windowing. Mirrors minimp3 L3_imdct36.
fn l3_imdct36(grbuf: *mut f32, overlap: *mut f32, window: *const f32, nbands: usize) {
    unsafe {
        let mut gr = grbuf;
        let mut ov = overlap;
        let mut j: usize = 0;
        while j < nbands {
            let mut co = [0f32; 9];
            let mut si = [0f32; 9];

            *co.as_mut_ptr().add(0) = -(*gr.add(0));
            *si.as_mut_ptr().add(0) = *gr.add(17);
            let mut i: usize = 0;
            while i < 4 {
                let i4 = i << 2;
                *si.as_mut_ptr().add(8 - (i << 1)) = *gr.add(i4 + 1) - *gr.add(i4 + 2);
                *co.as_mut_ptr().add(1 + (i << 1)) = *gr.add(i4 + 1) + *gr.add(i4 + 2);
                *si.as_mut_ptr().add(7 - (i << 1)) = *gr.add(i4 + 4) - *gr.add(i4 + 3);
                *co.as_mut_ptr().add(2 + (i << 1)) = -(*gr.add(i4 + 3) + *gr.add(i4 + 4));
                i += 1;
            }

            l3_dct3_9(co.as_mut_ptr());
            l3_dct3_9(si.as_mut_ptr());

            *si.as_mut_ptr().add(1) = -*si.as_ptr().add(1);
            *si.as_mut_ptr().add(3) = -*si.as_ptr().add(3);
            *si.as_mut_ptr().add(5) = -*si.as_ptr().add(5);
            *si.as_mut_ptr().add(7) = -*si.as_ptr().add(7);

            let twid = G_TWID9.as_ptr();
            let mut i: usize = 0;
            while i < 9 {
                let ovl = *ov.add(i);
                let co_i = *co.as_ptr().add(i);
                let si_i = *si.as_ptr().add(i);
                let sum = co_i * *twid.add(9 + i) + si_i * *twid.add(i);
                *ov.add(i) = co_i * *twid.add(i) - si_i * *twid.add(9 + i);
                *gr.add(i)        = ovl * *window.add(i)         - sum * *window.add(9 + i);
                *gr.add(17 - i)   = ovl * *window.add(9 + i)     + sum * *window.add(i);
                i += 1;
            }

            gr = gr.add(18);
            ov = ov.add(9);
            j += 1;
        }
    }
}

/// 3-point IDCT used by IMDCT-12 (mirrors minimp3 L3_idct3).
#[inline]
fn l3_idct3(x0: f32, x1: f32, x2: f32, dst: *mut f32) {
    unsafe {
        let m1 = x1 * 0.86602540;
        let a1 = x0 - x2 * 0.5;
        *dst.add(1) = x0 + x2;
        *dst.add(0) = a1 + m1;
        *dst.add(2) = a1 - m1;
    }
}

/// IMDCT-12 (one short window). Mirrors minimp3 L3_imdct12. Reads spectral
/// values at indices 0,3,6,9,12,15 (stride 3) of x and writes 6 output samples.
fn l3_imdct12(x: *const f32, dst: *mut f32, overlap: *mut f32) {
    unsafe {
        // minimp3 g_twid3 = {0.79335334, 0.92387953, 0.99144486, 0.60876143, 0.38268343, 0.13052619}
        const TW0: f32 = 0.79335334;
        const TW1: f32 = 0.92387953;
        const TW2: f32 = 0.99144486;
        const TW3: f32 = 0.60876143;
        const TW4: f32 = 0.38268343;
        const TW5: f32 = 0.13052619;

        let mut co = [0f32; 3];
        let mut si = [0f32; 3];

        l3_idct3(-*x.add(0), *x.add(6) + *x.add(3), *x.add(12) + *x.add(9), co.as_mut_ptr());
        l3_idct3(*x.add(15), *x.add(12) - *x.add(9), *x.add(6) - *x.add(3), si.as_mut_ptr());
        *si.as_mut_ptr().add(1) = -*si.as_ptr().add(1);

        let twid = [TW0, TW1, TW2, TW3, TW4, TW5];
        let mut i: usize = 0;
        while i < 3 {
            let ovl = *overlap.add(i);
            let co_i = *co.as_ptr().add(i);
            let si_i = *si.as_ptr().add(i);
            let sum = co_i * *twid.as_ptr().add(3 + i) + si_i * *twid.as_ptr().add(i);
            *overlap.add(i) = co_i * *twid.as_ptr().add(i) - si_i * *twid.as_ptr().add(3 + i);
            *dst.add(i)     = ovl * *twid.as_ptr().add(2 - i) - sum * *twid.as_ptr().add(5 - i);
            *dst.add(5 - i) = ovl * *twid.as_ptr().add(5 - i) + sum * *twid.as_ptr().add(2 - i);
            i += 1;
        }
    }
}

/// IMDCT short for `nbands` subbands. Mirrors minimp3 L3_imdct_short.
fn l3_imdct_short(grbuf: *mut f32, overlap: *mut f32, nbands: usize) {
    unsafe {
        let mut gr = grbuf;
        let mut ov = overlap;
        let mut j: usize = 0;
        while j < nbands {
            let mut tmp = [0f32; 18];
            let mut i: usize = 0;
            while i < 18 { *tmp.as_mut_ptr().add(i) = *gr.add(i); i += 1; }
            // First 6 dst samples are taken from previous granule's overlap[0..5]
            i = 0;
            while i < 6 { *gr.add(i) = *ov.add(i); i += 1; }
            // Three short windows chain through inter-window overlap (ov[6..8]).
            l3_imdct12(tmp.as_ptr(),         gr.add(6),  ov.add(6));
            l3_imdct12(tmp.as_ptr().add(1),  gr.add(12), ov.add(6));
            l3_imdct12(tmp.as_ptr().add(2),  ov,         ov.add(6));
            gr = gr.add(18);
            ov = ov.add(9);
            j += 1;
        }
    }
}

/// Apply IMDCT to one granule (mirrors minimp3 L3_imdct_gr). Long bands first,
/// then short for short/mixed.
fn process_imdct(freq: *mut f32, overlap: *mut f32, block_type: u8, n_long_bands: usize) {
    unsafe {
        if n_long_bands > 0 {
            l3_imdct36(freq, overlap, MDCT_WIN_LONG.as_ptr(), n_long_bands);
        }
        let remaining = SUBBANDS - n_long_bands;
        if remaining == 0 { return; }
        let gr2 = freq.add(18 * n_long_bands);
        let ov2 = overlap.add(9 * n_long_bands);
        if block_type == 2 {
            l3_imdct_short(gr2, ov2, remaining);
        } else if block_type == 3 {
            l3_imdct36(gr2, ov2, MDCT_WIN_STOP.as_ptr(), remaining);
        } else {
            // block_type 0 or 1 (start). Both use the long window.
            l3_imdct36(gr2, ov2, MDCT_WIN_LONG.as_ptr(), remaining);
        }
    }
}

/// L3_change_sign — negate every other sample of every other band, starting
/// from band 1 sample 1. Required by the polyphase synthesis filterbank.
fn l3_change_sign(grbuf: *mut f32) {
    unsafe {
        let mut b: usize = 1;
        while b < 32 {
            let base = b * 18;
            let mut i: usize = 1;
            while i < 18 {
                *grbuf.add(base + i) = -*grbuf.add(base + i);
                i += 2;
            }
            b += 2;
        }
    }
}

// ============================================================================
// Section 12: Synthesis filterbank (mirrors minimp3 mp3d_DCT_II / mp3d_synth*)
// ============================================================================

static G_SEC: [f32; 24] = [
    10.19000816, 0.50060302, 0.50241929, 3.40760851, 0.50547093, 0.52249861,
    2.05778098,  0.51544732, 0.56694406, 1.48416460, 0.53104258, 0.64682180,
    1.16943991,  0.55310392, 0.78815460, 0.97256821, 0.58293498, 1.06067765,
    0.83934963,  0.62250412, 1.72244716, 0.74453628, 0.67480832, 5.10114861,
];

#[rustfmt::skip]
static G_WIN_SYNTH: [f32; 240] = [
    -1.0,26.0,-31.0,208.0,218.0,401.0,-519.0,2063.0,2000.0,4788.0,-5517.0,7134.0,5959.0,35640.0,-39336.0,74992.0,
    -1.0,24.0,-35.0,202.0,222.0,347.0,-581.0,2080.0,1952.0,4425.0,-5879.0,7640.0,5288.0,33791.0,-41176.0,74856.0,
    -1.0,21.0,-38.0,196.0,225.0,294.0,-645.0,2087.0,1893.0,4063.0,-6237.0,8092.0,4561.0,31947.0,-43006.0,74630.0,
    -1.0,19.0,-41.0,190.0,227.0,244.0,-711.0,2085.0,1822.0,3705.0,-6589.0,8492.0,3776.0,30112.0,-44821.0,74313.0,
    -1.0,17.0,-45.0,183.0,228.0,197.0,-779.0,2075.0,1739.0,3351.0,-6935.0,8840.0,2935.0,28289.0,-46617.0,73908.0,
    -1.0,16.0,-49.0,176.0,228.0,153.0,-848.0,2057.0,1644.0,3004.0,-7271.0,9139.0,2037.0,26482.0,-48390.0,73415.0,
    -2.0,14.0,-53.0,169.0,227.0,111.0,-919.0,2032.0,1535.0,2663.0,-7597.0,9389.0,1082.0,24694.0,-50137.0,72835.0,
    -2.0,13.0,-58.0,161.0,224.0,72.0,-991.0,2001.0,1414.0,2330.0,-7910.0,9592.0,70.0,22929.0,-51853.0,72169.0,
    -2.0,11.0,-63.0,154.0,221.0,36.0,-1064.0,1962.0,1280.0,2006.0,-8209.0,9750.0,-998.0,21189.0,-53534.0,71420.0,
    -2.0,10.0,-68.0,147.0,215.0,2.0,-1137.0,1919.0,1131.0,1692.0,-8491.0,9863.0,-2122.0,19478.0,-55178.0,70590.0,
    -3.0,9.0,-73.0,139.0,208.0,-29.0,-1210.0,1870.0,970.0,1388.0,-8755.0,9935.0,-3300.0,17799.0,-56778.0,69679.0,
    -3.0,8.0,-79.0,132.0,200.0,-57.0,-1283.0,1817.0,794.0,1095.0,-8998.0,9966.0,-4533.0,16155.0,-58333.0,68692.0,
    -4.0,7.0,-85.0,125.0,189.0,-83.0,-1356.0,1759.0,605.0,814.0,-9219.0,9959.0,-5818.0,14548.0,-59838.0,67629.0,
    -4.0,7.0,-91.0,117.0,177.0,-106.0,-1428.0,1698.0,402.0,545.0,-9416.0,9916.0,-7154.0,12980.0,-61289.0,66494.0,
    -5.0,6.0,-97.0,111.0,163.0,-127.0,-1498.0,1634.0,185.0,288.0,-9585.0,9838.0,-8540.0,11455.0,-62684.0,65290.0,
];

/// DCT-II on grbuf (in-place). Mirrors minimp3 mp3d_DCT_II non-SIMD path.
fn mp3d_dct_ii(grbuf: *mut f32, n: usize) {
    unsafe {
        let mut k: usize = 0;
        while k < n {
            let y = grbuf.add(k);
            // t is [4][8]: 4 rows × 8 cols of f32 (after restructure).
            let mut t = [[0f32; 8]; 4];

            let mut i: usize = 0;
            while i < 8 {
                let x0 = *y.add(i * 18);
                let x1 = *y.add((15 - i) * 18);
                let x2 = *y.add((16 + i) * 18);
                let x3 = *y.add((31 - i) * 18);
                let t0 = x0 + x3;
                let t1 = x1 + x2;
                let t2 = (x1 - x2) * *G_SEC.as_ptr().add(3 * i + 0);
                let t3 = (x0 - x3) * *G_SEC.as_ptr().add(3 * i + 1);
                t[0][i] = t0 + t1;
                t[1][i] = (t0 - t1) * *G_SEC.as_ptr().add(3 * i + 2);
                t[2][i] = t3 + t2;
                t[3][i] = (t3 - t2) * *G_SEC.as_ptr().add(3 * i + 2);
                i += 1;
            }

            // 4 rounds of butterflies, one per row "block" of 8 values.
            let mut row: usize = 0;
            while row < 4 {
                let x = &mut t[row];
                let mut x0 = x[0]; let mut x1 = x[1]; let mut x2 = x[2]; let mut x3 = x[3];
                let mut x4 = x[4]; let mut x5 = x[5]; let mut x6 = x[6]; let mut x7 = x[7];
                let mut xt;
                xt = x0 - x7; x0 += x7;
                x7 = x1 - x6; x1 += x6;
                x6 = x2 - x5; x2 += x5;
                x5 = x3 - x4; x3 += x4;
                x4 = x0 - x3; x0 += x3;
                x3 = x1 - x2; x1 += x2;
                x[0] = x0 + x1;
                x[4] = (x0 - x1) * 0.70710677;
                x5 = x5 + x6;
                x6 = (x6 + x7) * 0.70710677;
                x7 = x7 + xt;
                x3 = (x3 + x4) * 0.70710677;
                x5 = x5 - x7 * 0.198912367; // rotate by PI/8
                x7 = x7 + x5 * 0.382683432;
                x5 = x5 - x7 * 0.198912367;
                let x0b = xt - x6;
                xt = xt + x6;
                x[1] = (xt + x7) * 0.50979561;
                x[2] = (x4 + x3) * 0.54119611;
                x[3] = (x0b - x5) * 0.60134488;
                x[5] = (x0b + x5) * 0.89997619;
                x[6] = (x4 - x3) * 1.30656302;
                x[7] = (xt - x7) * 2.56291556;
                row += 1;
            }

            // Write back in the bit-reversed layout minimp3 uses.
            let mut yp = y;
            let mut i: usize = 0;
            while i < 7 {
                *yp.add(0 * 18) = t[0][i];
                *yp.add(1 * 18) = t[2][i] + t[3][i] + t[3][i + 1];
                *yp.add(2 * 18) = t[1][i] + t[1][i + 1];
                *yp.add(3 * 18) = t[2][i + 1] + t[3][i] + t[3][i + 1];
                yp = yp.add(4 * 18);
                i += 1;
            }
            *yp.add(0 * 18) = t[0][7];
            *yp.add(1 * 18) = t[2][7] + t[3][7];
            *yp.add(2 * 18) = t[1][7];
            *yp.add(3 * 18) = t[3][7];

            k += 1;
        }
    }
}

#[inline]
fn mp3d_scale_pcm(sample: f32) -> i16 {
    // minimp3 "away from zero" rounding to int16.
    if sample >= 32766.5 { return 32767; }
    if sample <= -32767.5 { return -32768; }
    let s = (sample + 0.5) as i32;
    // minimp3 does `s -= (s < 0)` — only subtract from values already
    // truncated to a negative int, not based on the float sign.
    let s = if s < 0 { s - 1 } else { s };
    s as i16
}

fn mp3d_synth_pair(pcm: *mut i16, nch: usize, z: *const f32) {
    unsafe {
        let mut a: f32;
        a  = (*z.add(14 * 64) - *z.add(0))             * 29.0;
        a += (*z.add( 1 * 64) + *z.add(13 * 64))       * 213.0;
        a += (*z.add(12 * 64) - *z.add( 2 * 64))       * 459.0;
        a += (*z.add( 3 * 64) + *z.add(11 * 64))       * 2037.0;
        a += (*z.add(10 * 64) - *z.add( 4 * 64))       * 5153.0;
        a += (*z.add( 5 * 64) + *z.add( 9 * 64))       * 6574.0;
        a += (*z.add( 8 * 64) - *z.add( 6 * 64))       * 37489.0;
        a +=  *z.add( 7 * 64)                          * 75038.0;
        *pcm = mp3d_scale_pcm(a);

        let z2 = z.add(2);
        a  = *z2.add(14 * 64) * 104.0;
        a += *z2.add(12 * 64) * 1567.0;
        a += *z2.add(10 * 64) * 9727.0;
        a += *z2.add( 8 * 64) * 64019.0;
        a += *z2.add( 6 * 64) * -9975.0;
        a += *z2.add( 4 * 64) * -45.0;
        a += *z2.add( 2 * 64) * 146.0;
        a += *z2.add( 0 * 64) * -5.0;
        *pcm.add(16 * nch) = mp3d_scale_pcm(a);
    }
}

fn mp3d_synth(xl: *mut f32, dstl: *mut i16, nch: usize, lins: *mut f32) {
    unsafe {
        let xr = xl.add(576 * (nch - 1));
        let dstr = dstl.add(nch - 1);
        let zlin = lins.add(15 * 64);
        let w = G_WIN_SYNTH.as_ptr();

        *zlin.add(4*15)     = *xl.add(18 * 16);
        *zlin.add(4*15 + 1) = *xr.add(18 * 16);
        *zlin.add(4*15 + 2) = *xl;
        *zlin.add(4*15 + 3) = *xr;
        *zlin.add(4*31)     = *xl.add(1 + 18 * 16);
        *zlin.add(4*31 + 1) = *xr.add(1 + 18 * 16);
        *zlin.add(4*31 + 2) = *xl.add(1);
        *zlin.add(4*31 + 3) = *xr.add(1);

        mp3d_synth_pair(dstr, nch, lins.add(4 * 15 + 1));
        mp3d_synth_pair(dstr.add(32 * nch), nch, lins.add(4 * 15 + 64 + 1));
        mp3d_synth_pair(dstl, nch, lins.add(4 * 15));
        mp3d_synth_pair(dstl.add(32 * nch), nch, lins.add(4 * 15 + 64));

        let mut i: isize = 14;
        let mut wp = w; // walking pointer into G_WIN_SYNTH
        while i >= 0 {
            let iu = i as usize;
            *zlin.add(4 * iu)         = *xl.add(18 * (31 - iu));
            *zlin.add(4 * iu + 1)     = *xr.add(18 * (31 - iu));
            *zlin.add(4 * iu + 2)     = *xl.add(1 + 18 * (31 - iu));
            *zlin.add(4 * iu + 3)     = *xr.add(1 + 18 * (31 - iu));
            *zlin.add(4 * (iu + 16))      = *xl.add(1 + 18 * (1 + iu));
            *zlin.add(4 * (iu + 16) + 1)  = *xr.add(1 + 18 * (1 + iu));
            *zlin.offset(4 * (i - 16) + 2) = *xl.add(18 * (1 + iu));
            *zlin.offset(4 * (i - 16) + 3) = *xr.add(18 * (1 + iu));

            let mut a = [0f32; 4];
            let mut b = [0f32; 4];

            // 8 unrolled stages (S0, S2, S1, S2, S1, S2, S1, S2)
            macro_rules! load_k {
                ($k:expr) => {{
                    let w0 = *wp; let w1 = *wp.add(1);
                    let vz = zlin.offset(4 * i - ($k as isize) * 64);
                    let vy = zlin.offset(4 * i - (15 - $k as isize) * 64);
                    wp = wp.add(2);
                    (w0, w1, vz, vy)
                }};
            }

            // S0(0): initial assign (b = vz*w1 + vy*w0, a = vz*w0 - vy*w1)
            {
                let (w0, w1, vz, vy) = load_k!(0);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] = vzj * w1 + vyj * w0;
                    a[j] = vzj * w0 - vyj * w1;
                    j += 1;
                }
            }
            // S2(1): b += vz*w1 + vy*w0; a += vy*w1 - vz*w0
            {
                let (w0, w1, vz, vy) = load_k!(1);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] += vzj * w1 + vyj * w0;
                    a[j] += vyj * w1 - vzj * w0;
                    j += 1;
                }
            }
            // S1(2): b += vz*w1 + vy*w0; a += vz*w0 - vy*w1
            {
                let (w0, w1, vz, vy) = load_k!(2);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] += vzj * w1 + vyj * w0;
                    a[j] += vzj * w0 - vyj * w1;
                    j += 1;
                }
            }
            // S2(3)
            {
                let (w0, w1, vz, vy) = load_k!(3);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] += vzj * w1 + vyj * w0;
                    a[j] += vyj * w1 - vzj * w0;
                    j += 1;
                }
            }
            // S1(4)
            {
                let (w0, w1, vz, vy) = load_k!(4);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] += vzj * w1 + vyj * w0;
                    a[j] += vzj * w0 - vyj * w1;
                    j += 1;
                }
            }
            // S2(5)
            {
                let (w0, w1, vz, vy) = load_k!(5);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] += vzj * w1 + vyj * w0;
                    a[j] += vyj * w1 - vzj * w0;
                    j += 1;
                }
            }
            // S1(6)
            {
                let (w0, w1, vz, vy) = load_k!(6);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] += vzj * w1 + vyj * w0;
                    a[j] += vzj * w0 - vyj * w1;
                    j += 1;
                }
            }
            // S2(7)
            {
                let (w0, w1, vz, vy) = load_k!(7);
                let mut j: usize = 0;
                while j < 4 {
                    let vzj = *vz.add(j);
                    let vyj = *vy.add(j);
                    b[j] += vzj * w1 + vyj * w0;
                    a[j] += vyj * w1 - vzj * w0;
                    j += 1;
                }
            }

            *dstr.add((15 - iu) * nch) = mp3d_scale_pcm(a[1]);
            *dstr.add((17 + iu) * nch) = mp3d_scale_pcm(b[1]);
            *dstl.add((15 - iu) * nch) = mp3d_scale_pcm(a[0]);
            *dstl.add((17 + iu) * nch) = mp3d_scale_pcm(b[0]);
            *dstr.add((47 - iu) * nch) = mp3d_scale_pcm(a[3]);
            *dstr.add((49 + iu) * nch) = mp3d_scale_pcm(b[3]);
            *dstl.add((47 - iu) * nch) = mp3d_scale_pcm(a[2]);
            *dstl.add((49 + iu) * nch) = mp3d_scale_pcm(b[2]);

            i -= 1;
        }
    }
}

fn mp3d_synth_granule(
    qmf_state: *mut f32,
    grbuf: *mut f32,
    nbands: usize,
    nch: usize,
    pcm: *mut i16,
    lins: *mut f32,
) {
    unsafe {
        let mut ch: usize = 0;
        while ch < nch {
            mp3d_dct_ii(grbuf.add(576 * ch), nbands);
            ch += 1;
        }

        let mut idx: usize = 0;
        while idx < 15 * 64 { *lins.add(idx) = *qmf_state.add(idx); idx += 1; }

        let mut i: usize = 0;
        while i < nbands {
            mp3d_synth(grbuf.add(i), pcm.add(32 * nch * i), nch, lins.add(i * 64));
            i += 2;
        }

        if nch == 1 {
            let mut k: usize = 0;
            while k < 15 * 64 {
                *qmf_state.add(k) = *lins.add(nbands * 64 + k);
                k += 2;
            }
        } else {
            let mut k: usize = 0;
            while k < 15 * 64 { *qmf_state.add(k) = *lins.add(nbands * 64 + k); k += 1; }
        }
    }
}

// ============================================================================
// Section 13: Mp3State struct + helpers
// ============================================================================

#[repr(C)]
pub struct Mp3State {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pending_out: u16,
    pending_offset: u16,
    io_buf: [u8; IO_BUF_SIZE],
    io_buf_out: [u8; IO_BUF_SIZE],

    // Frame accumulation
    frame_buf: [u8; 1500],
    frame_pos: usize,
    frame_size: usize,

    // Audio info
    sample_rate: u32,
    channels: u8,
    channel_mode: u8,
    mode_extension: u8,
    has_crc: u8,

    // State machine
    phase: Mp3Phase,
    id3_skip: u32,

    // Side info
    si_main_data_begin: u16,
    si_private_bits: u8,
    si_scfsi: [u8; 8],

    // Granule info: [gr][ch] flattened
    gi_part2_3_length: [u16; 4],
    gi_big_values: [u16; 4],
    gi_global_gain: [u8; 4],
    gi_scalefac_compress: [u8; 4],
    gi_window_switching: [u8; 4],
    gi_block_type: [u8; 4],
    gi_mixed_block: [u8; 4],
    gi_table_select: [u8; 12],
    gi_subblock_gain: [u8; 12],
    gi_region0_count: [u8; 4],
    gi_region1_count: [u8; 4],
    gi_preflag: [u8; 4],
    gi_scalefac_scale: [u8; 4],
    gi_count1table_select: [u8; 4],

    // Scalefactors: [2 granules][2 channels][39 bands] flattened = 156
    scalefactors: [u8; 156],

    // Huffman decoded integer values (per granule/channel, reused)
    huff_values: [i32; 576],

    // Frequency lines after requantization: [2 channels][576] flattened (f32)
    freq_lines: [f32; 1152],

    // IMDCT overlap buffer: [2 channels][32 subbands × 9] = [2][288] = 576 f32
    overlap: [f32; 576],

    // Synthesis QMF history (shared across channels in mp3d_synth interleave)
    qmf_state: [f32; 960],
    // Synthesis working buffer: (18+15)*64 = 2112 f32
    lins: [f32; 2112],

    // Output buffer: stereo interleaved
    out_buf: [i16; 2304],
    out_pos: u16,
    out_len: u16,

    frame_count: u32,

    // Bit reservoir
    main_data: [u8; 2048],
    main_data_len: u16,
    main_data_bit_pos: u16,
    reservoir: [u8; 512],
    reservoir_len: u16,

    last_sent_rate: u32,
    underrun_count: u32,
}

#[inline(always)]
fn gi_idx(gr: usize, ch: usize) -> usize { gr * 2 + ch }

#[inline(always)]
fn sf_idx(gr: usize, ch: usize, band: usize) -> usize { gr * 78 + ch * 39 + band }

// ============================================================================
// Section 13b: Layer probe (compile-time gated; off in shipped builds)
//
// Set MP3_PROBE=1 at codec build time to emit [probe] dev_log lines that
// dump per-granule layer state at each MP3 pipeline boundary. The harness
// (.context/mp3_bisect/probe_mp3.py) parses these against a minimp3
// ground-truth dump (.context/mp3_bisect/minimp3_layers; build via
// `make minimp3-ref`) to locate the first layer / first frame where
// our codec disagrees with the reference. The bisection toolchain is
// gitignored under .context/ — see .context/mp3_bisect/README.md.
// ============================================================================

// Compile-time gate: `MP3_PROBE=1 make modules TARGET=bcm2712` enables.
// Default off — zero cost when unset.
const MP3_PROBE: bool = option_env!("MP3_PROBE").is_some();
const MP3_PROBE_FRAME_LO: u32 = 0;
const MP3_PROBE_FRAME_HI: u32 = 200;

#[inline]
fn probe_active(frame_count: u32) -> bool {
    MP3_PROBE && frame_count >= MP3_PROBE_FRAME_LO && frame_count <= MP3_PROBE_FRAME_HI
}

/// Float-to-decimal with 6 significant digits, sign + dot. Avoids float
/// formatting deps; used only in probe build.
unsafe fn fmt_f32_probe(dst: *mut u8, val: f32) -> usize {
    if val.is_nan() {
        *dst = b'N'; *dst.add(1) = b'a'; *dst.add(2) = b'N';
        return 3;
    }
    let mut p = 0usize;
    let mut v = val;
    if v < 0.0 { *dst.add(p) = b'-'; p += 1; v = -v; }
    if v == 0.0 { *dst.add(p) = b'0'; return p + 1; }
    // Find exponent
    let mut exp: i32 = 0;
    let mut mant = v;
    while mant >= 10.0 { mant /= 10.0; exp += 1; }
    while mant < 1.0  { mant *= 10.0; exp -= 1; }
    // Emit 6 digits with decimal point after the first digit, then 'e' + exp
    let mut digits = [0u8; 7];
    let mut m = mant;
    for i in 0..7 {
        let d = m as u32;
        digits[i] = b'0' + (d as u8 % 10);
        m = (m - d as f32) * 10.0;
    }
    *dst.add(p) = digits[0]; p += 1;
    *dst.add(p) = b'.'; p += 1;
    for i in 1..7 { *dst.add(p) = digits[i]; p += 1; }
    *dst.add(p) = b'e'; p += 1;
    if exp < 0 { *dst.add(p) = b'-'; p += 1; }
    p += fmt_u32_raw(dst.add(p), exp.unsigned_abs());
    p
}

/// Emit one probe line. tag is at most 6 chars.
unsafe fn probe_emit(
    sys: &SyscallTable,
    tag: &[u8],
    frame: u32,
    gr: u8, ch: u8,
    head_label: &[u8],
    head_val: i32,
    floats: *const f32,
    n_floats: usize,
) {
    let mut buf = [0u8; 256];
    let bp = buf.as_mut_ptr();
    let mut p = 0usize;
    // tag (left-padded with spaces, fixed 6 chars)
    let mut t = 0;
    while t < tag.len() && t < 6 { *bp.add(p) = tag[t]; p += 1; t += 1; }
    while p < 6 { *bp.add(p) = b' '; p += 1; }
    *bp.add(p) = b' '; p += 1;
    *bp.add(p) = b'f'; p += 1;
    p += fmt_u32_raw(bp.add(p), frame);
    *bp.add(p) = b' '; p += 1;
    *bp.add(p) = b'g'; p += 1;
    p += fmt_u32_raw(bp.add(p), gr as u32);
    *bp.add(p) = b' '; p += 1;
    *bp.add(p) = b'c'; p += 1;
    p += fmt_u32_raw(bp.add(p), ch as u32);
    if !head_label.is_empty() {
        *bp.add(p) = b' '; p += 1;
        let mut k = 0; while k < head_label.len() { *bp.add(p) = head_label[k]; p += 1; k += 1; }
        p += fmt_u32_raw(bp.add(p), head_val as u32);
    }
    if !floats.is_null() && n_floats > 0 {
        let mut i = 0usize;
        while i < n_floats && p + 16 < 256 {
            *bp.add(p) = b' '; p += 1;
            p += fmt_f32_probe(bp.add(p), *floats.add(i));
            i += 1;
        }
    }
    dev_log(sys, 3, bp, p);
}

// ============================================================================
// Section 14: Frame decoder
// ============================================================================

fn decode_frame(s: &mut Mp3State) -> i32 {
    unsafe {
        let frame_ptr = s.frame_buf.as_ptr();
        let frame_len = s.frame_pos;

        let data_start = 4 + if s.has_crc != 0 { 2usize } else { 0 };
        let side_info_size = if s.channels == 1 { 17usize } else { 32 };

        if frame_len < data_start + side_info_size { return -6; }

        let si_ret = parse_side_info(s, frame_ptr.add(data_start), side_info_size);
        if si_ret < 0 { return si_ret; }

        let frame_data_start = data_start + side_info_size;
        let frame_data_len = if frame_len > frame_data_start { frame_len - frame_data_start } else { 0 };
        accumulate_main_data(s, frame_ptr.add(frame_data_start), frame_data_len);

        let keep = s.si_main_data_begin as usize;
        let main_data_start = if keep + frame_data_len <= s.main_data_len as usize {
            s.main_data_len as usize - keep - frame_data_len
        } else {
            0
        };
        s.main_data_bit_pos = (main_data_start * 8) as u16;

        let num_channels = s.channels as usize;
        let num_granules: usize = 2;
        let ms_stereo = s.channel_mode == 1 && (s.mode_extension & 0x02) != 0;

        let mut gr: usize = 0;
        while gr < num_granules {
            let mut ch: usize = 0;
            while ch < num_channels {
                let ret = decode_granule_channel(s, gr, ch, ms_stereo);
                if ret < 0 { return ret; }
                if probe_active(s.frame_count) {
                    let sys = &*s.syscalls;
                    let idx = gi_idx(gr, ch);
                    // side-info probe (compact)
                    probe_emit(sys, b"side", s.frame_count, gr as u8, ch as u8,
                        b"bt=", *s.gi_block_type.as_ptr().add(idx) as i32,
                        core::ptr::null(), 0);
                    probe_emit(sys, b"side2", s.frame_count, gr as u8, ch as u8,
                        b"big=", *s.gi_big_values.as_ptr().add(idx) as i32,
                        core::ptr::null(), 0);
                    probe_emit(sys, b"side3", s.frame_count, gr as u8, ch as u8,
                        b"gg=", *s.gi_global_gain.as_ptr().add(idx) as i32,
                        core::ptr::null(), 0);
                    probe_emit(sys, b"side4", s.frame_count, gr as u8, ch as u8,
                        b"p23=", *s.gi_part2_3_length.as_ptr().add(idx) as i32,
                        core::ptr::null(), 0);
                    let fl_probe = s.freq_lines.as_ptr().add(ch * GRANULE_SAMPLES);
                    probe_emit(sys, b"reqz", s.frame_count, gr as u8, ch as u8,
                        b"", 0, fl_probe, 16);
                }
                ch += 1;
            }

            // Joint stereo: MS first, then intensity (if needed). For cmajor.mp3
            // there's no intensity-stereo content; we leave the placeholder.
            if num_channels == 2 && s.channel_mode == 1 {
                if (s.mode_extension & 0x02) != 0 {
                    process_ms_stereo(s.freq_lines.as_mut_ptr());
                }
                // Intensity stereo NYI (lame/most encoders use MS for non-extreme
                // content; cmajor.mp3 uses MS). If a stream needs IS, this is the
                // hook point.
            }

            // Antialias + reorder + IMDCT + change_sign per channel
            ch = 0;
            while ch < num_channels {
                let idx = gi_idx(gr, ch);
                let bt = *s.gi_block_type.as_ptr().add(idx);
                let mb = *s.gi_mixed_block.as_ptr().add(idx) != 0;

                let fl = s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES);

                if probe_active(s.frame_count) {
                    let sys = &*s.syscalls;
                    probe_emit(sys, b"reqms", s.frame_count, gr as u8, ch as u8,
                        b"", 0, fl, 16);
                }

                // n_long_bands: subbands at granule start that use LONG-block
                // IMDCT (matching minimp3 L3_decode). Only mixed short blocks
                // need this > 0; everything else (pure long/start/stop/short)
                // lets process_imdct's else-branch handle all 32 subbands with
                // the appropriate window. Treating bt != 2 as "n_long_bands=32"
                // would wrongly force LONG window for STOP blocks.
                let n_long_bands: usize = if bt == 2 && mb {
                    if s.sample_rate == 32000 { 4 } else { 2 }
                } else {
                    0
                };

                // Antialias (matches minimp3): default 31 seams for long-like
                // blocks; for short/mixed blocks limit to n_long_bands - 1 so
                // we never butterfly across the long→short seam.
                let aa_bands = if bt == 2 {
                    if n_long_bands == 0 { 0 } else { n_long_bands - 1 }
                } else {
                    31
                };
                if aa_bands > 0 {
                    antialias_butterflies(fl, aa_bands);
                }

                // Reorder short-block portion (window-interleave).
                if bt == 2 {
                    let widths_ptr = get_sfb_short_widths(s.sample_rate);
                    let scratch = s.huff_values.as_mut_ptr() as *mut f32;
                    let short_start = fl.add(n_long_bands * 18);
                    let nbands_short = 32 - n_long_bands;
                    reorder_short(short_start, scratch, widths_ptr, nbands_short);
                }

                if probe_active(s.frame_count) {
                    let sys = &*s.syscalls;
                    probe_emit(sys, b"aaaz", s.frame_count, gr as u8, ch as u8,
                        b"", 0, fl, 16);
                    // Also dump samples from band 1 (post-antialias seams visible here)
                    probe_emit(sys, b"aaaz1", s.frame_count, gr as u8, ch as u8,
                        b"", 0, fl.add(18), 16);
                }

                // IMDCT (handles long+short split internally based on n_long_bands).
                process_imdct(fl, s.overlap.as_mut_ptr().add(ch * 288), bt, n_long_bands);

                // L3_change_sign: required for polyphase synthesis.
                l3_change_sign(fl);

                if probe_active(s.frame_count) {
                    let sys = &*s.syscalls;
                    probe_emit(sys, b"imdct", s.frame_count, gr as u8, ch as u8,
                        b"", 0, fl, 16);
                    // Band 1 region — exposes change_sign flips
                    probe_emit(sys, b"imdct1", s.frame_count, gr as u8, ch as u8,
                        b"", 0, fl.add(18), 16);
                    // Band 11 region — exposes deeper synthesis state
                    probe_emit(sys, b"imdct11", s.frame_count, gr as u8, ch as u8,
                        b"", 0, fl.add(198), 16);
                }

                ch += 1;
            }

            // Synthesis: emits 18 polyphase output blocks × 32 samples × nch.
            let output_offset = gr * GRANULE_SAMPLES * num_channels;
            mp3d_synth_granule(
                s.qmf_state.as_mut_ptr(),
                s.freq_lines.as_mut_ptr(),
                18,
                num_channels,
                s.out_buf.as_mut_ptr().add(output_offset),
                s.lins.as_mut_ptr(),
            );

            if probe_active(s.frame_count) {
                let sys = &*s.syscalls;
                // Dump PCM samples at 3 strategic offsets in this granule.
                let mut pcm_buf = [0u8; 256];
                let bp = pcm_buf.as_mut_ptr();
                let nch = num_channels;
                let emit_at = |bp: *mut u8, label: &[u8], gr_val: usize, sample_off: usize| -> usize {
                    let mut p = 0usize;
                    let mut t = 0; while t < label.len() && p < 6 { unsafe { *bp.add(p) = label[t]; } p += 1; t += 1; }
                    while p < 6 { unsafe { *bp.add(p) = b' '; } p += 1; }
                    unsafe { *bp.add(p) = b' '; } p += 1;
                    unsafe { *bp.add(p) = b'f'; } p += 1;
                    p += unsafe { fmt_u32_raw(bp.add(p), s.frame_count) };
                    unsafe { *bp.add(p) = b' '; } p += 1;
                    unsafe { *bp.add(p) = b'g'; } p += 1;
                    p += unsafe { fmt_u32_raw(bp.add(p), gr_val as u32) };
                    let mut k = 0;
                    while k < 16 {
                        unsafe { *bp.add(p) = b' '; } p += 1;
                        let sample = unsafe { *s.out_buf.as_ptr().add(output_offset + (sample_off + k) * nch) };
                        p += unsafe { fmt_i16_raw(bp.add(p), sample) };
                        k += 1;
                    }
                    p
                };

                // sample 0 (head of granule)
                let p = emit_at(bp, b"pcmL", gr, 0);
                dev_log(sys, 3, bp, p);
                // sample 248 (middle of granule)
                let p = emit_at(bp, b"pcm248", gr, 248);
                dev_log(sys, 3, bp, p);
                // sample 448 (where bin diverges from minimp3 at frame 0)
                let p = emit_at(bp, b"pcm448", gr, 448);
                dev_log(sys, 3, bp, p);
                // sample 560 (near end of granule)
                let p = emit_at(bp, b"pcm560", gr, 560);
                dev_log(sys, 3, bp, p);
            }

            gr += 1;
        }

        // Mono → stereo expansion (interleave)
        if num_channels == 1 {
            let mut i: usize = SAMPLES_PER_FRAME;
            while i > 0 {
                i -= 1;
                let mono = *s.out_buf.as_ptr().add(i);
                let st_idx = i * 2;
                *s.out_buf.as_mut_ptr().add(st_idx) = mono;
                *s.out_buf.as_mut_ptr().add(st_idx + 1) = mono;
            }
        }

        (SAMPLES_PER_FRAME * 2) as i32
    }
}

fn parse_side_info(s: &mut Mp3State, data: *const u8, len: usize) -> i32 {
    unsafe {
        let mut reader = br_new(data, len);
        let num_channels = s.channels as usize;

        let mdb = br_read_bits(&mut reader, 9);
        if mdb < 0 { return -6; }
        s.si_main_data_begin = mdb as u16;

        if num_channels == 1 {
            let pb = br_read_bits(&mut reader, 5);
            if pb < 0 { return -6; }
            s.si_private_bits = pb as u8;
        } else {
            let pb = br_read_bits(&mut reader, 3);
            if pb < 0 { return -6; }
            s.si_private_bits = pb as u8;
        }

        let mut ch: usize = 0;
        while ch < num_channels {
            let mut band: usize = 0;
            while band < 4 {
                let bit = br_read_bit(&mut reader);
                if bit < 0 { return -6; }
                *s.si_scfsi.as_mut_ptr().add(ch * 4 + band) = bit as u8;
                band += 1;
            }
            ch += 1;
        }

        let mut gr: usize = 0;
        while gr < 2 {
            ch = 0;
            while ch < num_channels {
                let idx = gi_idx(gr, ch);

                let v = br_read_bits(&mut reader, 12); if v < 0 { return -6; }
                *s.gi_part2_3_length.as_mut_ptr().add(idx) = v as u16;

                let v = br_read_bits(&mut reader, 9); if v < 0 { return -6; }
                *s.gi_big_values.as_mut_ptr().add(idx) = v as u16;

                let v = br_read_bits(&mut reader, 8); if v < 0 { return -6; }
                *s.gi_global_gain.as_mut_ptr().add(idx) = v as u8;

                let v = br_read_bits(&mut reader, 4); if v < 0 { return -6; }
                *s.gi_scalefac_compress.as_mut_ptr().add(idx) = v as u8;

                let v = br_read_bit(&mut reader); if v < 0 { return -6; }
                *s.gi_window_switching.as_mut_ptr().add(idx) = v as u8;

                if v != 0 {
                    let bt = br_read_bits(&mut reader, 2); if bt < 0 { return -6; }
                    *s.gi_block_type.as_mut_ptr().add(idx) = bt as u8;

                    let mb = br_read_bit(&mut reader); if mb < 0 { return -6; }
                    *s.gi_mixed_block.as_mut_ptr().add(idx) = mb as u8;

                    let ts0 = br_read_bits(&mut reader, 5); if ts0 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3) = ts0 as u8;
                    let ts1 = br_read_bits(&mut reader, 5); if ts1 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 1) = ts1 as u8;
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 2) = 0;

                    let sg0 = br_read_bits(&mut reader, 3); if sg0 < 0 { return -6; }
                    *s.gi_subblock_gain.as_mut_ptr().add(idx * 3) = sg0 as u8;
                    let sg1 = br_read_bits(&mut reader, 3); if sg1 < 0 { return -6; }
                    *s.gi_subblock_gain.as_mut_ptr().add(idx * 3 + 1) = sg1 as u8;
                    let sg2 = br_read_bits(&mut reader, 3); if sg2 < 0 { return -6; }
                    *s.gi_subblock_gain.as_mut_ptr().add(idx * 3 + 2) = sg2 as u8;

                    if bt as u8 == 2 && mb == 0 {
                        *s.gi_region0_count.as_mut_ptr().add(idx) = 8;
                    } else {
                        *s.gi_region0_count.as_mut_ptr().add(idx) = 7;
                    }
                    *s.gi_region1_count.as_mut_ptr().add(idx) = 36;
                } else {
                    *s.gi_block_type.as_mut_ptr().add(idx) = 0;
                    *s.gi_mixed_block.as_mut_ptr().add(idx) = 0;

                    let ts0 = br_read_bits(&mut reader, 5); if ts0 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3) = ts0 as u8;
                    let ts1 = br_read_bits(&mut reader, 5); if ts1 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 1) = ts1 as u8;
                    let ts2 = br_read_bits(&mut reader, 5); if ts2 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 2) = ts2 as u8;

                    let r0 = br_read_bits(&mut reader, 4); if r0 < 0 { return -6; }
                    *s.gi_region0_count.as_mut_ptr().add(idx) = r0 as u8;
                    let r1 = br_read_bits(&mut reader, 3); if r1 < 0 { return -6; }
                    *s.gi_region1_count.as_mut_ptr().add(idx) = r1 as u8;
                }

                let pf = br_read_bit(&mut reader); if pf < 0 { return -6; }
                *s.gi_preflag.as_mut_ptr().add(idx) = pf as u8;
                let ss = br_read_bit(&mut reader); if ss < 0 { return -6; }
                *s.gi_scalefac_scale.as_mut_ptr().add(idx) = ss as u8;
                let ct = br_read_bit(&mut reader); if ct < 0 { return -6; }
                *s.gi_count1table_select.as_mut_ptr().add(idx) = ct as u8;

                ch += 1;
            }
            gr += 1;
        }

        0
    }
}

fn accumulate_main_data(s: &mut Mp3State, frame_data: *const u8, frame_data_len: usize) {
    unsafe {
        let keep = s.si_main_data_begin as usize;
        let reservoir_avail = s.reservoir_len as usize;
        let reservoir_use = if keep <= reservoir_avail { keep } else { reservoir_avail };

        if reservoir_use > 0 {
            let src_start = reservoir_avail - reservoir_use;
            let mut i: usize = 0;
            while i < reservoir_use {
                *s.main_data.as_mut_ptr().add(i) = *s.reservoir.as_ptr().add(src_start + i);
                i += 1;
            }
        }
        s.main_data_len = reservoir_use as u16;

        let space = 2048 - s.main_data_len as usize;
        let copy_len = if frame_data_len < space { frame_data_len } else { space };
        let dst_offset = s.main_data_len as usize;
        let mut i: usize = 0;
        while i < copy_len {
            *s.main_data.as_mut_ptr().add(dst_offset + i) = *frame_data.add(i);
            i += 1;
        }
        s.main_data_len += copy_len as u16;

        let total = s.main_data_len as usize;
        let save_len = if total < 512 { total } else { 512 };
        let save_start = total - save_len;
        i = 0;
        while i < save_len {
            *s.reservoir.as_mut_ptr().add(i) = *s.main_data.as_ptr().add(save_start + i);
            i += 1;
        }
        s.reservoir_len = save_len as u16;
    }
}

fn decode_granule_channel(s: &mut Mp3State, gr: usize, ch: usize, ms_stereo: bool) -> i32 {
    unsafe {
        let idx = gi_idx(gr, ch);

        let byte_start = s.main_data_bit_pos as usize / 8;
        let bit_offset = s.main_data_bit_pos as usize - byte_start * 8;

        let data_len = s.main_data_len as usize;
        if byte_start >= data_len { return -6; }

        let scalefac_bits = decode_scalefactors(s, gr, ch, byte_start, bit_offset);
        if scalefac_bits < 0 { return scalefac_bits; }

        {
            let reader_start = byte_start;
            let total_skip = bit_offset + scalefac_bits as usize;
            let mut reader = br_new(
                s.main_data.as_ptr().add(reader_start),
                data_len - reader_start,
            );
            if total_skip > 0 {
                let ret = br_skip_bits(&mut reader, total_skip);
                if ret < 0 { return -6; }
            }

            let part2_3_len = *s.gi_part2_3_length.as_ptr().add(idx);
            let huff_bits = if part2_3_len > scalefac_bits as u16 { part2_3_len - scalefac_bits as u16 } else { 0 };

            let ret = decode_spectral_data(
                &mut reader,
                *s.gi_big_values.as_ptr().add(idx),
                s.gi_table_select.as_ptr().add(idx * 3),
                *s.gi_region0_count.as_ptr().add(idx),
                *s.gi_region1_count.as_ptr().add(idx),
                *s.gi_count1table_select.as_ptr().add(idx) != 0,
                huff_bits,
                s.huff_values.as_mut_ptr(),
                *s.gi_block_type.as_ptr().add(idx),
                *s.gi_mixed_block.as_ptr().add(idx) != 0,
                s.sample_rate,
            );
            if ret < 0 { return ret; }
        }

        requantize(
            s.huff_values.as_ptr(),
            s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES),
            s.scalefactors.as_ptr().add(sf_idx(gr, ch, 0)),
            *s.gi_global_gain.as_ptr().add(idx),
            *s.gi_scalefac_scale.as_ptr().add(idx) != 0,
            *s.gi_block_type.as_ptr().add(idx),
            *s.gi_mixed_block.as_ptr().add(idx) != 0,
            s.gi_subblock_gain.as_ptr().add(idx * 3),
            *s.gi_preflag.as_ptr().add(idx) != 0,
            s.sample_rate,
            ms_stereo,
        );

        s.main_data_bit_pos += *s.gi_part2_3_length.as_ptr().add(idx);
        0
    }
}

fn decode_scalefactors(s: &mut Mp3State, gr: usize, ch: usize, byte_start: usize, bit_offset: usize) -> i32 {
    unsafe {
        let idx = gi_idx(gr, ch);
        let data_len = s.main_data_len as usize;

        let mut reader = br_new(
            s.main_data.as_ptr().add(byte_start),
            data_len - byte_start,
        );
        if bit_offset > 0 {
            let ret = br_skip_bits(&mut reader, bit_offset);
            if ret < 0 { return -6; }
        }

        let sfc = *s.gi_scalefac_compress.as_ptr().add(idx) as usize;
        let sfc_safe = if sfc > 15 { 15 } else { sfc };
        let (slen1, slen2) = *SLEN_TABLE.as_ptr().add(sfc_safe);
        let mut bits_read: usize = 0;

        let block_type = *s.gi_block_type.as_ptr().add(idx);
        let mixed = *s.gi_mixed_block.as_ptr().add(idx) != 0;
        let sf_base = sf_idx(gr, ch, 0);

        // Zero the destination range first so unused slots are deterministic 0.
        let mut z: usize = 0;
        while z < 39 { *s.scalefactors.as_mut_ptr().add(sf_base + z) = 0; z += 1; }

        if block_type == 2 {
            if mixed {
                // 44.1/48 kHz mixed: 8 long bands [0..7] + short bands sfb=3..11 × 3 wins
                let mut band: usize = 0;
                while band < 8 {
                    if slen1 > 0 {
                        let v = br_read_bits(&mut reader, slen1);
                        if v < 0 { return -6; }
                        *s.scalefactors.as_mut_ptr().add(sf_base + band) = v as u8;
                        bits_read += slen1 as usize;
                    }
                    band += 1;
                }
                // Short bands sfb=3..5 (slen1)
                let mut sfb: usize = 3;
                while sfb < 6 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = 8 + (sfb - 3) * 3 + win;
                        if slen1 > 0 {
                            let v = br_read_bits(&mut reader, slen1);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen1 as usize;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
                // Short bands sfb=6..11 (slen2)
                sfb = 6;
                while sfb < 12 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = 8 + (sfb - 3) * 3 + win;
                        if slen2 > 0 {
                            let v = br_read_bits(&mut reader, slen2);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen2 as usize;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
            } else {
                // Pure short: 12 SFBs × 3 wins
                let mut sfb: usize = 0;
                while sfb < 6 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = sfb * 3 + win;
                        if slen1 > 0 {
                            let v = br_read_bits(&mut reader, slen1);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen1 as usize;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
                sfb = 6;
                while sfb < 12 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = sfb * 3 + win;
                        if slen2 > 0 {
                            let v = br_read_bits(&mut reader, slen2);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen2 as usize;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
            }
        } else {
            // Long block: 22 SFBs in 4 groups, with SCFSI reuse for gr=1.
            let group_starts: [usize; 4] = [0, 6, 11, 16];
            let group_ends: [usize; 4] = [6, 11, 16, 21];

            let mut group_idx: usize = 0;
            while group_idx < 4 {
                let start = *group_starts.as_ptr().add(group_idx);
                let end = *group_ends.as_ptr().add(group_idx);
                let reuse = gr == 1 && *s.si_scfsi.as_ptr().add(ch * 4 + group_idx) != 0;
                let slen = if group_idx < 2 { slen1 } else { slen2 };

                let mut sfb = start;
                while sfb < end {
                    if reuse {
                        let prev_base = sf_idx(0, ch, 0);
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = *s.scalefactors.as_ptr().add(prev_base + sfb);
                    } else if slen > 0 {
                        let v = br_read_bits(&mut reader, slen);
                        if v < 0 { return -6; }
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = v as u8;
                        bits_read += slen as usize;
                    }
                    sfb += 1;
                }
                group_idx += 1;
            }
        }

        bits_read as i32
    }
}

// ============================================================================
// Section 15: Codec API
// ============================================================================

pub unsafe fn mp3_init(
    s: &mut Mp3State,
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
) {
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.pending_out = 0;
    s.pending_offset = 0;
    s.frame_pos = 0;
    s.frame_size = 0;
    s.sample_rate = 44100;
    s.channels = 2;
    s.channel_mode = 0;
    s.mode_extension = 0;
    s.has_crc = 0;
    s.phase = Mp3Phase::Sync;
    s.id3_skip = 0;
    s.out_pos = 0;
    s.out_len = 0;
    s.frame_count = 0;
    s.main_data_len = 0;
    s.main_data_bit_pos = 0;
    s.reservoir_len = 0;
    s.last_sent_rate = 0;
    s.underrun_count = 0;

    let mut i: usize = 0;
    while i < 960 { *s.qmf_state.as_mut_ptr().add(i) = 0.0; i += 1; }
    i = 0;
    while i < 576 { *s.overlap.as_mut_ptr().add(i) = 0.0; i += 1; }
    i = 0;
    while i < 2112 { *s.lins.as_mut_ptr().add(i) = 0.0; i += 1; }
    i = 0;
    while i < 1152 { *s.freq_lines.as_mut_ptr().add(i) = 0.0; i += 1; }

    let sys = &*s.syscalls;
    dev_log(sys, 3, b"[mp3] init".as_ptr(), 10);
}

pub unsafe fn mp3_feed_detect(s: &mut Mp3State, buf: *const u8, len: usize) {
    s.frame_pos = 0;
    s.id3_skip = 0;

    if len >= 3 && *buf == b'I' && *buf.add(1) == b'D' && *buf.add(2) == b'3' {
        if len >= 10 {
            let s6 = *buf.add(6) as u32;
            let s7 = *buf.add(7) as u32;
            let s8 = *buf.add(8) as u32;
            let s9 = *buf.add(9) as u32;
            let tag_body_size = (s6 << 21) | (s7 << 14) | (s8 << 7) | s9;
            let total_tag_size = 10 + tag_body_size;
            if total_tag_size > len as u32 {
                s.id3_skip = total_tag_size - len as u32;
            }
        }
        return;
    }

    if len >= 4 && *buf == 0xFF && (*buf.add(1) & 0xE0) == 0xE0 {
        let mut sr: u32 = 0;
        let mut ch: u8 = 0;
        let mut cm: u8 = 0;
        let mut me: u8 = 0;
        let mut hc: u8 = 0;
        let mut fs: usize = 0;
        let ret = parse_header(buf, &mut sr, &mut ch, &mut cm, &mut me, &mut hc, &mut fs);
        if ret == 0 && fs > 0 && fs <= 1500 {
            s.sample_rate = sr;
            s.channels = ch;
            s.channel_mode = cm;
            s.mode_extension = me;
            s.has_crc = hc;
            s.frame_size = fs;
            let copy_len = if len > fs { fs } else { len };
            let mut j: usize = 0;
            while j < copy_len {
                *s.frame_buf.as_mut_ptr().add(j) = *buf.add(j);
                j += 1;
            }
            s.frame_pos = copy_len;
            if s.frame_pos >= s.frame_size {
                s.phase = Mp3Phase::Decode;
            } else {
                s.phase = Mp3Phase::Frame;
            }
        }
    }
}

pub unsafe fn mp3_step(s: &mut Mp3State) -> i32 {
    if s.syscalls.is_null() { return -1; }
    let sys = &*s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;

    if s.out_pos < s.out_len {
        let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
        if out_poll > 0 && ((out_poll as u32) & POLL_OUT) != 0 {
            let remaining_bytes = ((s.out_len - s.out_pos) as usize) * 2;
            let chunk = if remaining_bytes > 2048 { 2048 } else { remaining_bytes };
            let src = s.out_buf.as_ptr().add(s.out_pos as usize) as *const u8;
            let written = (sys.channel_write)(out_chan, src, chunk);
            if written > 0 {
                s.out_pos += (written as usize / 2) as u16;
            }
        }
    }

    if s.id3_skip > 0 {
        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 { return 0; }
        let max_read = if s.id3_skip > IO_BUF_SIZE as u32 { IO_BUF_SIZE } else { s.id3_skip as usize };
        let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), max_read);
        if read > 0 {
            s.id3_skip -= read as u32;
        }
        return 0;
    }

    if s.phase == Mp3Phase::Sync {
        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 { return 0; }

        let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), IO_BUF_SIZE);
        if read <= 0 { return 0; }

        let count = read as usize;
        let mut pos: usize = 0;
        while pos + 3 < count {
            let b0 = *s.io_buf.as_ptr().add(pos);
            let b1 = *s.io_buf.as_ptr().add(pos + 1);
            if b0 == 0xFF && (b1 & 0xE0) == 0xE0 {
                let mut sr: u32 = 0;
                let mut ch: u8 = 0;
                let mut cm: u8 = 0;
                let mut me: u8 = 0;
                let mut hc: u8 = 0;
                let mut fs: usize = 0;
                let ret = parse_header(
                    s.io_buf.as_ptr().add(pos),
                    &mut sr, &mut ch, &mut cm, &mut me, &mut hc, &mut fs,
                );
                if ret == 0 && fs > 0 && fs <= 1500 {
                    s.sample_rate = sr;
                    s.channels = ch;
                    s.channel_mode = cm;
                    s.mode_extension = me;
                    s.has_crc = hc;
                    s.frame_size = fs;

                    let avail = count - pos;
                    let copy_len = if avail > fs { fs } else { avail };
                    let mut j: usize = 0;
                    while j < copy_len {
                        *s.frame_buf.as_mut_ptr().add(j) = *s.io_buf.as_ptr().add(pos + j);
                        j += 1;
                    }
                    s.frame_pos = copy_len;

                    if s.frame_pos >= s.frame_size {
                        s.phase = Mp3Phase::Decode;
                    } else {
                        s.phase = Mp3Phase::Frame;
                    }
                    return 0;
                }
            }
            pos += 1;
        }
        return 0;
    }

    if s.phase == Mp3Phase::Frame {
        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 {
            if s.out_pos >= s.out_len {
                s.underrun_count += 1;
            }
            return 0;
        }

        let needed = s.frame_size - s.frame_pos;
        let max_read = if needed > IO_BUF_SIZE { IO_BUF_SIZE } else { needed };
        let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), max_read);
        if read <= 0 { return 0; }

        let count = read as usize;
        let mut j: usize = 0;
        while j < count {
            if s.frame_pos < 1500 {
                *s.frame_buf.as_mut_ptr().add(s.frame_pos) = *s.io_buf.as_ptr().add(j);
                s.frame_pos += 1;
            }
            j += 1;
        }

        if s.frame_pos >= s.frame_size {
            s.phase = Mp3Phase::Decode;
        }
        return 0;
    }

    if s.phase == Mp3Phase::Decode && s.out_pos >= s.out_len {
        let result = decode_frame(s);
        if result >= 0 {
            s.out_pos = 0;
            s.out_len = result as u16;
            s.frame_count = s.frame_count.wrapping_add(1);


            if s.sample_rate != s.last_sent_rate && s.sample_rate > 0 {
                let mut rate_buf = [0u8; 4];
                let rb = rate_buf.as_mut_ptr();
                let sr = s.sample_rate;
                *rb = sr as u8;
                *rb.add(1) = (sr >> 8) as u8;
                *rb.add(2) = (sr >> 16) as u8;
                *rb.add(3) = (sr >> 24) as u8;
                dev_channel_ioctl(sys, out_chan, IOCTL_NOTIFY, rb, 4);
                s.last_sent_rate = s.sample_rate;
            }

            if s.frame_count & 63 == 0 && s.underrun_count > 0 {
                let mut lb = [0u8; 48];
                let bp = lb.as_mut_ptr();
                let tag = b"[mp3] underrun f=";
                let mut p = 0usize;
                let mut t = 0usize;
                while t < tag.len() { *bp.add(p) = *tag.as_ptr().add(t); p += 1; t += 1; }
                p += fmt_u32_raw(bp.add(p), s.frame_count);
                let tag2 = b" n=";
                t = 0; while t < tag2.len() { *bp.add(p) = *tag2.as_ptr().add(t); p += 1; t += 1; }
                p += fmt_u32_raw(bp.add(p), s.underrun_count);
                dev_log(sys, 2, bp, p);
                s.underrun_count = 0;
            }
        } else {
            let mut lb = [0u8; 48];
            let bp = lb.as_mut_ptr();
            let tag = b"[mp3] err ";
            let mut p = 0usize;
            let mut t = 0usize;
            while t < tag.len() { *bp.add(p) = *tag.as_ptr().add(t); p += 1; t += 1; }
            p += fmt_i16_raw(bp.add(p), result as i16);
            *bp.add(p) = b' '; p += 1;
            *bp.add(p) = b'B'; p += 1;
            let mut bi = 0usize;
            while bi < 4 {
                *bp.add(p) = b','; p += 1;
                p += fmt_u32_raw(bp.add(p), *s.gi_big_values.as_ptr().add(bi) as u32);
                bi += 1;
            }
            *bp.add(p) = b' '; p += 1;
            *bp.add(p) = b'T'; p += 1;
            bi = 0;
            while bi < 4 {
                *bp.add(p) = b','; p += 1;
                p += fmt_u32_raw(bp.add(p), *s.gi_table_select.as_ptr().add(bi * 3) as u32);
                bi += 1;
            }
            dev_log(sys, 1, bp, p);
        }
        s.frame_pos = 0;
        s.frame_size = 0;
        s.phase = Mp3Phase::Sync;
        return 2;
    }

    0
}
