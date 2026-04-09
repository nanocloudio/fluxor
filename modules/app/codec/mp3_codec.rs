// MP3 codec kernel for unified decoder.
//
// Extracted from mp3.rs — contains state struct, decode pipeline, and
// init/step functions. No module boilerplate.
//
// Used by: modules/decoder/mod.rs (unified decoder)
// Standalone: modules/mp3.rs (unchanged, still builds independently)

use super::abi::SyscallTable;
use super::{POLL_IN, POLL_OUT, E_AGAIN, IOCTL_NOTIFY, drain_pending, track_pending, dev_log, dev_channel_ioctl, fmt_u32_raw, fmt_i16_raw};

// ============================================================================
// Section 1: Constants, Q15 helpers, BitReader
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

// --- Q15 fixed-point helpers ---

#[inline(always)]
fn q15_mul(a: i16, b: i16) -> i16 {
    let product = (a as i32) * (b as i32);
    let rounded = (product + 0x4000) >> 15;
    rounded.clamp(-32768, 32767) as i16
}

#[inline(always)]
fn q15_sat_add(a: i16, b: i16) -> i16 {
    (a as i32 + b as i32).clamp(-32768, 32767) as i16
}

#[inline(always)]
fn q15_sat_sub(a: i16, b: i16) -> i16 {
    (a as i32 - b as i32).clamp(-32768, 32767) as i16
}

// Q30 accumulator helper
#[inline(always)]
fn q30_mac(acc: i32, a: i16, b: i16) -> i32 {
    acc.saturating_add((a as i32) * (b as i32))
}

#[inline(always)]
fn q30_to_q15(val: i32) -> i16 {
    let rounded = (val + 0x4000) >> 15;
    rounded.clamp(-32768, 32767) as i16
}

/// Clamp i64 to i32 range (used throughout IMDCT/synthesis to avoid overflow).
#[inline(always)]
fn clamp_i32(v: i64) -> i32 {
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// Clamp i64 to i16 range (used by scale_pcm and similar).
#[inline(always)]
fn clamp_i16(v: i64) -> i16 {
    v.clamp(-32768, 32767) as i16
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

        // Sync check
        if b0 != 0xFF || (b1 & 0xE0) != 0xE0 { return -1; }

        let version_bits = (b1 >> 3) & 0x03;
        let layer_bits = (b1 >> 1) & 0x03;
        let protection_bit = b1 & 0x01;

        // MPEG1 only
        if version_bits != 3 { return -8; }
        // Layer III only
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

// Packed Huffman tree (CC0 public domain)
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

/// Cached bitstream reader.
/// Peeks N bits from a 32-bit cache without consuming, then flushes.
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
        // Initialize cache from first 4 bytes (big-endian)
        let mut cache: u32 = 0;
        let avail = if data_len > byte_offset { data_len - byte_offset } else { 0 };
        let init_bytes = if avail > 4 { 4 } else { avail };
        let mut i: usize = 0;
        while i < init_bytes {
            cache |= (*start.add(i) as u32) << (24 - (i << 3));
            i += 1;
        }
        let next = start.add(init_bytes);
        // Convention: sh = (bit_offset & 7) - 8 after loading 4 bytes
        // sh < 0 means cache is full; sh >= 0 triggers CHECK (load more bytes)
        let sh = 24 - (init_bytes as i32) * 8; // 4 bytes → -8, 3 → 0, etc.
        BsCached { cache, sh, next, limit }
    }
}

impl BsCached {
    /// Peek at the top N bits of the cache (1..=32). Does NOT consume.
    #[inline(always)]
    fn peek(&self, n: u32) -> u32 {
        self.cache >> (32 - n)
    }

    /// Consume N bits from the cache.
    #[inline(always)]
    fn flush(&mut self, n: u32) {
        self.cache <<= n;
        self.sh += n as i32;
    }

    /// Refill the cache from the byte stream.
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

    /// Return current bit position relative to start (for part2_3 boundary check).
    #[inline(always)]
    fn bits_consumed(&self, data: *const u8, byte_offset: usize) -> usize {
        unsafe {
            let bytes_read = self.next.offset_from(data.add(byte_offset)) as usize;
            // bytes_read * 8 is total bytes consumed as bits
            // sh starts negative, goes positive as bits are consumed
            // actual position = bytes_read*8 - (bits still in cache)
            // bits still in cache = -(sh + 8) when sh < 0, but simpler:
            // bits_consumed = bytes_read * 8 + sh + 32 - 32 ...
            // Actually: after init, sh = init_bytes*8 - 32
            // After consuming N bits total via flush, sh increases by N
            // So bits consumed = (bytes_read*8 - 32) - initial_sh ... no.
            // BSPOS formula: (bs_next_ptr - start)*8 - 24 + bs_sh
            let byte_dist = bytes_read;
            // total bits available = byte_dist * 8
            // bits remaining in cache = -(self.sh) - 8  ... no
            // sh after init with 4 bytes = 4*8 - 32 = 0
            // after flushing 5 bits, sh = 5, then check refills:
            //   reads 1 byte, sh = 5-8 = -3. cache has 32-5+8 = 35 bits? no, 32.
            // Let me think again. sh tracks how many bits we've consumed beyond
            // BSPOS = (next - buf_start)*8 - 24 + sh
            (byte_dist * 8).wrapping_add(self.sh as usize).wrapping_sub(8)
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

        // Lower nibble first (j=0), then upper nibble (j=1).
        // Sign/linbits bits must be consumed in this order.
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

        // bits 7..4 encode v,w,x,y presence
        if (leaf & 128) != 0 {
            v = if (bs.cache >> 31) != 0 { -1 } else { 1 };
            bs.flush(1);
        }
        if (leaf & 64) != 0 {
            w = if (bs.cache >> 31) != 0 { -1 } else { 1 };
            bs.flush(1);
        }
        if (leaf & 32) != 0 {
            x = if (bs.cache >> 31) != 0 { -1 } else { 1 };
            bs.flush(1);
        }
        if (leaf & 16) != 0 {
            y = if (bs.cache >> 31) != 0 { -1 } else { 1 };
            bs.flush(1);
        }

        bs.check();
        (v, w, x, y)
    }
}

// ============================================================================
// Section 4: Spectral data decoding (tree-based Huffman)
// ============================================================================

/// Decode all spectral data for one granule/channel using tree-based Huffman.
fn decode_spectral_data(
    reader: &mut BitReader,
    big_values: u16,
    table_select: *const u8,
    region0_count: u8,
    region1_count: u8,
    count1table_select: bool,
    part2_3_length: u16,
    output: *mut i32,
    sfb_table: *const usize,
) -> i32 {
    unsafe {
        // Zero output first
        let mut i: usize = 0;
        while i < 576 {
            *output.add(i) = 0;
            i += 1;
        }

        // Region boundaries from scalefactor band table (ISO 11172-3 2.4.2.7)
        let r0_idx = (region0_count as usize + 1).min(22);
        let r1_idx = (region0_count as usize + region1_count as usize + 2).min(22);
        let region0_end_raw = *sfb_table.add(r0_idx);
        let region0_end = if region0_end_raw < big_values as usize * 2 { region0_end_raw } else { big_values as usize * 2 };
        let region1_end_raw = *sfb_table.add(r1_idx);
        let region1_end = if region1_end_raw < big_values as usize * 2 { region1_end_raw } else { big_values as usize * 2 };
        let big_values_end = big_values as usize * 2;

        let start_bit = br_bit_position(reader);
        let part2_3_end = start_bit + part2_3_length as usize;

        // Build a cached bitstream reader from the current BitReader position
        let byte_off = reader.byte_pos;
        let bit_off = reader.bit_pos as u32;
        let mut bs = bs_cached_new(reader.data, byte_off, reader.data_len);
        // Align: skip the bit_pos bits already consumed within the current byte
        if bit_off > 0 {
            bs.flush(bit_off);
        }
        bs.check();

        // Decode big_values pairs across three regions
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

        // Count1 region: decode quads until we hit the part2_3 boundary
        let mut pos = big_values_end;
        // Compute how many bits the cached BS has consumed so far
        let bs_byte_dist = bs.next.offset_from(reader.data.add(byte_off)) as usize;
        let mut bits_used = (bs_byte_dist * 8) as i32 + bs.sh + 8 + bit_off as i32;

        while pos + 3 < 576 {
            // Check part2_3 boundary
            if (start_bit as i32 + bits_used as i32) >= part2_3_end as i32 { break; }

            let (v, w, x, y) = decode_quad_tree(&mut bs, count1table_select);
            *output.add(pos) = v;
            *output.add(pos + 1) = w;
            *output.add(pos + 2) = x;
            *output.add(pos + 3) = y;
            pos += 4;

            // Recompute bits used
            let bd2 = bs.next.offset_from(reader.data.add(byte_off)) as usize;
            bits_used = (bd2 * 8) as i32 + bs.sh + 8 + bit_off as i32;
        }

        // Advance the original BitReader to part2_3_end
        let consumed_total = part2_3_length as usize;
        reader.byte_pos = (start_bit + consumed_total) >> 3;
        reader.bit_pos = ((start_bit + consumed_total) & 7) as u8;

        0
    }
}

// (old TABLE_5 through TABLE_B, get_huff_table, decode_pair_from_table,
//  decode_quad_from_table, decode_big_values, decode_count1, and
//  old decode_spectral_data all removed — replaced by tree-based Huffman above)


// ============================================================================
// Section 5: Requantize tables and function
// ============================================================================

static POW_4_3: [i32; 256] = [
    0, 1, 3, 4, 6, 9, 11, 13, 16, 19, 22, 24, 27, 31, 34, 37,
    40, 44, 47, 51, 54, 58, 62, 65, 69, 73, 77, 81, 85, 89, 93, 97,
    102, 106, 110, 114, 119, 123, 128, 132, 137, 141, 146, 151, 155, 160, 165, 170,
    174, 179, 184, 189, 194, 199, 204, 209, 214, 219, 225, 230, 235, 240, 245, 251,
    256, 261, 267, 272, 278, 283, 288, 294, 300, 305, 311, 316, 322, 328, 333, 339,
    345, 350, 356, 362, 368, 374, 380, 386, 391, 397, 403, 409, 415, 421, 427, 433,
    440, 446, 452, 458, 464, 470, 477, 483, 489, 495, 502, 508, 514, 521, 527, 533,
    540, 546, 553, 559, 566, 572, 579, 585, 592, 598, 605, 612, 618, 625, 632, 638,
    645, 652, 659, 665, 672, 679, 686, 693, 699, 706, 713, 720, 727, 734, 741, 748,
    755, 762, 769, 776, 783, 790, 797, 804, 811, 818, 825, 833, 840, 847, 854, 861,
    869, 876, 883, 890, 898, 905, 912, 920, 927, 934, 942, 949, 957, 964, 971, 979,
    986, 994, 1001, 1009, 1016, 1024, 1031, 1039, 1047, 1054, 1062, 1069, 1077, 1085, 1092, 1100,
    1108, 1115, 1123, 1131, 1139, 1146, 1154, 1162, 1170, 1177, 1185, 1193, 1201, 1209, 1217, 1225,
    1232, 1240, 1248, 1256, 1264, 1272, 1280, 1288, 1296, 1304, 1312, 1320, 1328, 1336, 1344, 1352,
    1360, 1368, 1377, 1385, 1393, 1401, 1409, 1417, 1426, 1434, 1442, 1450, 1458, 1467, 1475, 1483,
    1491, 1500, 1508, 1516, 1525, 1533, 1541, 1550, 1558, 1567, 1575, 1583, 1592, 1600, 1609, 1617,
];

static POW2_QUARTER: [i32; 4] = [32768, 38968, 46341, 55109];

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

// SFB widths for short blocks (per window), zero-terminated.
// Each entry is the width of one scalefactor band for one short window.
// Total per table sums to 192 (= 576 / 3 windows).
static SFB_SHORT_W_48000: [u8; 14] = [4,4,4,4,6,6,10,12,14,16,20,26,66, 0];
static SFB_SHORT_W_44100: [u8; 14] = [4,4,4,4,6,8,10,12,14,18,22,30,56, 0];
static SFB_SHORT_W_32000: [u8; 14] = [4,4,4,4,6,8,12,16,20,26,34,42,12, 0];

fn get_sfb_short_widths(sample_rate: u32) -> *const u8 {
    if sample_rate == 48000 { SFB_SHORT_W_48000.as_ptr() }
    else if sample_rate == 32000 { SFB_SHORT_W_32000.as_ptr() }
    else { SFB_SHORT_W_44100.as_ptr() }
}

/// Reorder short-block spectral values from SFB-sequential to window-interleaved.
/// After reorder, each group of 18 values (one subband) has 3 windows interleaved
/// at stride 3, so L3_imdct_short can extract each window's 6 values.
/// Uses `scratch` as temporary buffer (must be >= 576 i32).
fn reorder_short(grbuf: *mut i32, scratch: *mut i32, sample_rate: u32) {
    unsafe {
        let sfb_w = get_sfb_short_widths(sample_rate);
        let mut src = grbuf;
        let mut dst_idx: usize = 0;
        let mut wi: usize = 0;
        loop {
            let len = *sfb_w.add(wi) as usize;
            if len == 0 { break; }
            let mut i: usize = 0;
            while i < len {
                *scratch.add(dst_idx) = *src.add(i);
                *scratch.add(dst_idx + 1) = *src.add(len + i);
                *scratch.add(dst_idx + 2) = *src.add(2 * len + i);
                dst_idx += 3;
                i += 1;
            }
            src = src.add(3 * len);
            wi += 1;
        }
        // Copy back
        let mut i: usize = 0;
        while i < dst_idx {
            *grbuf.add(i) = *scratch.add(i);
            i += 1;
        }
    }
}

/// Requantize spectral values for one granule/channel.
/// Output is Q15 stored in i32 (will become Q30 after IMDCT accumulation).
fn requantize(
    input: *const i32,
    output: *mut i32,
    scalefactors: *const u8,
    global_gain: u8,
    scalefac_scale: bool,
    block_type: u8,
    subblock_gain: *const u8,
    preflag: bool,
    sample_rate: u32,
    norm_shift: i32,
) {
    unsafe {
        let sfb_table = get_sfb_table(sample_rate);
        let gain_exp = global_gain as i32 - 210;
        let sf_shift: i32 = if scalefac_scale { 1 } else { 0 };

        let mut sfb: usize = 0;
        let mut i: usize = 0;
        while i < GRANULE_SAMPLES {
            // Advance SFB
            while sfb + 1 < 23 {
                let next_boundary = *sfb_table.add(sfb + 1);
                if i < next_boundary { break; }
                sfb += 1;
            }

            let is_val = *input.add(i);
            if is_val == 0 {
                *output.add(i) = 0;
                i += 1;
                continue;
            }

            let sf_raw = if sfb < 39 { *scalefactors.add(sfb) as i32 } else { 0 };
            // Add pretab to scalefactor (ISO 11172-3 §2.4.3.4)
            let sf = if preflag && block_type != 2 && sfb < 22 {
                sf_raw + *PRETAB.as_ptr().add(sfb)
            } else {
                sf_raw
            };

            // |x|^(4/3)
            let magnitude = if is_val < 0 { -is_val } else { is_val };
            let pow_result = if magnitude < 256 {
                *POW_4_3.as_ptr().add(magnitude as usize)
            } else {
                let base = *POW_4_3.as_ptr().add(255);
                let scaled = magnitude / 256;
                base * scaled / 4
            };

            // Subblock gain for short blocks
            let sbg = if block_type == 2 {
                let window = (i / 6) - ((i / 6) / 3) * 3; // i/6 mod 3 without %
                *subblock_gain.add(window) as i32 * 8
            } else {
                0
            };

            let total_exp = gain_exp - (sf << sf_shift) - sbg;

            // Decompose 2^(total_exp/4) = 2^(int_shift) * 2^(frac/4)
            // Using arithmetic right shift: works correctly for negative values
            let int_shift = total_exp >> 2;
            let frac_idx = (total_exp & 3) as usize;
            let frac_idx_safe = if frac_idx >= 4 { 0 } else { frac_idx };
            // pow_result(Q0) × POW2_QUARTER(Q15) = Q15
            let scaled_q15 = pow_result as i64 * *POW2_QUARTER.as_ptr().add(frac_idx_safe) as i64;

            // Apply int_shift minus per-granule norm_shift to prevent i32 overflow
            // in downstream IMDCT/DCT-II. Compensated post-synthesis by <<norm_shift.
            let total_shift = int_shift - norm_shift;
            let result = if total_shift >= 0 {
                let ts = total_shift as u32;
                if ts > 30 { i32::MAX as i64 }
                else { (scaled_q15 << ts).min(i32::MAX as i64) }
            } else {
                let rs = (-total_shift) as u32;
                if rs > 45 { 0i64 } else { scaled_q15 >> rs }
            };

            let signed_result = if is_val < 0 { -(result as i32) } else { result as i32 };
            *output.add(i) = signed_result;
            i += 1;
        }

        // Preflag is now integrated into the scalefactor in the main loop above
    }
}

// ============================================================================
// Section 6: Stereo processing (MS stereo, intensity stereo)
// ============================================================================

/// Process MS stereo: convert mid/side to left/right
/// freq_lines layout: [ch0: 576 i16][ch1: 576 i16]
// ISO 11172-3 Table B.9: Antialiasing butterfly coefficients in Q15
// cs[i] = cos(atan(ca_float[i]/cs_float[i])) scaled to Q15
// ca[i] = sin(atan(ca_float[i]/cs_float[i])) scaled to Q15
// ISO 11172-3 Table B.9: Antialiasing butterfly coefficients in Q15
static ANTIALIAS_CS: [i16; 8] = [
    28098, 28893, 31117, 32221, 32621, 32740, 32765, 32767,
];
static ANTIALIAS_CA: [i16; 8] = [
    -16859, -15458, -10269, -5961, -3099, -1342, -465, -121,
];

/// Antialiasing butterfly reduction between adjacent subbands (ISO 11172-3 §2.4.3.4).
/// Applied to long blocks only, before IMDCT. For mixed blocks, sb_limit=1.
fn antialias_butterflies(freq: *mut i32, sb_limit: usize) {
    unsafe {
        let mut sb: usize = 0;
        while sb < sb_limit {
            let mut i: usize = 0;
            while i < 8 {
                let upper = sb * 18 + 17 - i;
                let lower = sb * 18 + 18 + i;
                if lower >= GRANULE_SAMPLES { break; }
                let a = *freq.add(upper) as i64;
                let b = *freq.add(lower) as i64;
                let cs = *ANTIALIAS_CS.as_ptr().add(i) as i64;
                let ca = *ANTIALIAS_CA.as_ptr().add(i) as i64;
                let new_a = ((a * cs) >> 15) - ((b * ca) >> 15);
                let new_b = ((b * cs) >> 15) + ((a * ca) >> 15);
                *freq.add(upper) = new_a as i32;
                *freq.add(lower) = new_b as i32;
                i += 1;
            }
            sb += 1;
        }
    }
}

fn process_ms_stereo(freq_lines: *mut i32) {
    unsafe {
        let inv_sqrt2: i64 = 23170; // 1/sqrt(2) in Q15
        let right = freq_lines.add(GRANULE_SAMPLES);
        let mut i: usize = 0;
        while i < GRANULE_SAMPLES {
            let m = *freq_lines.add(i) as i64;
            let s = *right.add(i) as i64;
            *freq_lines.add(i) = (((m + s) * inv_sqrt2) >> 15) as i32;
            *right.add(i) = (((m - s) * inv_sqrt2) >> 15) as i32;
            i += 1;
        }
    }
}

/// Process intensity stereo (simplified)
fn process_intensity_stereo(freq_lines: *mut i32, right_big_values: u16) {
    unsafe {
        let is_start = (right_big_values as usize * 2).min(GRANULE_SAMPLES);
        if is_start >= GRANULE_SAMPLES { return; }

        let left_ptr = freq_lines;
        let right_ptr = freq_lines.add(GRANULE_SAMPLES);
        // Use center ratio as default
        let left_ratio: i64 = 23170;
        let right_ratio: i64 = 23170;

        let mut i = is_start;
        while i < GRANULE_SAMPLES {
            let left_val = *left_ptr.add(i) as i64;
            *left_ptr.add(i) = ((left_val * left_ratio) >> 15) as i32;
            *right_ptr.add(i) = ((left_val * right_ratio) >> 15) as i32;
            i += 1;
        }
    }
}

// ============================================================================
// Section 7: IMDCT (window tables, imdct_36, imdct_12, process_imdct)
// ============================================================================

const IMDCT_LONG: usize = 36;
const IMDCT_SHORT: usize = 12;
const IMDCT_LONG_IN: usize = 18;
const IMDCT_SHORT_IN: usize = 6;

// IMDCT via 9-point DCT-III decomposition + twiddle factors

#[inline(always)]
fn q15_mul_i32(a: i32, b: i16) -> i32 {
    ((a as i64 * b as i64) >> 15) as i32
}

static TWID9: [i16; 18] = [
    24159, 25997, 27636, 29066, 30274, 31251, 31991, 32488, 32737,
    22138, 19948, 17606, 15131, 12540,  9854,  7092,  4277,  1429,
];

static MDCT_WIN0: [i16; 18] = [
    32737, 32488, 31991, 31251, 30274, 29066, 27636, 25997, 24159,
     1429,  4277,  7092,  9854, 12540, 15131, 17606, 19948, 22138,
];

static MDCT_WIN1: [i16; 18] = [
    32767, 32767, 32767, 32767, 32767, 32767, 32488, 30274, 25997,
        0,     0,     0,     0,     0,     0,  4277, 12540, 19948,
]; // Note: 1.0 in Q15 is 32768 but clamped to 32767 (i16 max). Error < 0.003%.

const DCT3_HALF: i16 = 16384;
const DCT3_C1: i16 = 30792;   // 0.93969262
const DCT3_C2: i16 = 25102;   // 0.76604444
const DCT3_C3: i16 = 5690;    // 0.17364818
const DCT3_C4: i16 = 28378;   // 0.86602540
const DCT3_C5: i16 = 32270;   // 0.98480775
const DCT3_C6: i16 = 11207;   // 0.34202014
const DCT3_C7: i16 = 21063;   // 0.64278761

/// 9-point DCT-III (in-place)
unsafe fn mp3_dct3_9(y: *mut i32) {
    let mut s0 = *y.add(0);
    let s2 = *y.add(2);
    let mut s4 = *y.add(4);
    let mut s6 = *y.add(6);
    let mut s8 = *y.add(8);

    let t0 = s0 + q15_mul_i32(s6, DCT3_HALF);
    s0 = s0 - s6;
    let t4 = q15_mul_i32(s4 + s2, DCT3_C1);
    let t2 = q15_mul_i32(s8 + s2, DCT3_C2);
    s6 = q15_mul_i32(s4 - s8, DCT3_C3);
    s4 = s4 + s8 - s2;
    let s2_new = s0 - q15_mul_i32(s4, DCT3_HALF);
    *y.add(4) = s4 + s0;
    s8 = t0 - t2 + s6;
    s0 = t0 - t4 + t2;
    s4 = t0 + t4 - s6;

    let s1 = *y.add(1);
    let mut s3 = *y.add(3);
    let s5 = *y.add(5);
    let s7 = *y.add(7);

    s3 = q15_mul_i32(s3, DCT3_C4);
    let t0b = q15_mul_i32(s5 + s1, DCT3_C5);
    let t4b = q15_mul_i32(s5 - s7, DCT3_C6);
    let t2b = q15_mul_i32(s1 + s7, DCT3_C7);
    let s1_new = q15_mul_i32(s1 - s5 - s7, DCT3_C4);
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

/// IMDCT-36 with overlap-add (ISO 11172-3 §2.4.3.4).
/// grbuf: 18 values per subband (modified in-place to output).
/// overlap: 9 values per subband (persistent state).
/// window: 18-entry Q15 window (MDCT_WIN0 or MDCT_WIN1).
unsafe fn mp3_imdct36(grbuf: *mut i32, overlap: *mut i32, window: *const i16, nbands: usize) {
    let mut gr = grbuf;
    let mut ov = overlap;
    let twid = TWID9.as_ptr();

    let mut j: usize = 0;
    while j < nbands {
        let mut co: [i32; 9] = [0; 9];
        let mut si: [i32; 9] = [0; 9];

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

        mp3_dct3_9(co.as_mut_ptr());
        mp3_dct3_9(si.as_mut_ptr());

        let sip = si.as_mut_ptr();
        *sip.add(1) = -(*sip.add(1));
        *sip.add(3) = -(*sip.add(3));
        *sip.add(5) = -(*sip.add(5));
        *sip.add(7) = -(*sip.add(7));

        let cop = co.as_ptr();

        let mut i: usize = 0;
        while i < 9 {
            let ovl = *ov.add(i);
            let co_i = *cop.add(i);
            let si_i = *sip.add(i);
            let tw_cos = *twid.add(9 + i);
            let tw_sin = *twid.add(i);
            let win_i = *window.add(i);
            let win_9i = *window.add(9 + i);

            let sum = q15_mul_i32(co_i, tw_cos) + q15_mul_i32(si_i, tw_sin);
            *ov.add(i) = q15_mul_i32(co_i, tw_sin) - q15_mul_i32(si_i, tw_cos);
            *gr.add(i) = q15_mul_i32(ovl, win_i) - q15_mul_i32(sum, win_9i);
            *gr.add(17 - i) = q15_mul_i32(ovl, win_9i) + q15_mul_i32(sum, win_i);
            i += 1;
        }

        gr = gr.add(18);
        ov = ov.add(9);
        j += 1;
    }
}

// --- Short block IMDCT (ISO 11172-3 §2.4.3.4, 12-point transform) ---

/// Twiddle factors for 12-point IMDCT decomposition (Q15).
/// [cos0, cos1, cos2, sin0, sin1, sin2] — same values as the short window shape.
static TWID3: [i16; 6] = [25997, 19948, 4277, 32488, 12540, 30274];

/// 3-point DCT-III (in-place on 3 values).
unsafe fn mp3_dct3_3(y: *mut i32) {
    let s0 = *y.add(0);
    let s1 = *y.add(1);
    let s2 = *y.add(2);
    let t0 = s0 + q15_mul_i32(s2, DCT3_HALF);
    *y.add(0) = t0 + q15_mul_i32(s1, DCT3_C4);
    *y.add(1) = s0 - s2;
    *y.add(2) = t0 - q15_mul_i32(s1, DCT3_C4);
}

/// 12-point IMDCT via 3-point DCT-III decomposition.
/// Reads 6 frequency values at `stride` from `x`.
/// Writes 6 time-domain output samples to `dst`.
/// Reads and updates 3 overlap values at `overlap`.
unsafe fn mp3_imdct12(x: *const i32, stride: usize, dst: *mut i32, overlap: *mut i32) {
    let x0 = *x.add(0 * stride);
    let x1 = *x.add(1 * stride);
    let x2 = *x.add(2 * stride);
    let x3 = *x.add(3 * stride);
    let x4 = *x.add(4 * stride);
    let x5 = *x.add(5 * stride);

    // Prepare co[3] and si[3] (even/odd decomposition, same pattern as imdct36)
    let mut co = [0i32; 3];
    let mut si = [0i32; 3];
    *co.as_mut_ptr().add(0) = -(x0);
    *si.as_mut_ptr().add(0) = x5;
    *si.as_mut_ptr().add(2) = x1 - x2;
    *co.as_mut_ptr().add(1) = x1 + x2;
    *si.as_mut_ptr().add(1) = x4 - x3;
    *co.as_mut_ptr().add(2) = -(x3 + x4);

    // 3-point DCT-III
    mp3_dct3_3(co.as_mut_ptr());
    mp3_dct3_3(si.as_mut_ptr());

    // Negate odd si values (DCT-III sign convention)
    *si.as_mut_ptr().add(1) = -(*si.as_ptr().add(1));

    // Twiddle + window + overlap-add
    let twid = TWID3.as_ptr();
    let mut i: usize = 0;
    while i < 3 {
        let ovl = *overlap.add(i);
        let co_i = *co.as_ptr().add(i);
        let si_i = *si.as_ptr().add(i);
        let tw_cos = *twid.add(3 + i) as i64;
        let tw_sin = *twid.add(i) as i64;
        let win_a = *twid.add(2 - i) as i64;
        let win_b = *twid.add(5 - i) as i64;

        let sum = ((co_i as i64 * tw_cos) >> 15) as i32
                + ((si_i as i64 * tw_sin) >> 15) as i32;
        *overlap.add(i) = ((co_i as i64 * tw_sin) >> 15) as i32
                        - ((si_i as i64 * tw_cos) >> 15) as i32;
        *dst.add(i) = ((ovl as i64 * win_a) >> 15) as i32
                    - ((sum as i64 * win_b) >> 15) as i32;
        *dst.add(5 - i) = ((ovl as i64 * win_b) >> 15) as i32
                         + ((sum as i64 * win_a) >> 15) as i32;
        i += 1;
    }
}

/// Short-block IMDCT for all subbands (3 × 12-point windows per subband).
/// Input must be reordered (window-interleaved at stride 3).
/// Per-subband overlap layout: [0..5] inter-granule carry, [6..8] inter-window carry.
unsafe fn mp3_imdct_short(grbuf: *mut i32, overlap: *mut i32, nbands: usize) {
    let mut gr = grbuf;
    let mut ov = overlap;
    let mut j: usize = 0;
    while j < nbands {
        // Save input (output overwrites grbuf in-place)
        let mut tmp = [0i32; 18];
        let mut i: usize = 0;
        while i < 18 { *tmp.as_mut_ptr().add(i) = *gr.add(i); i += 1; }

        // Output[0..5] = previous inter-granule overlap
        i = 0;
        while i < 6 { *gr.add(i) = *ov.add(i); i += 1; }

        // 3 short windows chain through inter-window overlap (ov[6..8])
        mp3_imdct12(tmp.as_ptr(),       3, gr.add(6),  ov.add(6)); // win 0 → output[6..11]
        mp3_imdct12(tmp.as_ptr().add(1), 3, gr.add(12), ov.add(6)); // win 1 → output[12..17]
        mp3_imdct12(tmp.as_ptr().add(2), 3, ov,         ov.add(6)); // win 2 → overlap[0..5]

        gr = gr.add(18);
        ov = ov.add(9);
        j += 1;
    }
}

/// Process IMDCT for one granule/channel (ISO 11172-3 §2.4.3.4).
/// freq_lines: 576 values (32 subbands × 18). Modified in-place to time-domain output.
/// overlap: 288 values (32 subbands × 9). Persistent state.
fn process_imdct(
    freq_lines: *mut i32,
    overlap: *mut i32,
    block_type: u8,
    _mixed_block: bool,
) {
    unsafe {
        if block_type == 2 {
            // Short blocks: 3 × 12-point IMDCT per subband
            mp3_imdct_short(freq_lines, overlap, SUBBANDS);
        } else if block_type == 3 {
            // Stop block
            mp3_imdct36(freq_lines, overlap, MDCT_WIN1.as_ptr(), SUBBANDS);
        } else if block_type == 1 {
            // Start block — use WIN1 reversed? For now use WIN0
            mp3_imdct36(freq_lines, overlap, MDCT_WIN0.as_ptr(), SUBBANDS);
        } else {
            // Long blocks (normal)
            mp3_imdct36(freq_lines, overlap, MDCT_WIN0.as_ptr(), SUBBANDS);
        }
    }
}

// Precomputed IMDCT-36 cosines: cos(π/72 × (2n+19) × (2k+1)), indexed [n*18+k]
#[rustfmt::skip]
static IMDCT_COS_36: [i16; 648] = [
    22138,-25997,-17606,29066,12540,-31251,-7092,32488,1429,-32737,4277,31991,-9854,-30274,15131,27636,-19948,-24159,
    19948,-30274,-4277,32488,-12540,-25997,25997,12540,-32488,4277,30274,-19948,-19948,30274,4277,-32488,12540,25997,
    17606,-32488,9854,24159,-30274,1429,29066,-25997,-7092,31991,-19948,-15131,32737,-12540,-22138,31251,-4277,-27636,
    15131,-32488,22138,7092,-30274,27636,-1429,-25997,31251,-9854,-19948,32737,-17606,-12540,31991,-24159,-4277,29066,
    12540,-30274,30274,-12540,-12540,30274,-30274,12540,12540,-30274,30274,-12540,-12540,30274,-30274,12540,12540,-30274,
    9854,-25997,32737,-27636,12540,7092,-24159,32488,-29066,15131,4277,-22138,31991,-30274,17606,1429,-19948,31251,
    7092,-19948,29066,-32737,30274,-22138,9854,4277,-17606,27636,-32488,31251,-24159,12540,1429,-15131,25997,-31991,
    4277,-12540,19948,-25997,30274,-32488,32488,-30274,25997,-19948,12540,-4277,-4277,12540,-19948,25997,-30274,32488,
    1429,-4277,7092,-9854,12540,-15131,17606,-19948,22138,-24159,25997,-27636,29066,-30274,31251,-31991,32488,-32737,
    -1429,4277,-7092,9854,-12540,15131,-17606,19948,-22138,24159,-25997,27636,-29066,30274,-31251,31991,-32488,32737,
    -4277,12540,-19948,25997,-30274,32488,-32488,30274,-25997,19948,-12540,4277,4277,-12540,19948,-25997,30274,-32488,
    -7092,19948,-29066,32737,-30274,22138,-9854,-4277,17606,-27636,32488,-31251,24159,-12540,-1429,15131,-25997,31991,
    -9854,25997,-32737,27636,-12540,-7092,24159,-32488,29066,-15131,-4277,22138,-31991,30274,-17606,-1429,19948,-31251,
    -12540,30274,-30274,12540,12540,-30274,30274,-12540,-12540,30274,-30274,12540,12540,-30274,30274,-12540,-12540,30274,
    -15131,32488,-22138,-7092,30274,-27636,1429,25997,-31251,9854,19948,-32737,17606,12540,-31991,24159,4277,-29066,
    -17606,32488,-9854,-24159,30274,-1429,-29066,25997,7092,-31991,19948,15131,-32737,12540,22138,-31251,4277,27636,
    -19948,30274,4277,-32488,12540,25997,-25997,-12540,32488,-4277,-30274,19948,19948,-30274,-4277,32488,-12540,-25997,
    -22138,25997,17606,-29066,-12540,31251,7092,-32488,-1429,32737,-4277,-31991,9854,30274,-15131,-27636,19948,24159,
    -24159,19948,27636,-15131,-30274,9854,31991,-4277,-32737,-1429,32488,7092,-31251,-12540,29066,17606,-25997,-22138,
    -25997,12540,32488,4277,-30274,-19948,19948,30274,-4277,-32488,-12540,25997,25997,-12540,-32488,-4277,30274,19948,
    -27636,4277,31251,22138,-12540,-32737,-15131,19948,31991,7092,-25997,-29066,1429,30274,24159,-9854,-32488,-17606,
    -29066,-4277,24159,31991,12540,-17606,-32737,-19948,9854,31251,25997,-1429,-27636,-30274,-7092,22138,32488,15131,
    -30274,-12540,12540,30274,30274,12540,-12540,-30274,-30274,-12540,12540,30274,30274,12540,-12540,-30274,-30274,-12540,
    -31251,-19948,-1429,17606,30274,31991,22138,4277,-15131,-29066,-32488,-24159,-7092,12540,27636,32737,25997,9854,
    -31991,-25997,-15131,-1429,12540,24159,31251,32488,27636,17606,4277,-9854,-22138,-30274,-32737,-29066,-19948,-7092,
    -32488,-30274,-25997,-19948,-12540,-4277,4277,12540,19948,25997,30274,32488,32488,30274,25997,19948,12540,4277,
    -32737,-32488,-31991,-31251,-30274,-29066,-27636,-25997,-24159,-22138,-19948,-17606,-15131,-12540,-9854,-7092,-4277,-1429,
    -32737,-32488,-31991,-31251,-30274,-29066,-27636,-25997,-24159,-22138,-19948,-17606,-15131,-12540,-9854,-7092,-4277,-1429,
    -32488,-30274,-25997,-19948,-12540,-4277,4277,12540,19948,25997,30274,32488,32488,30274,25997,19948,12540,4277,
    -31991,-25997,-15131,-1429,12540,24159,31251,32488,27636,17606,4277,-9854,-22138,-30274,-32737,-29066,-19948,-7092,
    -31251,-19948,-1429,17606,30274,31991,22138,4277,-15131,-29066,-32488,-24159,-7092,12540,27636,32737,25997,9854,
    -30274,-12540,12540,30274,30274,12540,-12540,-30274,-30274,-12540,12540,30274,30274,12540,-12540,-30274,-30274,-12540,
    -29066,-4277,24159,31991,12540,-17606,-32737,-19948,9854,31251,25997,-1429,-27636,-30274,-7092,22138,32488,15131,
    -27636,4277,31251,22138,-12540,-32737,-15131,19948,31991,7092,-25997,-29066,1429,30274,24159,-9854,-32488,-17606,
    -25997,12540,32488,4277,-30274,-19948,19948,30274,-4277,-32488,-12540,25997,25997,-12540,-32488,-4277,30274,19948,
    -24159,19948,27636,-15131,-30274,9854,31991,-4277,-32737,-1429,32488,7092,-31251,-12540,29066,17606,-25997,-22138,
];

fn imdct_cos_36(n: usize, k: usize) -> i16 {
    unsafe { *IMDCT_COS_36.as_ptr().add(n * 18 + k) }
}

// ============================================================================
// Section 8: Synthesis filterbank (ISO 11172-3 §2.4.3.5)
// ============================================================================

/// g_sec[24] in Q12 for DCT-II butterfly
static G_SEC: [i32; 24] = [
    41738,  2051,  2058, 13955,  2071,  2141,
     8429,  2112,  2322,  6079,  2176,  2650,
     4790,  2266,  3228,  3984,  2388,  4344,
     3439,  2550,  7056,  3050,  2764, 20898,
];

/// g_win[240] — synthesis window coefficients (integer, no Q scaling)
#[rustfmt::skip]
static G_WIN: [i32; 240] = [
    -1,26,-31,208,218,401,-519,2063,2000,4788,-5517,7134,5959,35640,-39336,74992,
    -1,24,-35,202,222,347,-581,2080,1952,4425,-5879,7640,5288,33791,-41176,74856,
    -1,21,-38,196,225,294,-645,2087,1893,4063,-6237,8092,4561,31947,-43006,74630,
    -1,19,-41,190,227,244,-711,2085,1822,3705,-6589,8492,3776,30112,-44821,74313,
    -1,17,-45,183,228,197,-779,2075,1739,3351,-6935,8840,2935,28289,-46617,73908,
    -1,16,-49,176,228,153,-848,2057,1644,3004,-7271,9139,2037,26482,-48390,73415,
    -2,14,-53,169,227,111,-919,2032,1535,2663,-7597,9389,1082,24694,-50137,72835,
    -2,13,-58,161,224,72,-991,2001,1414,2330,-7910,9592,70,22929,-51853,72169,
    -2,11,-63,154,221,36,-1064,1962,1280,2006,-8209,9750,-998,21189,-53534,71420,
    -2,10,-68,147,215,2,-1137,1919,1131,1692,-8491,9863,-2122,19478,-55178,70590,
    -3,9,-73,139,208,-29,-1210,1870,970,1388,-8755,9935,-3300,17799,-56778,69679,
    -3,8,-79,132,200,-57,-1283,1817,794,1095,-8998,9966,-4533,16155,-58333,68692,
    -4,7,-85,125,189,-83,-1356,1759,605,814,-9219,9959,-5818,14548,-59838,67629,
    -4,7,-91,117,177,-106,-1428,1698,402,545,-9416,9916,-7154,12980,-61289,66494,
    -5,6,-97,111,163,-127,-1498,1634,185,288,-9585,9838,-8540,11455,-62684,65290,
];

const DCT_INV_SQRT2: i32 = 23170;
const DCT_B0: i32 = 6518;
const DCT_B1: i32 = 12540;
const DCT_S1: i32 = 16703;
const DCT_S2: i32 = 17734;
const DCT_S3: i32 = 19705;
const DCT_S5: i32 = 29491;
const DCT_S6: i32 = 42813;
const DCT_S7: i32 = 83982;

#[inline(always)]
fn mul_q12(a: i32, b: i32) -> i32 { ((a as i64 * b as i64) >> 12) as i32 }
#[inline(always)]
fn mul_q15_i32(a: i32, b: i32) -> i32 { ((a as i64 * b as i64) >> 15) as i32 }
#[inline(always)]
/// Convert synthesis i64 accumulator to i16 PCM.
/// `shift` = 15 - norm_shift: compensates for the per-granule normalization
/// applied in requantize. When norm_shift=0 (quiet frames), shift=15.
/// When norm_shift>0 (loud frames), shift<15 so the synthesis output is
/// amplified to restore correct level — all in i64 space, no overflow possible.
#[inline(always)]
fn mp3d_scale_pcm(a: i64, shift: u32) -> i16 {
    clamp_i16(a >> shift)
}

/// In-place DCT-II on granule buffer (32-subband polyphase analysis)
unsafe fn mp3d_dct_ii(grbuf: *mut i32, n: usize) {
    let mut t: [i32; 32] = [0i32; 32];
    let mut k: usize = 0;
    while k < n {
        let y = grbuf.add(k);
        let x = t.as_mut_ptr();
        let mut i: usize = 0;
        while i < 8 {
            let x0 = *y.add(i * 18);
            let x1 = *y.add((15 - i) * 18);
            let x2 = *y.add((16 + i) * 18);
            let x3 = *y.add((31 - i) * 18);
            let t0 = x0.saturating_add(x3);
            let t1 = x1.saturating_add(x2);
            let sp = G_SEC.as_ptr().add(3 * i);
            let t2 = mul_q12(x1.saturating_sub(x2), *sp);
            let t3 = mul_q12(x0.saturating_sub(x3), *sp.add(1));
            *x.add(i) = t0.saturating_add(t1);
            *x.add(i + 8) = mul_q12(t0.saturating_sub(t1), *sp.add(2));
            *x.add(i + 16) = t3.saturating_add(t2);
            *x.add(i + 24) = mul_q12(t3.saturating_sub(t2), *sp.add(2));
            i += 1;
        }
        let mut j: usize = 0;
        while j < 4 {
            let xp = x.add(j * 8);
            let mut x0=*xp; let mut x1=*xp.add(1); let mut x2=*xp.add(2); let mut x3=*xp.add(3);
            let mut x4=*xp.add(4); let mut x5=*xp.add(5); let mut x6=*xp.add(6); let mut x7=*xp.add(7);
            let mut xt: i32;
            xt=x0.saturating_sub(x7); x0=x0.saturating_add(x7);
            x7=x1.saturating_sub(x6); x1=x1.saturating_add(x6);
            x6=x2.saturating_sub(x5); x2=x2.saturating_add(x5);
            x5=x3.saturating_sub(x4); x3=x3.saturating_add(x4);
            x4=x0.saturating_sub(x3); x0=x0.saturating_add(x3);
            x3=x1.saturating_sub(x2); x1=x1.saturating_add(x2);
            *xp = x0.saturating_add(x1);
            *xp.add(4) = mul_q15_i32(x0.saturating_sub(x1), DCT_INV_SQRT2);
            x5=x5.saturating_add(x6); x6=mul_q15_i32(x6.saturating_add(x7), DCT_INV_SQRT2); x7=x7.saturating_add(xt);
            x3=mul_q15_i32(x3.saturating_add(x4), DCT_INV_SQRT2);
            x5=x5.saturating_sub(mul_q15_i32(x7, DCT_B0)); x7=x7.saturating_add(mul_q15_i32(x5, DCT_B1)); x5=x5.saturating_sub(mul_q15_i32(x7, DCT_B0));
            x0=xt.saturating_sub(x6); xt=xt.saturating_add(x6);
            *xp.add(1)=mul_q15_i32(xt.saturating_add(x7),DCT_S1); *xp.add(2)=mul_q15_i32(x4.saturating_add(x3),DCT_S2);
            *xp.add(3)=mul_q15_i32(x0.saturating_sub(x5),DCT_S3); *xp.add(5)=mul_q15_i32(x0.saturating_add(x5),DCT_S5);
            *xp.add(6)=mul_q15_i32(x4.saturating_sub(x3),DCT_S6); *xp.add(7)=mul_q15_i32(xt.saturating_sub(x7),DCT_S7);
            j += 1;
        }
        let mut yp = y;
        let mut i: usize = 0;
        while i < 7 {
            *yp.add(0*18)=*x.add(i);
            *yp.add(1*18)=(*x.add(16+i)).saturating_add(*x.add(24+i)).saturating_add(*x.add(24+i+1));
            *yp.add(2*18)=(*x.add(8+i)).saturating_add(*x.add(8+i+1));
            *yp.add(3*18)=(*x.add(16+i+1)).saturating_add(*x.add(24+i)).saturating_add(*x.add(24+i+1));
            yp = yp.add(4 * 18);
            i += 1;
        }
        *yp.add(0*18)=*x.add(7);
        *yp.add(1*18)=(*x.add(16+7)).saturating_add(*x.add(24+7));
        *yp.add(2*18)=*x.add(8+7);
        *yp.add(3*18)=*x.add(24+7);
        k += 1;
    }
}

unsafe fn mp3d_synth_pair(pcm: *mut i16, nch: usize, z: *const i32, shift: u32) {
    let mut a: i64;
    a  = (*z.add(14*64) as i64 - *z.add(0) as i64) * 29;
    a += (*z.add(1*64) as i64 + *z.add(13*64) as i64) * 213;
    a += (*z.add(12*64) as i64 - *z.add(2*64) as i64) * 459;
    a += (*z.add(3*64) as i64 + *z.add(11*64) as i64) * 2037;
    a += (*z.add(10*64) as i64 - *z.add(4*64) as i64) * 5153;
    a += (*z.add(5*64) as i64 + *z.add(9*64) as i64) * 6574;
    a += (*z.add(8*64) as i64 - *z.add(6*64) as i64) * 37489;
    a += *z.add(7*64) as i64 * 75038;
    *pcm = mp3d_scale_pcm(a, shift);
    let z2 = z.add(2);
    a  = *z2.add(14*64) as i64 * 104;
    a += *z2.add(12*64) as i64 * 1567;
    a += *z2.add(10*64) as i64 * 9727;
    a += *z2.add(8*64) as i64 * 64019;
    a += *z2.add(6*64) as i64 * -9975;
    a += *z2.add(4*64) as i64 * -45;
    a += *z2.add(2*64) as i64 * 146;
    a += *z2.add(0*64) as i64 * -5;
    *pcm.add(16 * nch) = mp3d_scale_pcm(a, shift);
}

unsafe fn mp3d_synth(xl: *mut i32, dstl: *mut i16, nch: usize, lins: *mut i32, shift: u32) {
    let xr = xl.add(576 * (nch - 1));
    let dstr = dstl.add(nch - 1);
    let zlin = lins.add(15 * 64);
    let w = G_WIN.as_ptr();

    *zlin.add(4*15) = *xl.add(18*16); *zlin.add(4*15+1) = *xr.add(18*16);
    *zlin.add(4*15+2) = *xl; *zlin.add(4*15+3) = *xr;
    *zlin.add(4*31) = *xl.add(1+18*16); *zlin.add(4*31+1) = *xr.add(1+18*16);
    *zlin.add(4*31+2) = *xl.add(1); *zlin.add(4*31+3) = *xr.add(1);

    mp3d_synth_pair(dstr, nch, lins.add(4*15+1), shift);
    mp3d_synth_pair(dstr.add(32*nch), nch, lins.add(4*15+64+1), shift);
    mp3d_synth_pair(dstl, nch, lins.add(4*15), shift);
    mp3d_synth_pair(dstl.add(32*nch), nch, lins.add(4*15+64), shift);

    let mut i: isize = 14;
    while i >= 0 {
        let iu = i as usize;
        *zlin.add(4*iu) = *xl.add(18*(31-iu)); *zlin.add(4*iu+1) = *xr.add(18*(31-iu));
        *zlin.add(4*iu+2) = *xl.add(1+18*(31-iu)); *zlin.add(4*iu+3) = *xr.add(1+18*(31-iu));
        *zlin.add(4*(iu+16)) = *xl.add(1+18*(1+iu)); *zlin.add(4*(iu+16)+1) = *xr.add(1+18*(1+iu));
        let neg_off = zlin.offset(4*(i-16)+2);
        *neg_off = *xl.add(18*(1+iu)); *neg_off.add(1) = *xr.add(18*(1+iu));

        let mut a: [i64; 4] = [0; 4];
        let mut b: [i64; 4] = [0; 4];
        let wp = w.add((14 - iu) * 16);
        let mut kk: usize = 0;
        while kk < 8 {
            let w0 = *wp.add(kk * 2) as i64;
            let w1 = *wp.add(kk * 2 + 1) as i64;
            let vz = zlin.offset(4*i - (kk as isize)*64);
            let vy = zlin.offset(4*i - (15 - kk as isize)*64);
            let mut jj: usize = 0;
            while jj < 4 {
                let vzj = *vz.add(jj) as i64;
                let vyj = *vy.add(jj) as i64;
                let bterm = vzj * w1 + vyj * w0;
                if kk == 0 {
                    *b.as_mut_ptr().add(jj) = bterm;
                    *a.as_mut_ptr().add(jj) = vzj * w0 - vyj * w1;
                } else if (kk & 1) == 1 {
                    *b.as_mut_ptr().add(jj) += bterm;
                    *a.as_mut_ptr().add(jj) += vyj * w1 - vzj * w0;
                } else {
                    *b.as_mut_ptr().add(jj) += bterm;
                    *a.as_mut_ptr().add(jj) += vzj * w0 - vyj * w1;
                }
                jj += 1;
            }
            kk += 1;
        }
        *dstr.add((15-iu)*nch) = mp3d_scale_pcm(*a.as_ptr().add(1), shift);
        *dstr.add((17+iu)*nch) = mp3d_scale_pcm(*b.as_ptr().add(1), shift);
        *dstl.add((15-iu)*nch) = mp3d_scale_pcm(*a.as_ptr().add(0), shift);
        *dstl.add((17+iu)*nch) = mp3d_scale_pcm(*b.as_ptr().add(0), shift);
        *dstr.add((47-iu)*nch) = mp3d_scale_pcm(*a.as_ptr().add(3), shift);
        *dstr.add((49+iu)*nch) = mp3d_scale_pcm(*b.as_ptr().add(3), shift);
        *dstl.add((47-iu)*nch) = mp3d_scale_pcm(*a.as_ptr().add(2), shift);
        *dstl.add((49+iu)*nch) = mp3d_scale_pcm(*b.as_ptr().add(2), shift);
        i -= 1;
    }
}

/// Full granule synthesis for mono or stereo.
/// grbuf: 576 values for ch0, followed by 576 for ch1 if nch==2 (contiguous).
/// pcm: interleaved output (L,R,L,R... for stereo; mono samples for nch=1).
unsafe fn mp3d_synth_granule(
    qmf_state: *mut i32,
    grbuf: *mut i32,
    nch: usize,
    pcm: *mut i16,
    lins: *mut i32,
    pcm_shift: u32,
) {
    let nbands: usize = 18;
    // DCT-II on each channel
    mp3d_dct_ii(grbuf, nbands);
    if nch == 2 {
        mp3d_dct_ii(grbuf.add(576), nbands);
    }
    // Copy qmf history into working buffer
    let mut idx: usize = 0;
    while idx < 15 * 64 { *lins.add(idx) = *qmf_state.add(idx); idx += 1; }
    // Synthesis: produces 32*nch PCM samples per band pair
    let mut band: usize = 0;
    while band < nbands {
        mp3d_synth(grbuf.add(band), pcm.add(32 * nch * band), nch, lins.add(band * 64), pcm_shift);
        band += 2;
    }
    // Save updated qmf history
    let src = lins.add(nbands * 64);
    idx = 0;
    while idx < 15 * 64 { *qmf_state.add(idx) = *src.add(idx); idx += 1; }
}

// Section 9: Mp3State struct definition
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
    channel_mode: u8,  // 0=stereo, 1=joint, 2=dual, 3=mono
    mode_extension: u8,
    has_crc: u8,

    // State machine
    phase: Mp3Phase,
    /// Per-granule normalization shift (reduces requantize output to prevent i32 overflow)
    norm_shift: u8,
    /// Bytes remaining to skip (ID3 tag)
    id3_skip: u32,

    // Side info (flat)
    si_main_data_begin: u16,
    si_private_bits: u8,
    si_scfsi: [u8; 8],  // [ch][band] flattened, using u8 as bool

    // Granule info: [gr][ch] flattened as [4] (gr0ch0, gr0ch1, gr1ch0, gr1ch1)
    gi_part2_3_length: [u16; 4],
    gi_big_values: [u16; 4],
    gi_global_gain: [u8; 4],
    gi_scalefac_compress: [u8; 4],
    gi_window_switching: [u8; 4],
    gi_block_type: [u8; 4],
    gi_mixed_block: [u8; 4],
    gi_table_select: [u8; 12],  // [4][3]
    gi_subblock_gain: [u8; 12], // [4][3]
    gi_region0_count: [u8; 4],
    gi_region1_count: [u8; 4],
    gi_preflag: [u8; 4],
    gi_scalefac_scale: [u8; 4],
    gi_count1table_select: [u8; 4],

    // Scalefactors: [2][2][39] flattened = 156
    scalefactors: [u8; 156],

    // Huffman decoded values
    huff_values: [i32; 576],

    // Frequency lines after requantization: [2][576] flattened (Q30 i32)
    freq_lines: [i32; 1152],

    // IMDCT overlap buffer: [2][576] flattened (Q30 i32)
    overlap: [i32; 1152],

    // Synthesis QMF state: [2][960] (15*64 per channel)
    qmf_state: [i32; 1920],
    // Synthesis working buffer: (18+15)*64 = 2112
    lins: [i32; 2112],

    // Output buffer: stereo interleaved
    out_buf: [i16; 2304], // SAMPLES_PER_FRAME * 2
    out_pos: u16,
    out_len: u16,

    // Diagnostic
    frame_count: u32,

    // Bit reservoir
    main_data: [u8; 2048],
    main_data_len: u16,
    main_data_bit_pos: u16,

    // Saved reservoir: last `reservoir_len` bytes of previous frame's main_data
    // Kept separate because main_data tail gets externally corrupted (DMA/other module)
    reservoir: [u8; 512],
    reservoir_len: u16,

    // Last sample rate sent via IOCTL (0 = not yet sent)
    last_sent_rate: u32,

    // Diagnostic: input channel underrun counter (times we needed data but channel empty)
    underrun_count: u32,
}

// Helper to get granule info index: gr*2+ch
#[inline(always)]
fn gi_idx(gr: usize, ch: usize) -> usize { gr * 2 + ch }

// Helper to get scalefactor index: gr*78 + ch*39 + band
#[inline(always)]
fn sf_idx(gr: usize, ch: usize, band: usize) -> usize { gr * 78 + ch * 39 + band }

// ============================================================================
// Section 11: Internal decode functions
// ============================================================================

/// Decode a complete MP3 frame. Returns number of interleaved samples or negative error.
fn decode_frame(s: &mut Mp3State) -> i32 {
    unsafe {
        let frame_ptr = s.frame_buf.as_ptr();
        let frame_len = s.frame_pos;

        // Parse side information
        let data_start = 4 + if s.has_crc != 0 { 2usize } else { 0 };
        let side_info_size = if s.channels == 1 { 17usize } else { 32 };

        if frame_len < data_start + side_info_size { return -6; }

        // Parse side info
        let si_ret = parse_side_info(s, frame_ptr.add(data_start), side_info_size);
        if si_ret < 0 { return si_ret; }

        // Handle bit reservoir (uses saved reservoir immune to main_data corruption)
        let frame_data_start = data_start + side_info_size;
        let frame_data_len = if frame_len > frame_data_start { frame_len - frame_data_start } else { 0 };
        let reservoir_before = s.reservoir_len;
        accumulate_main_data(s, frame_ptr.add(frame_data_start), frame_data_len);

        // Set bit position
        let keep = s.si_main_data_begin as usize;
        let main_data_start = if keep + frame_data_len <= s.main_data_len as usize {
            s.main_data_len as usize - keep - frame_data_len
        } else {
            0
        };
        s.main_data_bit_pos = (main_data_start * 8) as u16;

        // PROBE 1: Reservoir satisfaction — log when frame needs more reservoir
        // data than was available (would cause Huffman to decode wrong bits)
        if keep > reservoir_before as usize {
            let sys = &*s.syscalls;
            let mut lb = [0u8; 64];
            let bp = lb.as_mut_ptr();
            let tag = b"[mp3] reservoir short f=";
            let mut p = 0usize;
            let mut t = 0usize;
            while t < tag.len() { *bp.add(p) = *tag.as_ptr().add(t); p += 1; t += 1; }
            p += fmt_u32_raw(bp.add(p), s.frame_count);
            let tag2 = b" need=";
            t = 0; while t < tag2.len() { *bp.add(p) = *tag2.as_ptr().add(t); p += 1; t += 1; }
            p += fmt_u32_raw(bp.add(p), keep as u32);
            let tag3 = b" have=";
            t = 0; while t < tag3.len() { *bp.add(p) = *tag3.as_ptr().add(t); p += 1; t += 1; }
            p += fmt_u32_raw(bp.add(p), reservoir_before as u32);
            dev_log(sys, 2, bp, p);
        }

        let num_channels = s.channels as usize;
        let num_granules: usize = 2;

        // Decode granules
        let mut gr: usize = 0;

        while gr < num_granules {
            // Per-granule normalization: compute how much to reduce requantize
            // output to prevent i32 overflow in IMDCT/DCT-II pipeline.
            // max_int_shift is the worst-case shift for this granule (sf=0).
            // We allow int_shift up to 1 safely; anything above is deferred.
            {
                let g0 = *s.gi_global_gain.as_ptr().add(gi_idx(gr, 0)) as i32;
                let g1 = if num_channels > 1 {
                    *s.gi_global_gain.as_ptr().add(gi_idx(gr, 1)) as i32
                } else { g0 };
                let max_gain = if g0 > g1 { g0 } else { g1 };
                let max_exp = max_gain - 210;
                let max_int_shift = max_exp >> 2;
                let ns = max_int_shift - 1;
                s.norm_shift = if ns > 0 { ns as u8 } else { 0 };
            }

            let mut ch: usize = 0;
            while ch < num_channels {
                let ret = decode_granule_channel(s, gr, ch);
                if ret < 0 { return ret; }
                ch += 1;
            }

            // Joint stereo processing
            if s.channel_mode == 1 {
                // MS stereo
                if (s.mode_extension & 0x02) != 0 {
                    process_ms_stereo(s.freq_lines.as_mut_ptr());
                }
                // Intensity stereo
                if (s.mode_extension & 0x01) != 0 {
                    let idx1 = gi_idx(gr, 1);
                    process_intensity_stereo(s.freq_lines.as_mut_ptr(), *s.gi_big_values.as_ptr().add(idx1));
                }
            }

            // Antialiasing butterflies + IMDCT for each channel
            ch = 0;
            while ch < num_channels {
                let idx = gi_idx(gr, ch);
                let bt = *s.gi_block_type.as_ptr().add(idx);
                let mb = *s.gi_mixed_block.as_ptr().add(idx) != 0;

                // Antialiasing butterflies (ISO 11172-3 §2.4.3.4)
                if bt != 2 {
                    let fl = s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES);
                    let sb_limit: usize = if mb { 1 } else { 31 };
                    antialias_butterflies(fl, sb_limit);
                }

                // Reorder short-block spectral values to window-interleaved layout.
                // Uses huff_values as scratch (576 i32, free at this point).
                if bt == 2 {
                    reorder_short(
                        s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES),
                        s.huff_values.as_mut_ptr(),
                        s.sample_rate,
                    );
                }

                // IMDCT with overlap-add (9 values per subband = 288 per channel)
                process_imdct(
                    s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES),
                    s.overlap.as_mut_ptr().add(ch * 288),
                    bt,
                    mb,
                );

                // L3_change_sign: negate odd-indexed samples in odd-numbered subbands
                // Required by the polyphase synthesis filter (ISO 11172-3)
                {
                    let fl = s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES);
                    let mut sb: usize = 1;
                    while sb < 32 {
                        let base = sb * 18;
                        let mut ti: usize = 1;
                        while ti < 18 {
                            let idx = base + ti;
                            *fl.add(idx) = -(*fl.add(idx));
                            ti += 2;
                        }
                        sb += 2;
                    }
                }

                ch += 1;
            }

            // Synthesis: operates on all channels simultaneously.
            // pcm_shift = 15 - norm_shift: compensates for the per-granule normalization
            // inside the i64 synthesis accumulator (no overflow, no post-synthesis clipping).
            let output_offset = gr * GRANULE_SAMPLES * num_channels;
            let pcm_shift = 15u32 - s.norm_shift as u32;
            mp3d_synth_granule(
                s.qmf_state.as_mut_ptr(),
                s.freq_lines.as_mut_ptr(),
                num_channels,
                s.out_buf.as_mut_ptr().add(output_offset),
                s.lins.as_mut_ptr(),
                pcm_shift,
            );

            // PROBE 2: Discontinuity detector — count sign flips in first 48 L-channel
            // samples. Normal audio has <10 flips; decoded garbage has 20+.
            {
                let pcm = s.out_buf.as_ptr().add(output_offset);
                let step = num_channels; // stride for L-channel (1=mono, 2=stereo)
                let check_count: usize = 48;
                let mut flips: u32 = 0;
                let mut prev_sign: i32 = 0; // 0=unset
                let mut ci: usize = 0;
                while ci < check_count {
                    let v = *pcm.add(ci * step);
                    let sign = if v > 0 { 1i32 } else if v < 0 { -1i32 } else { prev_sign };
                    if prev_sign != 0 && sign != 0 && sign != prev_sign {
                        flips += 1;
                    }
                    if sign != 0 { prev_sign = sign; }
                    ci += 1;
                }
                if flips > 20 {
                    let sys = &*s.syscalls;
                    let mut lb = [0u8; 64];
                    let bp = lb.as_mut_ptr();
                    let tag = b"[mp3] glitch f=";
                    let mut p = 0usize;
                    let mut t = 0usize;
                    while t < tag.len() { *bp.add(p) = *tag.as_ptr().add(t); p += 1; t += 1; }
                    p += fmt_u32_raw(bp.add(p), s.frame_count);
                    let tag2 = b" gr=";
                    t = 0; while t < tag2.len() { *bp.add(p) = *tag2.as_ptr().add(t); p += 1; t += 1; }
                    p += fmt_u32_raw(bp.add(p), gr as u32);
                    let tag3 = b" flips=";
                    t = 0; while t < tag3.len() { *bp.add(p) = *tag3.as_ptr().add(t); p += 1; t += 1; }
                    p += fmt_u32_raw(bp.add(p), flips);
                    let tag4 = b" bt=";
                    t = 0; while t < tag4.len() { *bp.add(p) = *tag4.as_ptr().add(t); p += 1; t += 1; }
                    p += fmt_u32_raw(bp.add(p), *s.gi_block_type.as_ptr().add(gi_idx(gr, 0)) as u32);
                    *bp.add(p) = b'/'; p += 1;
                    p += fmt_u32_raw(bp.add(p), if num_channels > 1 {
                        *s.gi_block_type.as_ptr().add(gi_idx(gr, 1)) as u32
                    } else { 0 });
                    dev_log(sys, 2, bp, p);
                }
            }

            gr += 1;
        }

        // If mono, spread to stereo interleaved (process backwards to avoid overwrites)
        if num_channels == 1 {
            let mut i: usize = SAMPLES_PER_FRAME; // 1152
            while i > 0 {
                i -= 1;
                let mono_sample = *s.out_buf.as_ptr().add(i);
                let stereo_idx = i * 2;
                *s.out_buf.as_mut_ptr().add(stereo_idx) = mono_sample;     // L
                *s.out_buf.as_mut_ptr().add(stereo_idx + 1) = mono_sample; // R
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

        // SCFSI
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

        // Granule info
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
                    // Window switching flag set
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

        // Build main_data = saved_reservoir + new_frame_data
        // Use the saved reservoir (immune to external corruption of main_data tail)
        let reservoir_avail = s.reservoir_len as usize;
        let reservoir_use = if keep <= reservoir_avail { keep } else { reservoir_avail };

        // Copy reservoir to front of main_data
        if reservoir_use > 0 {
            let src_start = reservoir_avail - reservoir_use;
            let mut i: usize = 0;
            while i < reservoir_use {
                *s.main_data.as_mut_ptr().add(i) = *s.reservoir.as_ptr().add(src_start + i);
                i += 1;
            }
        }
        s.main_data_len = reservoir_use as u16;

        // Append frame data
        let space = 2048 - s.main_data_len as usize;
        let copy_len = if frame_data_len < space { frame_data_len } else { space };
        let dst_offset = s.main_data_len as usize;
        let mut i: usize = 0;
        while i < copy_len {
            *s.main_data.as_mut_ptr().add(dst_offset + i) = *frame_data.add(i);
            i += 1;
        }
        s.main_data_len += copy_len as u16;

        // Save the tail of main_data as reservoir for next frame
        // (main_data may get corrupted between frames, but reservoir won't)
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

fn decode_granule_channel(s: &mut Mp3State, gr: usize, ch: usize) -> i32 {
    unsafe {
        let idx = gi_idx(gr, ch);
        let _num_channels = s.channels as usize;

        let byte_start = s.main_data_bit_pos as usize / 8;
        let bit_offset = s.main_data_bit_pos as usize - byte_start * 8;

        let data_len = s.main_data_len as usize;
        if byte_start >= data_len { return -6; }

        // Decode scalefactors
        let scalefac_bits = decode_scalefactors(s, gr, ch, byte_start, bit_offset);
        if scalefac_bits < 0 { return scalefac_bits; }

        // Huffman decode
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
                get_sfb_table(s.sample_rate),
            );
            if ret < 0 { return ret; }
        }

        // Requantize (norm_shift reduces output to prevent i32 overflow downstream)
        requantize(
            s.huff_values.as_ptr(),
            s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES),
            s.scalefactors.as_ptr().add(sf_idx(gr, ch, 0)),
            *s.gi_global_gain.as_ptr().add(idx),
            *s.gi_scalefac_scale.as_ptr().add(idx) != 0,
            *s.gi_block_type.as_ptr().add(idx),
            s.gi_subblock_gain.as_ptr().add(idx * 3),
            *s.gi_preflag.as_ptr().add(idx) != 0,
            s.sample_rate,
            s.norm_shift as i32,
        );

        // Advance bit position
        s.main_data_bit_pos += *s.gi_part2_3_length.as_ptr().add(idx);

        0
    }
}

fn decode_scalefactors(s: &mut Mp3State, gr: usize, ch: usize, byte_start: usize, bit_offset: usize) -> i32 {
    unsafe {
        let idx = gi_idx(gr, ch);
        let num_channels = s.channels as usize;
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

        if block_type == 2 {
            if mixed {
                // Mixed block: long bands 0-7
                let mut band: usize = 0;
                while band < 8 {
                    if slen1 > 0 {
                        let v = br_read_bits(&mut reader, slen1);
                        if v < 0 { return -6; }
                        *s.scalefactors.as_mut_ptr().add(sf_base + band) = v as u8;
                        bits_read += slen1 as usize;
                    } else {
                        *s.scalefactors.as_mut_ptr().add(sf_base + band) = 0;
                    }
                    band += 1;
                }
                // Short bands 3-5
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
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
                // Short bands 6-11
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
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
            } else {
                // Pure short blocks
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
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
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
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
            }
        } else {
            // Long blocks
            // Group 0: bands 0-5, Group 1: 6-10, Group 2: 11-15, Group 3: 16-20
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
                        // Copy from previous granule
                        let prev_base = sf_idx(0, ch, 0);
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = *s.scalefactors.as_ptr().add(prev_base + sfb);
                    } else if slen > 0 {
                        let v = br_read_bits(&mut reader, slen);
                        if v < 0 { return -6; }
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = v as u8;
                        bits_read += slen as usize;
                    } else {
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = 0;
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
// Codec API (called by decoder.rs)
// ============================================================================

/// Initialize MP3 codec state.
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

    // Zero synth state
    let mut i: usize = 0;
    while i < 1920 { *s.qmf_state.as_mut_ptr().add(i) = 0; i += 1; }

    // Zero overlap
    i = 0;
    while i < 1152 { *s.overlap.as_mut_ptr().add(i) = 0; i += 1; }

    let sys = &*s.syscalls;
    dev_log(sys, 3, b"[mp3] init".as_ptr(), 10);
}

/// Feed initial detection bytes into MP3 codec.
/// Handles ID3v2 tag skipping and direct sync word detection.
pub unsafe fn mp3_feed_detect(s: &mut Mp3State, buf: *const u8, len: usize) {
    s.frame_pos = 0;
    s.id3_skip = 0;

    // Check for ID3v2 tag: "ID3" + version(2) + flags(1) + size(4) = 10 bytes
    if len >= 3 && *buf == b'I' && *buf.add(1) == b'D' && *buf.add(2) == b'3' {
        if len >= 10 {
            // Parse synchsafe integer size from bytes 6-9
            let s6 = *buf.add(6) as u32;
            let s7 = *buf.add(7) as u32;
            let s8 = *buf.add(8) as u32;
            let s9 = *buf.add(9) as u32;
            let tag_body_size = (s6 << 21) | (s7 << 14) | (s8 << 7) | s9;
            let total_tag_size = 10 + tag_body_size;
            // We already consumed `len` bytes from the channel during detection.
            // Skip the rest of the tag.
            if total_tag_size > len as u32 {
                s.id3_skip = total_tag_size - len as u32;
            }
        }
        return;
    }

    // Non-ID3 detect bytes (0xFF sync word) — do inline sync
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

/// Step the MP3 codec. Returns 0 on success.
pub unsafe fn mp3_step(s: &mut Mp3State) -> i32 {
    if s.syscalls.is_null() { return -1; }
    let sys = &*s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;

    // 1. Drain decoded PCM directly from out_buf to output channel.
    // Write directly — no intermediate io_buf_out copy.
    // Cap at 2048 bytes per write (matches channel buffer sizes).
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
        // Fall through to input processing (separate io_buf)
    }

    // 3. Skip ID3 tag data before sync search
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

    // 4. State machine for input processing
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
            // Only count as underrun when output is also drained (i2s will starve).
            // Normal pipeline latency (waiting for SD read) is not an underrun.
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
        // Only decode when previous output is fully drained
        let result = decode_frame(s);
        if result >= 0 {
            s.out_pos = 0;
            s.out_len = result as u16;
            s.frame_count = s.frame_count.wrapping_add(1);

            // Propagate sample rate downstream when it changes
            if s.sample_rate != s.last_sent_rate && s.sample_rate > 0 {
                let mut rate_buf = [0u8; 4];
                let rb = rate_buf.as_mut_ptr();
                let sr = s.sample_rate;
                *rb = sr as u8;
                *rb.add(1) = (sr >> 8) as u8;
                *rb.add(2) = (sr >> 16) as u8;
                *rb.add(3) = (sr >> 24) as u8;
                dev_channel_ioctl(sys, out_chan, IOCTL_NOTIFY, rb);
                s.last_sent_rate = s.sample_rate;
            }

            // Health probe: log accumulated underrun count (every 64th frame)
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
            // Log error code + all 4 big_values + first table_select per gc
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
        return 2; // Burst — start draining output immediately
    }

    0
}
