#ifndef IEEE80211_RADIOTAP_H
#define IEEE80211_RADIOTAP_H

#include <stdint.h>
#include <endian.h>

// Массивы каналов и имен с константами
static const uint32_t ieee80211_radiotap_channels_2GHz[] = {
    [2412] = 1,
    [2417] = 2,
    [2422] = 3,
    [2427] = 4,
    [2432] = 5,
    [2437] = 6,
    [2442] = 7,
    [2447] = 8,
    [2452] = 9,
    [2457] = 10,
    [2462] = 11,
    [2467] = 12,
    [2472] = 13,
    [2484] = 14,
};

static const char *ieee80211_radiotap_names[] = {
    [0] = "TSFT",
    [1] = "Flags",
    [2] = "Rate",
    [3] = "Channel",
    [4] = "FHSS",
    [5] = "dbm_Antenna_Signal",
    [6] = "dbm_Antenna_Noise",
    [7] = "Lock_Quality",
    [8] = "TX_Attenuation",
    [9] = "db_TX_Attenuation",
    [10] = "dbm_TX_Power",
    [11] = "Antenna",
    [12] = "db_Antenna_Signal",
    [13] = "db_Antenna_Noise",
    [14] = "RX_Flags",
    [15] = "TX_Flags",
    [16] = "RTS_retries",
    [17] = "Data_retries",
    [18] = "Channel_plus",
    [19] = "MCS",
    [20] = "A_MPDU_Status",
    [21] = "VHT_Info",
    [22] = "Frame_timestamp",
    [23] = "HE_Info",
    [24] = "HE_MU_Info",
    [25] = "RESERVED_1",
    [26] = "Null_Length_PSDU",
    [27] = "L_SIG",
    [28] = "TLVs",
    [29] = "RadioTap_NS_Next",
    [30] = "Vendor_NS_Next",
    [31] = "Ext"
};

static const char *ieee80211_radiotap_channel_flags_names[] = {
    [0] = "700 MHz",
    [1] = "800 MHz",
    [2] = "900 MHz",
    [4] = "Turbo",
    [5] = "CCK",
    [6] = "OFDM",
    [7] = "2 GHz",
    [8] = "5 GHz",
    [9] = "Passive",
    [10] = "Dynamic CCK-OFDM",
    [11] = "GFSK",
    [12] = "GSM",
    [13] = "Static turbo",
    [14] = "Half-Rate channel 10 MHz",
    [15] = "Quarter-Rate channel 5 MHz"
};

static const char *ieee80211_radiotap_flags_names[] = {
    [0] = "CCP",
    [1] = "Preamble",
    [2] = "WEP",
    [3] = "Fragmentation",
    [4] = "FCS at end",
    [5] = "Data Pad",
    [6] = "Bad FCS",
    [7] = "Short GI"
};

static const char *ieee80211_radiotap_tx_flags_names[] = {
    [0] = "TX Fail",
    [1] = "TX CTS",
    [2] = "TX RTS",
    [3] = "No NACK",
    [4] = "TX no sequence control"
};

static const char *ieee80211_radiotap_rx_flags_names[] = {
    [0] = "RX Bad FCS",
    [1] = "RX PLCP CRC Fail"
};

// Структуры данных
typedef struct {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((packed)) ieee80211_radiotap_header;

typedef enum {
    IEEE80211_RADIOTAP_TSFT                 = 0,
    IEEE80211_RADIOTAP_Flags                = 1,
    IEEE80211_RADIOTAP_Rate                 = 2,
    IEEE80211_RADIOTAP_Channel              = 3,
    IEEE80211_RADIOTAP_FHSS                 = 4,
    IEEE80211_RADIOTAP_dbm_Antenna_Signal   = 5,
    IEEE80211_RADIOTAP_dbm_Antenna_Noise    = 6,
    IEEE80211_RADIOTAP_Lock_Quality         = 7,
    IEEE80211_RADIOTAP_TX_Attenuation       = 8,
    IEEE80211_RADIOTAP_db_TX_Attenuation    = 9,
    IEEE80211_RADIOTAP_dbm_TX_Power         = 10,
    IEEE80211_RADIOTAP_Antenna              = 11,
    IEEE80211_RADIOTAP_db_Antenna_Signal    = 12,
    IEEE80211_RADIOTAP_db_Antenna_Noise     = 13,
    IEEE80211_RADIOTAP_RX_Flags             = 14,
    IEEE80211_RADIOTAP_TX_Flags             = 15,
    IEEE80211_RADIOTAP_RTS_retries          = 16,
    IEEE80211_RADIOTAP_Data_retries         = 17,
    IEEE80211_RADIOTAP_Channel_plus         = 18,
    IEEE80211_RADIOTAP_MCS                  = 19,
    IEEE80211_RADIOTAP_A_MPDU_Status        = 20,
    IEEE80211_RADIOTAP_VHT_Info             = 21,
    IEEE80211_RADIOTAP_Frame_timestamp      = 22,
    IEEE80211_RADIOTAP_HE_Info              = 23,
    IEEE80211_RADIOTAP_HE_MU_Info           = 24,
    IEEE80211_RADIOTAP_RESERVED_1           = 25,
    IEEE80211_RADIOTAP_NUL_Length_PSDU      = 26,
    IEEE80211_RADIOTAP_L_SIG                = 27,
    IEEE80211_RADIOTAP_TLVs                 = 28,
    IEEE80211_RADIOTAP_RadioTap_NS_Next     = 29,
    IEEE80211_RADIOTAP_Vendor_NS_Next       = 30,
    IEEE80211_RADIOTAP_Ext                  = 31
} ieee80211_radiotap_present_flags_t;

static const unsigned char ieee80211_radiotap_presents_size[] = {
    [IEEE80211_RADIOTAP_TSFT]               = 8,
    [IEEE80211_RADIOTAP_Flags]              = 1,
    [IEEE80211_RADIOTAP_Rate]               = 1,
    [IEEE80211_RADIOTAP_Channel]            = 2 * 2,
    [IEEE80211_RADIOTAP_FHSS]               = 2,
    [IEEE80211_RADIOTAP_dbm_Antenna_Signal] = 1,
    [IEEE80211_RADIOTAP_dbm_Antenna_Noise]  = 1,
    [IEEE80211_RADIOTAP_Lock_Quality]       = 2,
    [IEEE80211_RADIOTAP_TX_Attenuation]     = 2,
    [IEEE80211_RADIOTAP_db_TX_Attenuation]  = 2,
    [IEEE80211_RADIOTAP_dbm_TX_Power]       = 1,
    [IEEE80211_RADIOTAP_Antenna]            = 1,
    [IEEE80211_RADIOTAP_db_Antenna_Signal]  = 1,
    [IEEE80211_RADIOTAP_db_Antenna_Noise]   = 1,
    [IEEE80211_RADIOTAP_RX_Flags]           = 2,
    [IEEE80211_RADIOTAP_TX_Flags]           = 2,
    [IEEE80211_RADIOTAP_RTS_retries]        = 1,
    [IEEE80211_RADIOTAP_Data_retries]       = 1,
    [IEEE80211_RADIOTAP_MCS]                = 1 + 1 + 1,
    [IEEE80211_RADIOTAP_A_MPDU_Status]      = 4 + 2 + 1 + 1,
    [IEEE80211_RADIOTAP_VHT_Info]           = 12,
    [IEEE80211_RADIOTAP_Frame_timestamp]    = 12
};

static const unsigned char ieee80211_radiotap_presents_align[] = {
    [IEEE80211_RADIOTAP_TSFT]               = 8,
    [IEEE80211_RADIOTAP_Flags]              = 1,
    [IEEE80211_RADIOTAP_Rate]               = 1,
    [IEEE80211_RADIOTAP_Channel]            = 2,
    [IEEE80211_RADIOTAP_FHSS]               = 2,
    [IEEE80211_RADIOTAP_dbm_Antenna_Signal] = 1,
    [IEEE80211_RADIOTAP_dbm_Antenna_Noise]  = 1,
    [IEEE80211_RADIOTAP_Lock_Quality]       = 2,
    [IEEE80211_RADIOTAP_TX_Attenuation]     = 2,
    [IEEE80211_RADIOTAP_db_TX_Attenuation]  = 2,
    [IEEE80211_RADIOTAP_dbm_TX_Power]       = 1,
    [IEEE80211_RADIOTAP_Antenna]            = 1,
    [IEEE80211_RADIOTAP_db_Antenna_Signal]  = 1,
    [IEEE80211_RADIOTAP_db_Antenna_Noise]   = 1,
    [IEEE80211_RADIOTAP_RX_Flags]           = 2,
    [IEEE80211_RADIOTAP_TX_Flags]           = 2,
    [IEEE80211_RADIOTAP_RTS_retries]        = 1,
    [IEEE80211_RADIOTAP_Data_retries]       = 1,
    [IEEE80211_RADIOTAP_MCS]                = 1,
    [IEEE80211_RADIOTAP_A_MPDU_Status]      = 4,
    [IEEE80211_RADIOTAP_VHT_Info]           = 2,
    [IEEE80211_RADIOTAP_Frame_timestamp]    = 8
};

typedef union {
	struct {
		uint8_t CFP:1;
		uint8_t Preamble:1;
		uint8_t WEP:1;
		uint8_t Fragmentation:1;
		uint8_t FCS_at_END:1;
		uint8_t Data_Pad:1;
		uint8_t Bad_FCS:1;
		uint8_t Short_GI:1;
	};
	uint8_t value;
} ieee80211_radiotap_flags_t;

typedef union {
    struct {
        uint16_t MHz_700:1;  // 1 бит
        uint16_t MHz_800:1;  // 1 бит
        uint16_t MHz_900:1;  // 1 бит
        uint16_t Turbo:1;    // 1 бит
        uint16_t CCK:1;      // 1 бит
        uint16_t OFDM:1;     // 1 бит
        uint16_t GHz_2:1;    // 1 бит
        uint16_t GHz_5:1;    // 1 бит
        uint16_t Passive:1;  // 1 бит
        uint16_t Dynamic_CCK_OFDM:1; // 1 бит
        uint16_t GFSK:1;     // 1 бит
        uint16_t GSM:1;      // 1 бит
        uint16_t Static_turbo:1; // 1 бит
        uint16_t Half_rate_channel_10Mhz:1; // 1 бит
        uint16_t Quarter_rate_channel_5Mhz:1; // 1 бит
        uint16_t reserved:1; // 1 бит
    };
    uint16_t value; // Общий доступ ко всем битам
} ieee80211_radiotap_channel_flags_t;


typedef union {
    struct {
        uint16_t tx_fail:1;
        uint16_t cts:1;
        uint16_t rts:1;
        uint16_t nonack:1;
        uint16_t noseq:1;
        uint16_t reserved_1:3; // 3 бита в запасе, чтобы добить до 8
    };
    uint8_t value;
} ieee80211_radiotap_tx_flags_t;

typedef union {
    struct {
        uint16_t bad_fcs:1;
        uint16_t plcp_crc:1;
        uint16_t reserved_1:6; // Оставляем 6 бит запаса до 8
    };
    uint8_t value;
} ieee80211_radiotap_rx_flags_t;

typedef union {
    struct {
        uint8_t have_bw:1;
        uint8_t have_mcs:1;
        uint8_t have_gi:1;
        uint8_t have_fmt:1;
        uint8_t have_fec:1;
        uint8_t reserved_1:3; // 3 бита запас
    };
    uint8_t value;
} ieee80211_radiotap_mcs_known_t;

typedef union {
    struct {
        uint8_t bw_40:1;
        uint8_t bw20l:1;
        uint8_t bw20u:1;
        uint8_t short_gi:1;
        uint8_t fmt_gf:1;
        uint8_t fec_ldpc:1;
        uint8_t reserved_1:2; // 2 бита запас
    };
    uint8_t value;
} ieee80211_radiotap_mcs_flags_t;

typedef struct {
    ieee80211_radiotap_mcs_known_t known;
    ieee80211_radiotap_mcs_flags_t flags;
    uint8_t mcs_index;
} ieee80211_radiotap_mcs_t;

typedef struct {
	ieee80211_radiotap_header *rt_header;
    uint64_t tsft;
    ieee80211_radiotap_flags_t flags;
    double rate;
    uint16_t channel_frequency;
    uint16_t channel;
    ieee80211_radiotap_channel_flags_t channel_flags;
    int8_t dbm_Antenna_Signal;
    uint8_t antenna;
    ieee80211_radiotap_tx_flags_t tx_flags;
    ieee80211_radiotap_rx_flags_t rx_flags;
    ieee80211_radiotap_mcs_t mcs;
} ieee80211_radiotap_data_t;

extern int radiotap_parse(const uint8_t *packet, ieee80211_radiotap_data_t *data);

#endif // IEEE80211_RADIOTAP_H
