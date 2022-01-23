/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NL_80211_H__
#define _NL_80211_H__

#include <net/if.h>

#include <linux/limits.h>

#include <libubox/avl.h>
#include <libubox/vlist.h>

#define IEEE80211_CHAN_MAX (196 + 1)

struct wifi_phy {
	struct avl_node avl;
	char name[IF_NAMESIZE];
	char path[PATH_MAX];
	struct list_head wifs;

	uint16_t ht_capa;
	uint32_t vht_capa;
	uint16_t he_mac_capa[3];
	uint16_t he_phy_capa[6];

	unsigned char chandisabled[IEEE80211_CHAN_MAX];
	unsigned char channel[IEEE80211_CHAN_MAX];
	unsigned char chandfs[IEEE80211_CHAN_MAX];
	unsigned char chanpwr[IEEE80211_CHAN_MAX];
	unsigned int freq[IEEE80211_CHAN_MAX];

	char country[4];
	uint32_t dfs_region;

	int tx_ant, rx_ant, tx_ant_avail, rx_ant_avail;
	int band_2g, band_5gl, band_5gu, band_6g;
};

struct wifi_iface {
	struct avl_node avl;
	uint8_t addr[6];
	char saddr[18];
	int noise;
	char name[IF_NAMESIZE];
	char ssid[33];
	int type;
	uint32_t tx_power;
	uint32_t freq, freq1, freq2;
	uint32_t width;
	struct wifi_phy *parent;
	struct list_head stas;
	struct list_head phy;
};

struct sta_rate {
	int width;
	uint32_t bitrate;
	int vht;
	int ht;
	int nss;
	int mcs;
	int sgi;
};

struct wifi_station {
	struct avl_node avl;
	uint8_t addr[6];
	char saddr[18];
	struct wifi_iface *parent;
	struct list_head iface;

	int8_t rssi;
	uint32_t rx_packets[2];
	uint32_t tx_packets[2];
	uint32_t rx_bytes[2];
	uint32_t tx_bytes[2];
	uint32_t tx_retries[2];
	uint32_t tx_failed[2];
	uint32_t tx_offset[2];
	uint32_t inactive;
	uint32_t connected;
	uint64_t rx_duration;
	uint64_t tx_duration;

	uint64_t rx_msdu[16];
	uint64_t tx_msdu[16];
	uint64_t tx_msdu_retries[16];
	uint64_t tx_msdu_failed[16];

	struct sta_rate rx_rate, tx_rate;
};

int radio_nl80211_init(void);

#endif
