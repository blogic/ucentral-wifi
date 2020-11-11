/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *   Copyright (C) 2020 John Crispin <john@phrozen.org> 
 */

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

	unsigned char chandisabled[IEEE80211_CHAN_MAX];
	unsigned char channel[IEEE80211_CHAN_MAX];
	unsigned char chandfs[IEEE80211_CHAN_MAX];
	unsigned char chanpwr[IEEE80211_CHAN_MAX];
	unsigned int freq[IEEE80211_CHAN_MAX];

	char country[4];
	uint32_t dfs_region;

	int tx_ant, rx_ant, tx_ant_avail, rx_ant_avail;
	int band_2g, band_5gl, band_5gu;
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
	uint32_t rx_packets;
	uint32_t tx_packets;
	uint32_t rx_bytes;
	uint32_t tx_bytes;
	uint32_t tx_retries;
	uint32_t tx_failed;
	uint32_t tx_offset;
	uint32_t inactive;

	struct sta_rate rx_rate, tx_rate;
};

int radio_nl80211_init(void);

#endif
