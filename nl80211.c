/* SPDX-License-Identifier: BSD-3-Clause */

#define _GNU_SOURCE
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <glob.h>

#include <net/if.h>
#include <sys/types.h>

#include <linux/if_ether.h>
#include <linux/sockios.h>
#include "nl80211_copy.h"

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <libubox/avl-cmp.h>

#include <libubox/avl.h>
#include <libubox/vlist.h>
#include <libubox/ulog.h>
#include <libubox/uloop.h>

#include <unl.h>

#include "wifi.h"
#include "nl80211.h"

#define min(x,y) ((x) < (y) ? (x) : (y))

static struct blob_buf b;
static struct unl unl;
static struct uloop_fd fd;
static struct uloop_timeout timeout;

static int avl_addrcmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, 6);
}

static struct avl_tree phy_tree = AVL_TREE_INIT(phy_tree, avl_strcmp, false, NULL);
static struct avl_tree wif_tree = AVL_TREE_INIT(wif_tree, avl_strcmp, false, NULL);
static struct avl_tree sta_tree = AVL_TREE_INIT(sta_tree, avl_addrcmp, false, NULL);

static void sysfs_find_path(struct wifi_phy *phy)
{
	char path[PATH_MAX];
	char link[PATH_MAX];
	char *start, *stop;
	glob_t gl;
	unsigned int seq;

	snprintf(path, sizeof(path), "/sys/class/ieee80211/%s", phy->name);
	if (readlink(path, link, sizeof(link)) < 0)
		goto out;

	start = strstr(link, "devices/");
	if (!start)
		goto out;
	start += 8;
	if (strstr(start, "pci/"))
		start = strstr(start, "soc/");
	else if (strstr(start, "/pci"))
		start += 9;
	stop = strstr(start, "/ieee80211");
	if (stop)
		*stop = '\0';

	strcpy(phy->path, start);

	snprintf(path, sizeof(path), "/sys/class/ieee80211/%s/device/ieee80211/*", phy->name);

	if (glob(path, 0, NULL, &gl))
		return;
	for (seq = 0; seq < gl.gl_pathc; seq++) {

		if (!strcmp(basename(gl.gl_pathv[seq]), phy->name))
			break;
	}
	globfree(&gl);
	if (seq)
		sprintf(&phy->path[strlen(phy->path)], "+%d", seq);

	return;

out:
	ULOG_ERR("failed to readlink %s\n", path);
	strcpy(phy->path, phy->name);
}

static int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq < 5935) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq == 5935)
		return 2;
	else if (freq >= 5955 && freq <= 7115)
		return (freq - 5955) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

static void nl80211_parse_rateinfo(struct sta_rate *sta,struct nlattr **ri, char *table)
{
	if (ri[NL80211_RATE_INFO_BITRATE32])
		sta->bitrate = nla_get_u32(ri[NL80211_RATE_INFO_BITRATE32]) * 100;
	else if (ri[NL80211_RATE_INFO_BITRATE])
		sta->bitrate = nla_get_u16(ri[NL80211_RATE_INFO_BITRATE]) * 100;

	if (ri[NL80211_RATE_INFO_VHT_MCS]) {
		sta->vht = 1;
		sta->mcs = nla_get_u8(ri[NL80211_RATE_INFO_VHT_MCS]);

		if (ri[NL80211_RATE_INFO_VHT_NSS])
			sta->nss = nla_get_u8(ri[NL80211_RATE_INFO_VHT_NSS]);
	} else if (ri[NL80211_RATE_INFO_MCS]) {
		sta->ht = 1;
		sta->mcs = nla_get_u8(ri[NL80211_RATE_INFO_MCS]);
	}

	if (ri[NL80211_RATE_INFO_5_MHZ_WIDTH])
		sta->width = 5;
	else if (ri[NL80211_RATE_INFO_10_MHZ_WIDTH])
		sta->width = 10;
	else if (ri[NL80211_RATE_INFO_40_MHZ_WIDTH])
		sta->width = 40;
	else if (ri[NL80211_RATE_INFO_80_MHZ_WIDTH])
		sta->width = 80;
	else if (ri[NL80211_RATE_INFO_80P80_MHZ_WIDTH] ||
		ri[NL80211_RATE_INFO_160_MHZ_WIDTH])
		sta->width = 160;
	else
		sta->width = 20;

	if (ri[NL80211_RATE_INFO_SHORT_GI])
		sta->sgi = 1;
}

static void vif_update_stats(struct wifi_station *sta, struct nlattr **tb)
{
	static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
		[NL80211_RATE_INFO_BITRATE]      = { .type = NLA_U16    },
		[NL80211_RATE_INFO_MCS]          = { .type = NLA_U8     },
		[NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG   },
		[NL80211_RATE_INFO_SHORT_GI]     = { .type = NLA_FLAG   },
	};

	static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32    },
		[NL80211_STA_INFO_RX_PACKETS]    = { .type = NLA_U32    },
		[NL80211_STA_INFO_TX_PACKETS]    = { .type = NLA_U32    },
		[NL80211_STA_INFO_RX_BITRATE]    = { .type = NLA_NESTED },
		[NL80211_STA_INFO_TX_BITRATE]    = { .type = NLA_NESTED },
		[NL80211_STA_INFO_SIGNAL]        = { .type = NLA_U8     },
		[NL80211_STA_INFO_SIGNAL_AVG]    = { .type = NLA_U8     },
		[NL80211_STA_INFO_RX_BYTES]      = { .type = NLA_U32    },
		[NL80211_STA_INFO_TX_BYTES]      = { .type = NLA_U32    },
		[NL80211_STA_INFO_TX_RETRIES]    = { .type = NLA_U32    },
		[NL80211_STA_INFO_TX_FAILED]     = { .type = NLA_U32    },
		[NL80211_STA_INFO_T_OFFSET]      = { .type = NLA_U64    },
		[NL80211_STA_INFO_STA_FLAGS] =
			{ .minlen = sizeof(struct nl80211_sta_flag_update) },
	};

	struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1] = { };

	if (!tb[NL80211_ATTR_STA_INFO])
		return;
	if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
			     tb[NL80211_ATTR_STA_INFO], stats_policy))
		return;
	if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
		sta->rssi = (int32_t) nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);
	if (sinfo[NL80211_STA_INFO_RX_PACKETS])
		sta->rx_packets[0] = nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]);
	if (sinfo[NL80211_STA_INFO_TX_PACKETS])
		sta->tx_packets[0] = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]);
	if (sinfo[NL80211_STA_INFO_RX_BYTES])
		sta->rx_bytes[0] = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);
	if (sinfo[NL80211_STA_INFO_TX_BYTES])
		sta->tx_bytes[0] = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);
	if (sinfo[NL80211_STA_INFO_TX_RETRIES])
		sta->tx_retries[0] = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);
	if (sinfo[NL80211_STA_INFO_TX_FAILED])
		sta->tx_failed[0] = nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);
	if (sinfo[NL80211_STA_INFO_T_OFFSET])
		sta->tx_offset[0] = nla_get_u32(sinfo[NL80211_STA_INFO_T_OFFSET]);
	if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
		sta->inactive[0] = nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]);
	if (sinfo[NL80211_STA_INFO_RX_BITRATE] &&
	    !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE],
			      rate_policy))
		nl80211_parse_rateinfo(&sta->rx_rate, rinfo, "rx_rate");
	if (sinfo[NL80211_STA_INFO_TX_BITRATE] &&
	    !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE],
			      rate_policy))
		nl80211_parse_rateinfo(&sta->tx_rate, rinfo, "tx_rate");
}

static void nl80211_add_station(struct nlattr **tb, char *ifname)
{
	struct wifi_station *sta;
	struct wifi_iface *wif;
	uint8_t *addr;

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	addr = nla_data(tb[NL80211_ATTR_MAC]);
	sta = avl_find_element(&sta_tree, addr, sta, avl);
	if (sta) {
		vif_update_stats(sta, tb);
		return;
	}

	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif)
		return;
	sta = malloc(sizeof(*sta));
	if (!sta)
		return;

	memset(sta, 0, sizeof(*sta));
	memcpy(sta->addr, addr, 6);
	sta->avl.key = sta->addr;
	sta->parent = wif;
	avl_insert(&sta_tree, &sta->avl);
	list_add(&sta->iface, &wif->stas);
	snprintf(sta->saddr, sizeof(sta->saddr),
		 "%02x:%02x:%02x:%02x:%02x:%02x",
		 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	vif_update_stats(sta, tb);
}

static void _nl80211_del_station(struct wifi_station *sta)
{
	list_del(&sta->iface);
	avl_delete(&sta_tree, &sta->avl);
	free(sta);
}

static void nl80211_del_station(struct nlattr **tb, char *ifname)
{
	struct wifi_station *sta;
	uint8_t *addr;

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	addr = nla_data(tb[NL80211_ATTR_MAC]);
	sta = avl_find_element(&sta_tree, addr, sta, avl);
	if (!sta) {
		return;
	}

	_nl80211_del_station(sta);
}

static void nl80211_add_iface(struct nlattr **tb, char *ifname, char *phyname)
{
	struct wifi_iface *wif;
	uint8_t *addr;

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	addr = nla_data(tb[NL80211_ATTR_MAC]);
	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif) {
		wif = malloc(sizeof(*wif));
		if (!wif)
			return;

		memset(wif, 0, sizeof(*wif));
		memcpy(wif->addr, addr, 6);
		strncpy(wif->name, ifname, IF_NAMESIZE);
		wif->avl.key = wif->name;
		INIT_LIST_HEAD(&wif->stas);
		avl_insert(&wif_tree, &wif->avl);
		memcpy(wif->addr, addr, 6);
		wif->parent = avl_find_element(&phy_tree, phyname, wif->parent, avl);
		if (wif->parent)
			list_add(&wif->phy, &wif->parent->wifs);
		snprintf(wif->saddr, sizeof(wif->saddr),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	}

	if (tb[NL80211_ATTR_SSID]) {
		unsigned int len = nla_len(tb[NL80211_ATTR_SSID]);

		if (len >= sizeof(wif->ssid))
			len = sizeof(wif->ssid) - 1;

		memcpy(wif->ssid, nla_data(tb[NL80211_ATTR_SSID]), len);
		wif->ssid[len] = 0;
	} else
		*wif->ssid = '\0';
	if (tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL])
		wif->tx_power = nla_get_u32(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) / 100;
	else
		wif->tx_power = 0;
	if (tb[NL80211_ATTR_IFTYPE])
		wif->type = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);
	else
		wif->type = 0;
	if (tb[NL80211_ATTR_WIPHY_FREQ])
		wif->freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
	else
		wif->freq = 0;
	if (tb[NL80211_ATTR_CENTER_FREQ1])
		wif->freq1 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]);
	else
		wif->freq1 = 0;
	if (tb[NL80211_ATTR_CENTER_FREQ2])
		wif->freq2 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]);
	else
		wif->freq2 = 0;
	if (tb[NL80211_ATTR_CHANNEL_WIDTH])
		wif->width = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);
	else
		wif->width = 0;
}

static void _nl80211_del_iface(struct wifi_iface *wif)
{
	struct wifi_station *sta, *tmp;

	list_del(&wif->phy);
	list_for_each_entry_safe(sta, tmp, &wif->stas, iface)
		_nl80211_del_station(sta);
	avl_delete(&wif_tree, &wif->avl);
	free(wif);
}

static void nl80211_del_iface(struct nlattr **tb, char *ifname)
{
	struct wifi_iface *wif;

	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif)
		return;
	_nl80211_del_iface(wif);
}

static void nl80211_add_phy(struct nlattr **tb, char *name)
{
	struct wifi_phy *phy;

	phy = avl_find_element(&phy_tree, name, phy, avl);
	if (!phy) {
		phy = malloc(sizeof(*phy));
		if (!phy)
			return;

		memset(phy, 0, sizeof(*phy));
		strncpy(phy->name, name, IF_NAMESIZE);
		sysfs_find_path(phy);
		phy->avl.key = phy->name;
		INIT_LIST_HEAD(&phy->wifs);
		avl_insert(&phy_tree, &phy->avl);
	}

	if (tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX] &&
	    tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX]) {
		phy->tx_ant_avail = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX]);
		phy->rx_ant_avail = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX]);
	}

	if (tb[NL80211_ATTR_WIPHY_ANTENNA_TX] &&
	    tb[NL80211_ATTR_WIPHY_ANTENNA_RX]) {
		phy->tx_ant = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_TX]);
		phy->rx_ant = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_RX]);
	}

	if (tb[NL80211_ATTR_DFS_REGION])
		phy->dfs_region = nla_get_u32(tb[NL80211_ATTR_DFS_REGION]);
	if (tb[NL80211_ATTR_REG_ALPHA2])
		strncpy(phy->country, nla_get_string(tb[NL80211_ATTR_REG_ALPHA2]), sizeof(phy->dfs_region));
	if (tb[NL80211_ATTR_WIPHY_BANDS]) {
		struct nlattr *nl_band = NULL;
		int rem_band = 0;

		nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
			struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

			nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band),
				  nla_len(nl_band), NULL);

			if (tb_band[NL80211_BAND_ATTR_HT_CAPA])
				phy->ht_capa = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
			if (tb_band[NL80211_BAND_ATTR_VHT_CAPA])
				phy->vht_capa = nla_get_u32(tb_band[NL80211_BAND_ATTR_VHT_CAPA]);

			if (tb_band[NL80211_BAND_ATTR_IFTYPE_DATA]) {
				struct nlattr *nl_iftype;
				int rem_band;

				nla_for_each_nested(nl_iftype, tb_band[NL80211_BAND_ATTR_IFTYPE_DATA], rem_band) {
					struct nlattr *tb_he[NL80211_BAND_IFTYPE_ATTR_MAX + 1];
					struct nlattr *tb_flags[NL80211_IFTYPE_MAX + 1];

					nla_parse(tb_he, NL80211_BAND_IFTYPE_ATTR_MAX,
						  nla_data(nl_iftype), nla_len(nl_iftype), NULL);
					if (!tb_he[NL80211_BAND_IFTYPE_ATTR_IFTYPES])
						continue;
					if (nla_parse_nested(tb_flags, NL80211_IFTYPE_MAX,
							     tb_he[NL80211_BAND_IFTYPE_ATTR_IFTYPES], NULL))
						continue;
					if (!tb_flags[NL80211_IFTYPE_AP])
						continue;
					if (tb_he[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]) {
						unsigned int len;

						len  = nla_len(tb_he[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]);
						if (len > sizeof(phy->he_mac_capa))
							len = sizeof(phy->he_mac_capa);
						memcpy(phy->he_mac_capa, nla_data(tb_he[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]), len);
					}

					if (tb_he[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]) {
						unsigned int len;

						len = nla_len(tb_he[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]);

						if (len > sizeof(phy->he_phy_capa) - 1)
							len = sizeof(phy->he_phy_capa) - 1;
						memcpy(&((__u8 *)phy->he_phy_capa)[1], nla_data(tb_he[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]), len);
					}
				}
			}

			if (tb_band[NL80211_BAND_ATTR_FREQS]) {
			        struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
				struct nlattr *nl_freq = NULL;
				int rem_freq = 0;

				nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
					static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
						[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
						[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
						[NL80211_FREQUENCY_ATTR_NO_IR] = { .type = NLA_FLAG },
						[__NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
						[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
						[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
					};
					uint32_t freq;
					int chan;

					nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq),
						  nla_len(nl_freq), freq_policy);
					if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
						continue;

					freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
					chan = ieee80211_frequency_to_channel(freq);
					if (chan >= IEEE80211_CHAN_MAX) {
						ULOG_ERR("%s: found invalid channel %d\n", phy->name, chan);
						continue;
					}

					if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
						phy->chandisabled[chan] = 1;
						continue;
					}
					phy->freq[chan] = freq;
					phy->channel[chan] = 1;
					phy->chandfs[chan] = 1;
					if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] &&
					    !tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
						phy->chanpwr[chan] = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]) / 10;
					if (freq >= 6000) {
						phy->band_2g = 0;
						phy->band_5gl = 0;
						phy->band_5gu = 0;
						phy->band_6g = 1;
					} else if (chan <= 16)
						phy->band_2g = 1;
					else if (chan >= 32 && chan <= 68)
						phy->band_5gl = 1;
					else if (chan >= 96 && chan <= 173)
						phy->band_5gu = 1;
				}
			}
		}
	}
}

static void nl80211_del_phy(struct nlattr **tb, char *name)
{
	struct wifi_iface *wif, *tmp;
	struct wifi_phy *phy;

	phy = avl_find_element(&phy_tree, name, phy, avl);
	if (!phy)
		return;
	list_for_each_entry_safe(wif, tmp, &phy->wifs, phy)
		_nl80211_del_iface(wif);
	avl_delete(&phy_tree, &phy->avl);
	free(phy);
}

static int nl80211_recv(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	char ifname[IFNAMSIZ] = {};
	char phyname[IFNAMSIZ] = {};
	int ifidx = -1, phy = -1;

	memset(tb, 0, sizeof(tb));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_IFINDEX]) {
		ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
		if_indextoname(ifidx, ifname);

	} else if (tb[NL80211_ATTR_IFNAME]) {
	        strncpy(ifname, nla_get_string(tb[NL80211_ATTR_IFNAME]), IFNAMSIZ);
	}

	if (tb[NL80211_ATTR_WIPHY]) {
		phy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
		if (tb[NL80211_ATTR_WIPHY_NAME])
			strncpy(phyname, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]), IFNAMSIZ);
		else
			snprintf(phyname, sizeof(phyname), "phy%d", phy);
	}

	switch (gnlh->cmd) {
	case NL80211_CMD_NEW_STATION:
		nl80211_add_station(tb, ifname);
		break;
	case NL80211_CMD_DEL_STATION:
		nl80211_del_station(tb, ifname);
		break;
	case NL80211_CMD_NEW_INTERFACE:
		nl80211_add_iface(tb, ifname, phyname);
		break;
	case NL80211_CMD_DEL_INTERFACE:
		nl80211_del_iface(tb, ifname);
		break;
	case NL80211_CMD_DEL_WIPHY:
		nl80211_del_phy(tb, phyname);
		break;
	case NL80211_CMD_NEW_WIPHY:
	case NL80211_CMD_GET_WIPHY:
		nl80211_add_phy(tb, phyname);
		break;
	default:
		//syslog(0, "%s:%s[%d]%d\n", __FILE__, __func__, __LINE__, gnlh->cmd);
		break;
	}

	return NL_OK;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	return NL_SKIP;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static void nl80211_cb(struct uloop_fd *u, unsigned int statuss)
{
	struct nl_cb *cb;

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, NULL);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_recv, NULL);
	nl_recvmsgs(unl.sock, cb);
	nl_cb_put(cb);
}

static void nl80211_poll_stations(struct uloop_timeout *t)
{
	struct wifi_iface *wif = NULL;
	avl_for_each_element(&wif_tree, wif, avl) {
		struct nl_msg *msg;

		msg = unl_genl_msg(&unl, NL80211_CMD_GET_STATION, true);
		nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(wif->name));
		unl_genl_request(&unl, msg, nl80211_recv, NULL);
	}
	uloop_timeout_set(t, 5 * 1000);
}

static void blobmsg_add_chwidth(struct blob_buf *bbuf, const char *name, uint32_t chwidth)
{
	switch(chwidth) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		blobmsg_add_string(bbuf, name, "20_NOHT");
		break;
	case NL80211_CHAN_WIDTH_20:
		blobmsg_add_string(bbuf, name, "20");
		break;
	case NL80211_CHAN_WIDTH_40:
		blobmsg_add_string(bbuf, name, "40");
		break;
	case NL80211_CHAN_WIDTH_80:
		blobmsg_add_string(bbuf, name, "80");
		break;
	case NL80211_CHAN_WIDTH_80P80:
		blobmsg_add_string(bbuf, name, "80p80");
		break;
	case NL80211_CHAN_WIDTH_160:
		blobmsg_add_string(bbuf, name, "160");
		break;
	case NL80211_CHAN_WIDTH_5:
		blobmsg_add_string(bbuf, name, "6");
		break;
	case NL80211_CHAN_WIDTH_10:
		blobmsg_add_string(bbuf, name, "10");
		break;
	}
}

static int phy_find_hwmon(char *phy, char *hwmon)
{
        char tmp[PATH_MAX];
        glob_t gl;

        *hwmon = '\0';
        snprintf(tmp, sizeof(tmp), "/sys/class/ieee80211/%s/device/hwmon/*", phy);
        if (glob(tmp, GLOB_NOSORT | GLOB_MARK, NULL, &gl))
                return -1;
        if (gl.gl_pathc) {
                strcpy(hwmon, gl.gl_pathv[0]);
                strncat(hwmon, "temp1_input", PATH_MAX);
        }
        globfree(&gl);

        return 0;
}

static int phy_get_temp(char *phy)
{
	char hwmon_path[PATH_MAX];
	FILE *fp = NULL;
	int32_t t = 0;

	if (phy_find_hwmon(phy, hwmon_path))
		return -1;

	fp = fopen(hwmon_path, "r");
	if (!fp)
		return -1;
	if (fscanf(fp,"%d", &t) == EOF)
		t = 0;
	fclose(fp);

	return t;
}

static char *iftype_string[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_STATION] = "station",
	[NL80211_IFTYPE_AP] = "ap",
	[NL80211_IFTYPE_MESH_POINT] = "mesh",
};

static int iface_is_up(char *iface)
{
	char buf[8] = {};
	char *path;
	FILE *fp;

	if (asprintf(&path, "/sys/class/net/%s/operstate", iface) < 0)
		return 0;

	fp = fopen(path, "r");
	if (!fp)
		return 0;
	if (fread(buf,sizeof(buf), 1, fp) == 1)
		ULOG_ERR("failed to open %s\n", path);
	fclose(fp);

	if (!strncmp(buf, "up", 2))
		return 1;
	return 0;
}

static void dump_band(struct wifi_phy *phy)
{
	void *a = blobmsg_open_array(&b, "band");

	if (phy->band_2g)
		blobmsg_add_string(&b, NULL, "2G");
	if (phy->band_5gl || phy->band_5gu)
		blobmsg_add_string(&b, NULL, "5G");
	if (phy->band_6g)
		blobmsg_add_string(&b, NULL, "6G");
	blobmsg_close_table(&b, a);
}

int dump_phy(struct ubus_context *ctx,
	     struct ubus_object *obj,
	     struct ubus_request_data *req,
	     const char *method, struct blob_attr *msg)
{
	struct wifi_phy *phy;

	blob_buf_init(&b, 0);

	avl_for_each_element(&phy_tree, phy, avl) {
		void *p = blobmsg_open_table(&b, phy->path);
		int temp = phy_get_temp(phy->name);
		void *c;
		int ch, freq;
		int i;

		dump_band(phy);

		if (*phy->country)
			blobmsg_add_string(&b, "country", phy->country);
		if (phy->dfs_region)
			blobmsg_add_u32(&b, "dfs_region", phy->dfs_region);

		if (phy->ht_capa)
			blobmsg_add_u32(&b, "ht_capa", phy->ht_capa);

		if (phy->vht_capa)
			blobmsg_add_u32(&b, "vht_capa", phy->vht_capa);
		if (phy->he_mac_capa[0]) {
			c = blobmsg_open_array(&b, "he_mac_capa");

			for (i = 0; i < 3; i++)
				blobmsg_add_u16(&b, "he_mac_capa", phy->he_mac_capa[i]);
			blobmsg_close_table(&b, c);
		}
		if (phy->he_phy_capa[0]) {
			c = blobmsg_open_array(&b, "he_phy_capa");
			for (i = 0; i < 6; i++)
				blobmsg_add_u16(&b, "he_phy_capa", phy->he_phy_capa[i]);
			blobmsg_close_table(&b, c);
		}

		c = blobmsg_open_array(&b, "htmode");
		if (phy->ht_capa) {
			blobmsg_add_string(&b, NULL, "HT20");
			if (phy->ht_capa & 0x2)
				blobmsg_add_string(&b, NULL, "HT40");
		}
		if (phy->vht_capa) {
			int chwidth = (phy->vht_capa >> 2) & 0x3;

			blobmsg_add_string(&b, NULL, "VHT20");
			blobmsg_add_string(&b, NULL, "VHT40");
			blobmsg_add_string(&b, NULL, "VHT80");
			switch (chwidth) {
			case 2:
				blobmsg_add_string(&b, NULL, "VHT80+80");
				/* fall through */
			case 1:
				blobmsg_add_string(&b, NULL, "VHT160");
				break;
			}
		}
		if (phy->he_phy_capa[0]) {
			int chwidth = (phy->he_phy_capa[0] >> 8) & 0xff;

			blobmsg_add_string(&b, NULL, "HE20");
			if (chwidth & 0x2 || chwidth & 0x4)
				blobmsg_add_string(&b, NULL, "HE40");
			if (chwidth & 0x4)
				blobmsg_add_string(&b, NULL, "HE80");
			if (chwidth & 0x8 || chwidth & 0x10)
				blobmsg_add_string(&b, NULL, "HE160");
			if (chwidth & 0x10)
				blobmsg_add_string(&b, NULL, "HE80+80");
		}
		blobmsg_close_table(&b, c);


		if (phy->tx_ant_avail)
			blobmsg_add_u32(&b, "tx_ant", phy->tx_ant_avail);
		if (phy->rx_ant_avail)
			blobmsg_add_u32(&b, "rx_ant", phy->rx_ant_avail);
		if (temp / 1000)
			blobmsg_add_u32(&b, "temperature", temp / 1000);

		c = blobmsg_open_array(&b, "channels");
		for (ch = 0; ch < IEEE80211_CHAN_MAX; ch++) {
			if (phy->channel[ch])
				blobmsg_add_u16(&b, NULL, ch);
		}

		blobmsg_close_array(&b, c);

		c = blobmsg_open_array(&b, "frequencies");
		for (freq = 0; freq < IEEE80211_CHAN_MAX; freq++) {
			if (phy->freq[freq])
				blobmsg_add_u16(&b, NULL, phy->freq[freq]);
		}
		blobmsg_close_array(&b, c);

		blobmsg_close_table(&b, p);
	}
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
}

int dump_iface(struct ubus_context *ctx,
	       struct ubus_object *obj,
	       struct ubus_request_data *req,
	       const char *method, struct blob_attr *msg)
{
	struct wifi_phy *phy;
	struct nl_msg *nl;

	nl = unl_genl_msg(&unl, NL80211_CMD_GET_INTERFACE, true);
	unl_genl_request(&unl, nl, nl80211_recv, NULL);

	blob_buf_init(&b, 0);

	avl_for_each_element(&phy_tree, phy, avl) {
		void *p = NULL;
		struct wifi_iface *wif;

		list_for_each_entry(wif, &phy->wifs, phy) {
			static char buf[10];
			void *w, *f;

			if (!wif->name || !*wif->name || !wif->type)
				continue;
			if (!iftype_string[wif->type])
				continue;

			if (!iface_is_up(wif->name))
				continue;

			if (p)
				p = blobmsg_open_table(&b, phy->path);
			w = blobmsg_open_table(&b, wif->name);

			if (*wif->ssid)
				blobmsg_add_string(&b, "ssid", wif->ssid);
			blobmsg_add_string(&b, "mode", iftype_string[wif->type]);
			f = blobmsg_open_array(&b, "channel");
			if (wif->freq)
				blobmsg_add_u32(&b, NULL, ieee80211_frequency_to_channel(wif->freq));
			if (wif->freq1)
				blobmsg_add_u32(&b, NULL, ieee80211_frequency_to_channel(wif->freq1));
			if (wif->freq2)
				blobmsg_add_u32(&b, NULL, ieee80211_frequency_to_channel(wif->freq2));
			blobmsg_close_array(&b, f);

			blobmsg_add_chwidth(&b, "ch_width", wif->width);
			if (wif->tx_power)
				blobmsg_add_u32(&b, "tx_power", wif->tx_power);
			blobmsg_add_string(&b, "bssid", wif->saddr);

			if (wif->noise) {
				snprintf(buf, sizeof(buf), "%d", wif->noise);
				blobmsg_add_string(&b, "noise", buf);
			}

			blobmsg_close_array(&b, w);
		}
		if (p)
			blobmsg_close_table(&b, p);
	}
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
}

static void dump_rate(char *name, struct sta_rate *rate)
{
	void *r = blobmsg_open_table(&b, name);

	if (rate->width)
		blobmsg_add_u32(&b, "chwidth", rate->width);
	if (rate->bitrate)
		blobmsg_add_u32(&b, "bitrate", rate->bitrate);
	if (rate->vht)
		blobmsg_add_u8(&b, "vht", 1);
	if (rate->ht)
		blobmsg_add_u8(&b, "ht", 1);
	if (rate->nss)
		blobmsg_add_u32(&b, "nss", rate->nss);
	if (rate->mcs)
		blobmsg_add_u32(&b, "mcs", rate->mcs);
	if (rate->sgi)
		blobmsg_add_u8(&b, "sgi", 1);

	blobmsg_close_table(&b, r);
}

static int get_counter_delta(uint32_t *counter)
{
	uint32_t delta;

	if (counter[0] < counter[1])
		delta = UINT32_MAX - counter[1] + counter[0];
	else
		delta = counter[0] - counter[1];

	counter[1] = counter[0];

	return delta;
}

int dump_station(struct ubus_context *ctx,
		 struct ubus_object *obj,
		 struct ubus_request_data *req,
		 const char *method, struct blob_attr *msg)
{
	struct wifi_phy *phy;

	blob_buf_init(&b, 0);

	avl_for_each_element(&phy_tree, phy, avl) {
		struct wifi_iface *wif;

		list_for_each_entry(wif, &phy->wifs, phy) {
			struct wifi_station *sta;
			void *w = NULL;

			if (!wif->name || !*wif->name)
				continue;

			list_for_each_entry(sta, &wif->stas, iface) {
				void *s;

				if (!w)
					w = blobmsg_open_array(&b, wif->name);

				s = blobmsg_open_table(&b, NULL);
				blobmsg_add_string(&b, "bssid", sta->saddr);
				if (sta->rssi)
					blobmsg_add_u32(&b, "rssi", sta->rssi);
				if (sta->rx_packets)
					blobmsg_add_u32(&b, "rx_packets", get_counter_delta(sta->rx_packets));
				if (sta->tx_packets)
					blobmsg_add_u32(&b, "tx_packets", get_counter_delta(sta->tx_packets));
				if (sta->rx_bytes)
					blobmsg_add_u32(&b, "rx_bytes", get_counter_delta(sta->rx_bytes));
				if (sta->tx_bytes)
					blobmsg_add_u32(&b, "tx_bytes", get_counter_delta(sta->tx_bytes));
				if (sta->tx_retries)
					blobmsg_add_u32(&b, "tx_retries", get_counter_delta(sta->tx_retries));
				if (sta->tx_failed)
					blobmsg_add_u32(&b, "tx_failed", get_counter_delta(sta->tx_failed));
				if (sta->tx_offset)
					blobmsg_add_u32(&b, "tx_offset", get_counter_delta(sta->tx_offset));
				if (sta->tx_offset)
					blobmsg_add_u32(&b, "tx_offset", get_counter_delta(sta->tx_offset));
				dump_rate("rx_rate", &sta->rx_rate);
				dump_rate("tx_rate", &sta->tx_rate);
				blobmsg_close_table(&b, s);
			}
			if (w)
				blobmsg_close_array(&b, w);
		}
	}
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
}

static void
print_mac(char *mac_addr, const unsigned char *arg)
{
	sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
		arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
}

static int
nl80211_scan_dump_recv(struct nl_msg *msg, void *arg)
{
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_TSF]                  = { .type = NLA_U64 },
		[NL80211_BSS_FREQUENCY]            = { .type = NLA_U32 },
		[NL80211_BSS_BSSID]                = { 0 },
		[NL80211_BSS_BEACON_INTERVAL]      = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY]           = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { 0 },
		[NL80211_BSS_SIGNAL_MBM]           = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC]        = { .type = NLA_U8  },
		[NL80211_BSS_STATUS]               = { .type = NLA_U32 },
		[NL80211_BSS_SEEN_MS_AGO]          = { .type = NLA_U32 },
		[NL80211_BSS_BEACON_IES]           = { 0 },
	};

	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1] = {};
	struct nlattr *tb[NL80211_ATTR_MAX + 1] = {};
	char mac[18], ssid[33] = {};
	bool verbose = (bool) arg;
	void *c;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_BSS] ||
	    nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) ||
	    !bss[NL80211_BSS_BSSID])
		return NL_OK;

	print_mac(mac, nla_data(bss[NL80211_BSS_BSSID]));
	c = blobmsg_open_table(&b, mac);

	if (verbose && bss[NL80211_BSS_TSF])
		blobmsg_add_u64(&b, "tsf", nla_get_u64(bss[NL80211_BSS_TSF]));
	if (bss[NL80211_BSS_FREQUENCY])
		blobmsg_add_u32(&b, "channel",
			        ieee80211_frequency_to_channel((int)nla_get_u32(bss[NL80211_BSS_FREQUENCY])));
	if (bss[NL80211_BSS_SIGNAL_MBM])
		blobmsg_add_u32(&b, "signal", ((int) nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM])) / 100);
	if (verbose && bss[NL80211_BSS_SEEN_MS_AGO])
		blobmsg_add_u32(&b, "lastseen", nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]));
	if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		int ielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
		unsigned char *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
		int len;

		while (ielen >= 2 && ielen >= ie[1]) {
			switch (ie[0]) {
			case 0: /* SSID */
			case 114: /* Mesh ID */
				len = min(ie[1], 32 + 1);
				memcpy(ssid, ie + 2, len);
				ssid[len] = 0;
				if (len)
					blobmsg_add_string(&b, "ssid", ssid);
				break;
			}

			ielen -= ie[1] + 2;
			ie += ie[1] + 2;
		}
	}
	blobmsg_close_table(&b, c);
	return NL_OK;
}

static int
nl80211_survey_recv(struct nl_msg *msg, void *arg)
{
	static struct nla_policy sp[NL80211_SURVEY_INFO_MAX + 1] = {
		[NL80211_SURVEY_INFO_FREQUENCY]         = { .type = NLA_U32 },
		[NL80211_SURVEY_INFO_TIME]              = { .type = NLA_U64 },
		[NL80211_SURVEY_INFO_TIME_TX]           = { .type = NLA_U64 },
		[NL80211_SURVEY_INFO_TIME_RX]           = { .type = NLA_U64 },
		[NL80211_SURVEY_INFO_TIME_BUSY]         = { .type = NLA_U64 },
		[NL80211_SURVEY_INFO_TIME_EXT_BUSY]     = { .type = NLA_U64 },
		[NL80211_SURVEY_INFO_TIME_SCAN]         = { .type = NLA_U64 },
		[NL80211_SURVEY_INFO_NOISE]             = { .type = NLA_U8 },
	};

	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *si[NL80211_SURVEY_INFO_MAX + 1] = {};
	struct nlattr *tb[NL80211_ATTR_MAX + 1] = {};
	int *filter = arg, channel = 0;
	void *c;

	memset(tb, 0, sizeof(tb));
	memset(si, 0, sizeof(si));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_SURVEY_INFO])
		return NL_OK;

	if (nla_parse_nested(si, NL80211_SURVEY_INFO_MAX,
			     tb[NL80211_ATTR_SURVEY_INFO], sp)) {
		return NL_SKIP;
	}

	if (si[NL80211_SURVEY_INFO_FREQUENCY])
		channel = ieee80211_frequency_to_channel(nla_get_u32(si[NL80211_SURVEY_INFO_FREQUENCY]));

	if (*filter && (channel != *filter))
		return NL_OK;

	if (!*filter)
		c = blobmsg_open_table(&b, NULL);

	blobmsg_add_u32(&b, "channel",
		ieee80211_frequency_to_channel(nla_get_u32(si[NL80211_SURVEY_INFO_FREQUENCY])));

	if (si[NL80211_SURVEY_INFO_TIME_TX])
		blobmsg_add_u64(&b, "transmit_ms", nla_get_u64(si[NL80211_SURVEY_INFO_TIME_TX]));

	if (si[NL80211_SURVEY_INFO_TIME_RX])
		blobmsg_add_u64(&b, "receive_ms", nla_get_u64(si[NL80211_SURVEY_INFO_TIME_RX]));

	if (si[NL80211_SURVEY_INFO_TIME_BUSY])
		blobmsg_add_u64(&b, "busy_ms", nla_get_u64(si[NL80211_SURVEY_INFO_TIME_BUSY]));

	if (si[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
		blobmsg_add_u64(&b, "busy_ext", nla_get_u64(si[NL80211_SURVEY_INFO_TIME_EXT_BUSY]));

	if (si[NL80211_SURVEY_INFO_TIME])
		blobmsg_add_u64(&b, "active_ms", nla_get_u64(si[NL80211_SURVEY_INFO_TIME]));

	if (si[NL80211_SURVEY_INFO_NOISE])
		blobmsg_add_u32(&b, "noise", (int8_t)nla_get_u8(si[NL80211_SURVEY_INFO_NOISE]));

	blobmsg_add_u8(&b, "in_use", si[NL80211_SURVEY_INFO_IN_USE] ? 1 : 0);
	if (!*filter)
		blobmsg_close_table(&b, c);

	return NL_OK;
}

const struct blobmsg_policy scan_policy[__SCAN_MAX] = {
	[SCAN_BAND] = { .name = "band", .type = BLOBMSG_TYPE_STRING },
	[SCAN_CHANNELS] = { .name = "channels", .type = BLOBMSG_TYPE_ARRAY },
	[SCAN_PASSIVE] = { .name = "passive", .type = BLOBMSG_TYPE_BOOL },
};

int trigger_scan(struct ubus_context *ctx,
		 struct ubus_object *obj,
		 struct ubus_request_data *req,
		 const char *method, struct blob_attr *_msg)
{
	struct blob_attr *tb[__SCAN_MAX] = {};
	struct wifi_phy *phy;
	struct nl_msg *msg;
	char *band = NULL;
	bool passive = false;

	blobmsg_parse(scan_policy, __SCAN_MAX, tb, blob_data(_msg), blob_len(_msg));

	if (tb[SCAN_BAND])
		band = blobmsg_get_string(tb[SCAN_BAND]);

	if (tb[SCAN_PASSIVE] && blobmsg_get_u8(tb[SCAN_PASSIVE]))
		passive = true;

	avl_for_each_element(&phy_tree, phy, avl) {
		struct wifi_iface *wif;

		if (list_empty(&phy->wifs))
			continue;
		if (!band ||
		    (!strcmp(band, "2G") && phy->band_2g) ||
		    (!strcmp(band, "5G") && phy->band_5gl) ||
		    (!strcmp(band, "5G") && phy->band_5gu) ||
		    (!strcmp(band, "5G") && (phy->band_5gl || phy->band_5gu))) {

			wif = list_first_entry(&phy->wifs, struct wifi_iface, phy);
			msg = unl_genl_msg(&unl, NL80211_CMD_TRIGGER_SCAN, false);
			nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(wif->name));
			nla_put_u32(msg, NL80211_ATTR_SCAN_FLAGS, NL80211_SCAN_FLAG_AP);
			if (!passive) {
				struct nl_msg *ssids;

				ssids = nlmsg_alloc();
				nla_put(ssids, 1, 0, "");
				nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);
			}
			unl_genl_request(&unl, msg, NULL, NULL);
		}
	}
	return UBUS_STATUS_OK;
}

int dump_scan(struct ubus_context *ctx,
	      struct ubus_object *obj,
	      struct ubus_request_data *req,
	      const char *method, struct blob_attr *_msg)
{
	enum {
		SCAN_VERBOSE,
		SCAN_BAND,
		__SCAN_MAX,
	};

	static const struct blobmsg_policy scan_policy[__SCAN_MAX] = {
		[SCAN_VERBOSE] = { .name = "verbose", .type = BLOBMSG_TYPE_BOOL },
		[SCAN_BAND] = { .name = "band", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__SCAN_MAX] = {};
	struct wifi_phy *phy;
	bool verbose = false;
	struct nl_msg *msg;
	char *band = NULL;
	void *c;

	blobmsg_parse(scan_policy, __SCAN_MAX, tb, blob_data(_msg), blob_len(_msg));

	if (tb[SCAN_BAND])
		band = blobmsg_get_string(tb[SCAN_BAND]);

	if (tb[SCAN_VERBOSE])
		verbose = blobmsg_get_bool(tb[SCAN_VERBOSE]);

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, "scan");
	avl_for_each_element(&phy_tree, phy, avl) {
		struct wifi_iface *wif;

		if (list_empty(&phy->wifs))
			continue;
		if (!band ||
		    (!strcmp(band, "2G") && phy->band_2g) ||
		    (!strcmp(band, "5G") && phy->band_5gl) ||
		    (!strcmp(band, "5G") && phy->band_5gu) ||
		    (!strcmp(band, "5G") && (phy->band_5gl || phy->band_5gu))) {

			wif = list_first_entry(&phy->wifs, struct wifi_iface, phy);
			msg = unl_genl_msg(&unl, NL80211_CMD_GET_SCAN, true);
			nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(wif->name));
			unl_genl_request(&unl, msg, nl80211_scan_dump_recv, (void *) verbose);
		}
	}
	blobmsg_close_array(&b, c);
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
}

enum {
	SURVEY_CHANNEL,
	SURVEY_BAND,
	__SURVEY_MAX,
};

static const struct blobmsg_policy survey_policy[__SURVEY_MAX] = {
	[SURVEY_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
	[SURVEY_BAND] = { .name = "band", .type = BLOBMSG_TYPE_STRING },
};

int dump_survey(struct ubus_context *ctx,
		struct ubus_object *obj,
		struct ubus_request_data *req,
		const char *method, struct blob_attr *_msg)
{
	struct blob_attr *tb[__SURVEY_MAX] = {};
	struct wifi_phy *phy;
	struct nl_msg *msg;
	int channel = 0;
	char *band = NULL;
	void *c;

	blobmsg_parse(survey_policy, __SURVEY_MAX, tb, blobmsg_data(_msg), blobmsg_data_len(_msg));

	if (tb[SURVEY_BAND])
		band = blobmsg_get_string(tb[SURVEY_BAND]);

	if (tb[SURVEY_CHANNEL])
		channel = blobmsg_get_u32(tb[SURVEY_CHANNEL]);

	blob_buf_init(&b, 0);
	if (!channel)
		c = blobmsg_open_array(&b, "survey");
	avl_for_each_element(&phy_tree, phy, avl) {
		struct wifi_iface *wif;

		if (list_empty(&phy->wifs))
			continue;

		if (!band ||
		    (!strcmp(band, "2G") && phy->band_2g) ||
		    (!strcmp(band, "5G") && phy->band_5gl) ||
		    (!strcmp(band, "5G") && phy->band_5gu) ||
		    (!strcmp(band, "5G") && (phy->band_5gl || phy->band_5gu))) {

			wif = list_first_entry(&phy->wifs, struct wifi_iface, phy);
			msg = unl_genl_msg(&unl, NL80211_CMD_GET_SURVEY, true);
			nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(wif->name));
			unl_genl_request(&unl, msg, nl80211_survey_recv, &channel);
		}
	}
	if (!channel)
		blobmsg_close_array(&b, c);
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
}

int radio_nl80211_init(void)
{
	struct nl_msg *msg;

	if (unl_genl_init(&unl, "nl80211") < 0) {
		syslog(0, "nl80211: failed to connect\n");
		return -1;
	}

	msg = unl_genl_msg(&unl, NL80211_CMD_GET_WIPHY, true);
	nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
	unl_genl_request(&unl, msg, nl80211_recv, NULL);
	msg = unl_genl_msg(&unl, NL80211_CMD_GET_INTERFACE, true);
	unl_genl_request(&unl, msg, nl80211_recv, NULL);

	unl_genl_subscribe(&unl, "config");
	unl_genl_subscribe(&unl, "mlme");
	unl_genl_subscribe(&unl, "vendor");

	timeout.cb = nl80211_poll_stations;
	uloop_timeout_set(&timeout, 2 * 1000);

	fd.fd = unl.sock->s_fd;
	fd.cb = nl80211_cb;
	uloop_fd_add(&fd, ULOOP_READ);

	return 0;
}
