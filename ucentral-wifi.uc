#!/usr/bin/env ucrun

let fs = require('fs');
let nl80211 = require('nl80211');
let c = nl80211.const;

const iftype_names = [
	"unspecified",
	"adhoc",
	"station",
	"ap",
	"ap_vlan",
	"wds",
	"monitor",
	"mesh_point",
	"p2p_client",
	"p2p_go",
	"p2p_device"
];

const chanwidth_names = [
	"20_NOHT",
	"20",
	"40",
	"80",
	"80p80",
	"160",
	"5",
	"10"
];

let phys = {},
    ifs = {};

function phy_to_sysfs_path(phyname)
{
	let link = "/sys/class/ieee80211/" + phyname,
	    path = fs.readlink(link);

	if (!path) {
		ulog_warn("Unable readlink() " + link + ": " + fs.error());

		return null;
	}

	path = replace(path, regexp("^.+/devices/"), "");

	if (index(path, "pci/") != -1)
		path = replace(path, regexp("^.+soc/"), "soc/");
	else if (index(path, "/pci") != -1)
		path = substr(path, 9);

	let end = index(path, "/ieee80211/");

	if (end != -1)
		path = substr(path, 0, end);

	for (let i, entry in fs.lsdir("/sys/class/ieee80211/" + phyname + "/device/ieee80211")) {
		if (entry == phyname) {
			if (i != 0)
				path += "+" + i;

			break;
		}
	}

	return path;
}

function freq_to_channel(freq)
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
		return ((freq - 5955) / 5) + 1;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

function add_phy(phyinfo)
{
	let path = phy_to_sysfs_path(phyinfo.wiphy_name);

	if (!path)
		return;

	let info = {
		name: phyinfo.wiphy_name,
		wifs: {},
		chandisabled: {},
		freq: {},
		channel: {},
		chandfs: {},
		chanpwr: {}
	};

	if (phyinfo.reg_alpha2)
		info.country = phyinfo.reg_alpha2;

	if (phyinfo.dfs_region)
		info.dfs_region = phyinfo.dfs_region;

	for (let bandinfo in phyinfo.wiphy_bands) {
		if (bandinfo.ht_capa)
			info.ht_capa = bandinfo.ht_capa;

		if (bandinfo.vht_capa)
			info.vht_capa = bandinfo.vht_capa;

		for (let freqinfo in bandinfo.freqs) {
			let chan = freq_to_channel(freqinfo.freq);

			if (!chan)
				continue;

			if (freqinfo.disabled) {
				info.chandisabled[chan] = true;
				continue;
			}

			info.freq[chan] = freqinfo.freq;
			info.channel[chan] = true;
			info.chandfs[chan] = true;

			if (freqinfo.max_tx_power)
				info.chanpwr[chan] = freqinfo.max_tx_power;

			if (freqinfo.freq >= 6000)
				info.band_6g = true;
			else if (chan <= 16)
				info.band_2g = true;
			else if (chan >= 32 && chan <= 68)
				info.band_5gl = true;
			else if (chan >= 96 && chan <= 173)
				info.band_5gu = true;
		}
	}

	phys[path] = info;
}

function phy_get_temp(phyname)
{
	let temp = null;

	for (let path in fs.glob(sprintf("/sys/class/ieee80211/%s/hwmon*/temp1_input", phyname))) {
		let fd = fs.open(path, "r");

		if (fd) {
			temp = +fd.read("line");
			fd.close();
		}

		break;
	}

	return temp;
}

function phy_get_name(phyidx)
{
	let reply = nl80211.request(c.NL80211_CMD_GET_WIPHY, 0, { wiphy: phyidx });

	if (!reply)
		return null;

	return reply.wiphy_name;
}

function add_iface(ifinfo)
{
	if (!ifinfo.ifname)
		return null;

	let info = ifs[ifinfo.ifname];

	if (!info) {
		let phyname = phy_get_name(ifinfo.wiphy);

		info = {
			addr: ifinfo.mac,
			name: ifinfo.ifname,
			stas: [],
			parent: filter(values(phys), phy => (phy.name == phyname))[0]
		};

		if (info.parent)
			info.parent.wifs[ifinfo.ifname] = info;

		ifs[ifinfo.ifname] = info;
	}

	info.ssid = ifinfo.ssid || null;

	info.tx_power = ifinfo.wiphy_tx_power_level || 0;
	info.tx_power /= 100;

	info.type = ifinfo.iftype || 0;
	info.freq = ifinfo.wiphy_freq || 0;
	info.freq1 = ifinfo.center_freq1 || 0;
	info.freq2 = ifinfo.center_freq2 || 0;
	info.width = ifinfo.channel_width || 0;

	ifs[ifinfo.dev] = info;
}

function iface_is_up(ifname)
{
	let fd = fs.open(sprintf("/sys/class/net/%s/operstate", ifname), "r"),
	    up = false;

	if (fd) {
		up = (fd.read("line") == "up\n");
		fd.close();
	}

	return up;
}

global.ubus = {
	object: "wifi2",
	methods: {
		phy: {
			cb: function(msg) {
				let reply = {};

				phys = {};

				for (let phyinfo in nl80211.request(c.NL80211_CMD_GET_WIPHY, c.NLM_F_DUMP, { split_wiphy_dump: true }))
					add_phy(phyinfo);

				for (let path, phy in phys) {
					let info = {};

					let fields = {
						country: 'country',
						dfs_region: 'dfs_region',
						ht_capa: 'ht_capa',
						vht_capa: 'vht_capa',
						tx_ant_avail: 'tx_ant',
						rx_ant_avail: 'rx_ant'
					};

					for (let k, v in fields)
						if (exists(phy, k))
							info[v] = phy[k];


					info.band = [];

					if (phy.band_2g)
						push(info.band, "2G");

					if (phy.band_5gl || phy.band_5gu)
						push(info.band, "5G");

					if (phy.band_6g)
						push(info.band, "6G");


					info.htmode = [];

					if (phy.ht_capa) {
						push(info.htmode, "HT20");

						if (phy.ht_capa & 0x2)
							push(info.htmode, "HT40");
					}

					if (phy.vht_capa) {
						push(info.htmode, "VHT20", "VHT40", "VHT80");

						switch ((phy.vht_capa >> 2) & 0x3) {
						case 2:
							push(info.htmode, "VHT80+80");
							/* fall through */

						case 1:
							push(info.htmode, "VHT160");
						}
					}

					if (phy.he_phy_capa) {
						push(info.htmode, "HE20");

						let chwidth = (phy.he_phy_capa[0] >> 8) & 0xff;

						if (chwidth & 0x2 || chwidth & 0x4)
							push(info.htmode, "HE40");

						if (chwidth & 0x4)
							push(info.htmode, "HE80");

						if (chwidth & 0x8 || chwidth & 0x10)
							push(info.htmode, "HE160");

						if (chwidth & 0x10)
							push(info.htmode, "HE80+80");
					}


					let temp = phy_get_temp(phy.name);

					if (temp !== null)
						info.temperature = temp / 1000;


					info.channels = map(keys(phy.channel), ch => +ch);
					info.frequencies = map(keys(phy.freq), ch => phy.freq[ch]);


					reply[path] = info;
				}

				return reply;
			}
		},

		iface: {
			cb: function(msg) {
				let reply = {};

				phys = {};
				ifs = {};

				for (let phyinfo in nl80211.request(c.NL80211_CMD_GET_WIPHY, c.NLM_F_DUMP, { split_wiphy_dump: true }))
					add_phy(phyinfo);

				for (let ifinfo in nl80211.request(c.NL80211_CMD_GET_INTERFACE, c.NLM_F_DUMP))
					add_iface(ifinfo);

				for (let path, phyinfo in phys) {
					for (let ifname, ifinfo in phyinfo.wifs) {
						if (!iface_is_up(ifinfo.name))
							continue;

						let info = {};

						if (ifinfo.ssid)
							info.ssid = ifinfo.ssid;

						info.mode = iftype_names[ifinfo.type];
						info.channel = [];

						if (ifinfo.freq)
							push(info.channel, freq_to_channel(ifinfo.freq));

						if (ifinfo.freq1)
							push(info.channel, freq_to_channel(ifinfo.freq1));

						if (ifinfo.freq2)
							push(info.channel, freq_to_channel(ifinfo.freq2));

						info.ch_width = chanwidth_names[ifinfo.width];

						if (ifinfo.tx_power)
							info.tx_power = ifinfo.tx_power;

						info.bssid = ifinfo.addr;

						if (ifinfo.noise)
							info.noise = ifinfo.noise;

						if (!reply[path])
							reply[path] = {};

						reply[path][ifname] = info;
					}
				}

				return reply;
			}
		}
	}
};

global.start = function() { }
