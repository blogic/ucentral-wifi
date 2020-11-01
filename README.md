# uSync-wifi

Allows us to read the current wifi state via ubus

```

ubus call wifi phy
{
	"phy0": {
		"band": [
			"2",
			"5"
		],
		"ht_capa": 6639,
		"vht_capa": 29174,
		"channels": [
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 52, 56,
			60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
			149, 153, 157, 161, 165
		]
	}
}


ubus call wifi iface
{
	"wlan1": {
		"ssid": "OpenWrt",
		"mode": "ap",
		"frequency": [
			2462,
			2462
		],
		"ch_width": "20",
		"tx_power": 20,
		"mac": "c4:41:1e:22:71:07"
	},
	"wlan2": {
		"ssid": "OpenWrt",
		"mode": "ap",
		"frequency": [
			5180,
			5210
		],
		"ch_width": "80",
		"tx_power": 23,
		"mac": "c4:41:1e:22:71:08"
	}
}


ubus call wifi station
{
	"phy0": {
		"wlp3s0": {
			"ac:86:74:xx:xx:xx": {
				"rssi": 55,
				"rx_packets": 12815,
				"tx_packets": 828,
				"rx_bytes": 1307345,
				"tx_bytes": 159548
			}
		}
	}
}

```
