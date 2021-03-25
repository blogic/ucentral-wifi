/* SPDX-License-Identifier: BSD-3-Clause */

#include "wifi.h"
#include "nl80211.h"

int main(int argc, char **argv)
{
	uloop_init();
	radio_nl80211_init();
	ubus_init();
	uloop_run();
	uloop_done();
	return 0;
}
