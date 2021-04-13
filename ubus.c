/* SPDX-License-Identifier: BSD-3-Clause */

#include "wifi.h"

static struct ubus_auto_conn conn;

static const struct ubus_method wifi_methods[] = {
	UBUS_METHOD_NOARG("phy", dump_phy),
	UBUS_METHOD_NOARG("iface", dump_iface),
	UBUS_METHOD_NOARG("station", dump_station),
	UBUS_METHOD_NOARG("survey", dump_survey),
	UBUS_METHOD_NOARG("scan", trigger_scan),
	UBUS_METHOD_NOARG("scan_dump", dump_scan),
};

static struct ubus_object_type ubus_object_type =
	UBUS_OBJECT_TYPE("wifi", wifi_methods);

struct ubus_object ubus_object = {
	.name = "wifi",
	.type = &ubus_object_type,
	.methods = wifi_methods,
	.n_methods = ARRAY_SIZE(wifi_methods),
};

static void ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &ubus_object);
}

void ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}
