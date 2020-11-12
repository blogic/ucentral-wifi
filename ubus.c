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

#include "wifi.h"

static struct ubus_auto_conn conn;

static const struct ubus_method wifi_methods[] = {
	UBUS_METHOD_NOARG("phy", dump_phy),
	UBUS_METHOD_NOARG("iface", dump_iface),
	UBUS_METHOD_NOARG("station", dump_station),
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
