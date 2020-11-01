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

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/ulog.h>

#include <libubus.h>

void ubus_init(void);

int dump_phy(struct ubus_context *ctx,
	     struct ubus_object *obj,
	     struct ubus_request_data *req,
	     const char *method, struct blob_attr *msg);
int dump_iface(struct ubus_context *ctx,
	       struct ubus_object *obj,
	       struct ubus_request_data *req,
	       const char *method, struct blob_attr *msg);
int dump_station(struct ubus_context *ctx,
		 struct ubus_object *obj,
		 struct ubus_request_data *req,
		 const char *method, struct blob_attr *msg);
