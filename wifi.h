/* SPDX-License-Identifier: BSD-3-Clause */

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
