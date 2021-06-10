/* SPDX-License-Identifier: BSD-3-Clause */

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/ulog.h>

#include <libubus.h>

enum {
	SCAN_BAND,
	SCAN_CHANNELS,
	SCAN_PASSIVE,
	__SCAN_MAX,
};

extern const struct blobmsg_policy scan_policy[__SCAN_MAX];

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
int dump_survey(struct ubus_context *ctx,
		struct ubus_object *obj,
		struct ubus_request_data *req,
		const char *method, struct blob_attr *msg);
int dump_scan(struct ubus_context *ctx,
	      struct ubus_object *obj,
	      struct ubus_request_data *req,
	      const char *method, struct blob_attr *msg);
int trigger_scan(struct ubus_context *ctx,
		 struct ubus_object *obj,
		 struct ubus_request_data *req,
		 const char *method, struct blob_attr *msg);
