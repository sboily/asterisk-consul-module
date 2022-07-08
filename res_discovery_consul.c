/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) <2015-2019>, Sylvain Boily
 *
 * Sylvain Boily <sylvain@wazo.io>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * Please follow coding guidelines
 * https://wiki.asterisk.org/wiki/display/AST/Coding+Guidelines
 */

/*! \file
 *
 * \brief Consul discovery module ressource
 *
 * \author\verbatim Sylvain Boily <sylvain@wazo.io> \endverbatim
 *
 * This is a resource to discovery an Asterisk application via Consul
 * \ingroup applications
 */

/*! \li \ref res_discovery_consul.c uses configuration file \ref res_discovery_consul.conf
 * \addtogroup configuration_file Configuration Files
 */

/*! 
 * \page res_discovery_consul.conf res_discovery_consul.conf
 * \verbinclude res_discovery_consul.conf.sample
 */

/*** MODULEINFO
	<defaultenabled>no</defaultenabled>
	<depend>curl</depend>
	<support_level>extended</support_level>
 ***/

/*! \requirements
 *
 * libcurl - http://curl.haxx.se/libcurl/c
 * asterisk - http://asterisk.org
 *
 * Build:
 *
 * make
 * make install
 * make samples
 * 
 */

#include "asterisk.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#include "asterisk/module.h"
#include "asterisk/config.h"
#include "asterisk/json.h"
#include "asterisk/uuid.h"
#include "asterisk/cli.h"
#include "asterisk/manager.h"
#include "asterisk/strings.h"

/*** DOCUMENTATION
	<configInfo name="res_discovery_consul" language="en_US">
		<synopsis>Consul client.</synopsis>
		<configFile name="res_discovery_consul.conf">
			<configObject name="general">
				<synopsis>Global configuration settings</synopsis>
				<configOption name="enabled">
					<synopsis>Enable/disable the consul module</synopsis>
				</configOption>
				<configOption name="debug">
					<synopsis>Enable/disable debug</synopsis>
				</configOption>
			</configObject>
		</configFile>
	</configInfo>
	<manager name="DiscoverySetMaintenance" language="en_US">
		<synopsis>
			Discovery consul.
		</synopsis>
		<description>
			<para>...</para>
		</description>
	</manager>
	<managerEvent language="en_US" name="DiscoveryRegister">
		<managerEventInstance class="EVENT_FLAG_SYSTEM">
			<synopsis>Raised when are registred to consul.</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/managerEvent[@name='DiscoveryRegister']/managerEventInstance/syntax/parameter)" />
		</syntax>
		<see-also>
			<ref type="managerEvent">DiscoveryDeregister</ref>
		</see-also>
		</managerEventInstance>
	</managerEvent>
	<managerEvent language="en_US" name="DiscoveryDeregister">
		<managerEventInstance class="EVENT_FLAG_SYSTEM">
			<synopsis>Raised when are deregistred to consul.</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/managerEvent[@name='DiscoveryDeregister']/managerEventInstance/syntax/parameter)" />
		</syntax>
		<see-also>
			<ref type="managerEvent">DiscoveryDeregister</ref>
		</see-also>
		</managerEventInstance>
	</managerEvent>
	<managerEvent language="en_US" name="DiscoverySetMaintenance">
		<managerEventInstance class="EVENT_FLAG_SYSTEM">
			<synopsis>Raised when you set maintenance.</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/managerEvent[@name='DiscoveryDeregister']/managerEventInstance/syntax/parameter)" />
		</syntax>
		</managerEventInstance>
	</managerEvent>
 ***/

#define MAX_URL_LENGTH 512

struct curl_put_data {
	char *data;
	size_t size;
};

struct discovery_config {
	int enabled;
	char id[256];
	char name[256];
	char host[256];
	char discovery_ip[16];
	int discovery_port;
	char discovery_interface[32];
	int port;
	char tags[256];
	char token[256];
	int check;
	int check_http_port;
};

static struct discovery_config global_config = {
	.enabled = 1,
	.id = "asterisk",
	.name = "Asterisk",
	.host = "127.0.0.1",
	.discovery_ip = "127.0.0.1",
	.discovery_port = 5060,
	.discovery_interface = "eth0",
	.port = 8500,
	.tags = "asterisk",
	.token = "",
	.check = 0,
	.check_http_port = 8088
};

static const char config_file[] = "res_discovery_consul.conf";

static size_t read_data(char *ptr, size_t size, size_t nmemb, void* data);
static CURLcode consul_deregister(CURL *curl);
static CURLcode consul_register(CURL *curl);
static CURLcode consul_maintenance_service(CURL *curl, const char *enable);
static int discovery_ip_address(void);
static int discovery_hostname(void);
static int generate_uuid_id_consul(void);

/*! \brief Function called to read data and inject it on PUT */
static size_t read_data(char *ptr, size_t size, size_t nmemb, void* data)
{
	size_t realsize = size * nmemb;
	if (realsize < 1) {
		return 0;
	}

	struct curl_put_data* mem = (struct curl_put_data*) data;
	if (mem->size > 0) {
		size_t bytes_to_copy = (mem->size > realsize) ? realsize : mem->size;
		memcpy(ptr,mem->data,bytes_to_copy);
		mem->data += bytes_to_copy;
		mem->size -= bytes_to_copy;
		return bytes_to_copy;
	}

	return 0;
}

/*! \brief Function called to create json object for curl */
static struct ast_json *consul_put_json(void) {
	char eid[18];
	ast_eid_to_str(eid, sizeof(eid), &ast_eid_default);

	RAII_VAR(struct ast_json *, obj, ast_json_object_create(), ast_json_unref);
	RAII_VAR(struct ast_json *, tags, ast_json_array_create(), ast_json_unref);
	RAII_VAR(struct ast_json *, check, ast_json_object_create(), ast_json_unref);
	RAII_VAR(struct ast_json *, meta, ast_json_object_create(), ast_json_unref);

	if (!obj) {return NULL;}
	if (!tags) {return NULL;}
	if (!check) {return NULL;}
	if (!meta) {return NULL;}

	if (!strcasecmp(global_config.discovery_ip, "auto")) {
		discovery_ip_address();
	}

	if (!strcasecmp(global_config.name, "auto")) {
		discovery_hostname();
	}

	if (!strcasecmp(global_config.id, "auto")) {
		generate_uuid_id_consul();
	}

	ast_json_object_set(obj, "ID", ast_json_string_create(global_config.id));
	ast_json_object_set(obj, "Name", ast_json_string_create(global_config.name));
	ast_json_object_set(obj, "Address", ast_json_string_create(global_config.discovery_ip));
	ast_json_object_set(obj, "Port", ast_json_integer_create(global_config.discovery_port));
	ast_json_object_set(obj, "Tags", ast_json_ref(tags));
	ast_json_object_set(meta, "eid", ast_json_string_create(eid));
	ast_json_object_set(obj, "Meta", ast_json_ref(meta));

	ast_json_array_append(tags, ast_json_string_create(global_config.tags));

	if (global_config.check == 1) {
		char url_check[MAX_URL_LENGTH];

		snprintf(url_check, sizeof(url_check), "http://%s:%d/httpstatus",
				global_config.discovery_ip, global_config.check_http_port);
		ast_json_object_set(obj, "Check", ast_json_ref(check));
		ast_json_object_set(check, "Http", ast_json_string_create(url_check));
		ast_json_object_set(check, "Interval", ast_json_string_create("15s"));
	}

	ast_debug(1, "The json object created: %s\n", ast_json_dump_string_format(obj, AST_JSON_COMPACT));

	return ast_json_ref(obj);
}

/*! \brief Function called to create json object for curl */
static struct ast_json *consul_put_maintenance_json(void) {
	RAII_VAR(struct ast_json *, obj, ast_json_object_create(), ast_json_unref);

	if (!obj) {return NULL;}

	return ast_json_ref(obj);
}

/*! \brief Function called to set headers for curl */
static struct curl_slist *set_headers_json(void) {
	struct curl_slist *headers = NULL;

	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charsets: utf-8");

	return headers;
}

static void set_base_url(struct ast_str **str, const char *path)
{
	ast_str_set(str, 0, "http://%s:%d%s",global_config.host, global_config.port, path);
}


/*! \brief Function called to deregister via curl on consul */
static CURLcode consul_deregister(CURL *curl)
{
	CURLcode rcode;
	struct curl_slist *headers;
	struct ast_str *url = ast_str_alloca(MAX_URL_LENGTH);

	set_base_url(&url, "/v1/agent/service/deregister");
	ast_str_append(&url, 0, "/%s", global_config.id);
	if (!ast_strlen_zero(global_config.token)) {
		ast_str_append(&url, 0, "?token=%s", global_config.token);
	}

	headers = set_headers_json();

	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, ast_str_buffer(url));
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1);

	ast_debug(1, "Deregister node %s with url %s\n", global_config.id, ast_str_buffer(url));

	manager_event(EVENT_FLAG_SYSTEM, "DiscoveryDeregister", NULL);

	rcode = curl_easy_perform(curl);
	curl_slist_free_all(headers);

	return rcode;
}

/*! \brief Function called to deregister via curl on consul */
static CURLcode consul_maintenance_service(CURL *curl, const char *enable)
{
	CURLcode rcode;
	struct curl_put_data put_data = {0,0};
	struct curl_slist *headers;
	struct ast_str *url = ast_str_alloca(MAX_URL_LENGTH);
	struct ast_json *obj;
	char *reason = curl_easy_escape(curl, "Maintenance activated by Asterisk module", 41);

	obj = consul_put_maintenance_json();

	set_base_url(&url, "/v1/agent/service/maintenance");
	ast_str_append(&url, 0, "/%s?enable=%s&reason=%s", global_config.id, enable, reason);
	if (!ast_strlen_zero(global_config.token)) {
		ast_str_append(&url, 0, "&token=%s", global_config.token);
	}

	headers = set_headers_json();

	put_data.data = ast_malloc(strlen(ast_json_dump_string_format(obj, AST_JSON_COMPACT)));
	memcpy(put_data.data, ast_json_dump_string_format(obj, AST_JSON_COMPACT),
		   strlen(ast_json_dump_string_format(obj, AST_JSON_COMPACT)));
	put_data.size = strlen(ast_json_dump_string_format(obj, AST_JSON_COMPACT));

	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, ast_str_buffer(url));
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) put_data.size);

	curl_easy_setopt(curl, CURLOPT_READDATA, (void *) &put_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_data);

	rcode = curl_easy_perform(curl);

	manager_event(EVENT_FLAG_SYSTEM, "DiscoverySetMaintenance", "Maintenance: %s\n", enable);

	ast_json_free(obj);
	curl_slist_free_all(headers);
	curl_free(reason);

	return rcode;
}

/*! \brief Function called to register via curl on consul */
static CURLcode consul_register(CURL *curl)
{
	CURLcode rcode;
	struct curl_put_data put_data = {0,0};
	struct curl_slist *headers;
	struct ast_str *url = ast_str_alloca(MAX_URL_LENGTH);
	struct ast_json *obj;

	headers = set_headers_json();
	obj = consul_put_json();

	set_base_url(&url, "/v1/agent/service/register");
	if (!ast_strlen_zero(global_config.token)) {
		ast_str_append(&url, 0, "?token=%s", global_config.token);
	}

	put_data.data = ast_malloc(strlen(ast_json_dump_string_format(obj, AST_JSON_COMPACT)));
	memcpy(put_data.data, ast_json_dump_string_format(obj, AST_JSON_COMPACT),
		   strlen(ast_json_dump_string_format(obj, AST_JSON_COMPACT)));
	put_data.size = strlen(ast_json_dump_string_format(obj, AST_JSON_COMPACT));

	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_URL, ast_str_buffer(url));
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) put_data.size);

	curl_easy_setopt(curl, CURLOPT_READDATA, (void *) &put_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_data);

	rcode = curl_easy_perform(curl);

	manager_event(EVENT_FLAG_SYSTEM, "DiscoveryRegister", NULL);

	ast_json_free(obj);
	curl_slist_free_all(headers);

	return rcode;
}

/*! \brief Function called to load or reload the configuration file */
static void load_config(int reload)
{
	struct ast_config *cfg = NULL;

	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	struct ast_variable *v;

	int enabled, check;

	enabled = 1;
	check = 1;

	if (!(cfg = ast_config_load(config_file, config_flags)) || cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "res_discovery_consul configuration file '%s' not found\n", config_file);
		return;
	} else if (cfg == CONFIG_STATUS_FILEUNCHANGED) {
		return;
	}

	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (!strcasecmp(v->name, "enabled")) {
			if (ast_true(v->value) == 0) {
				enabled = 0;
			}
			global_config.enabled = enabled;
		}
	}

	for (v = ast_variable_browse(cfg, "consul"); v; v = v->next) {
		if (!strcasecmp(v->name, "id")) {
			ast_copy_string(global_config.id, v->value, strlen(v->value) + 1);
		} else if (!strcasecmp(v->name, "host")) {
			ast_copy_string(global_config.host, v->value, strlen(v->value) + 1);
		} else if (!strcasecmp(v->name, "port")) {
			global_config.port = atoi(v->value);
		} else if (!strcasecmp(v->name, "tags")) {
			ast_copy_string(global_config.tags, v->value, strlen(v->value) + 1);
		} else if (!strcasecmp(v->name, "name")) {
			ast_copy_string(global_config.name, v->value, strlen(v->value) + 1);
		} else if (!strcasecmp(v->name, "discovery_ip")) {
			ast_copy_string(global_config.discovery_ip, v->value, strlen(v->value) + 1);
		} else if (!strcasecmp(v->name, "discovery_port")) {
			global_config.discovery_port = atoi(v->value);
		} else if (!strcasecmp(v->name, "discovery_interface")) {
			ast_copy_string(global_config.discovery_interface, v->value, strlen(v->value) + 1);
		} else if (!strcasecmp(v->name, "token")) {
			ast_copy_string(global_config.token, v->value, strlen(v->value) + 1);
		} else if (!strcasecmp(v->name, "check")) {
			if (ast_true(v->value) == 0) {
				check = 0;
			}
			global_config.check = check;
		} else if (!strcasecmp(v->name, "check_http_port")) {
			global_config.check_http_port =  atoi(v->value);
		}
	}

	ast_config_destroy(cfg);

	return;
}

/*! \brief Function called to discovery ip */
static int discovery_ip_address(void)
{
	int fd;
	struct ifreq ifr;
	char host[16];

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, global_config.discovery_interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	sprintf(host, "%s", ast_inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	ast_copy_string(global_config.discovery_ip, host, strlen(host) + 1);

	ast_debug(1,"Discovery IP: %s\n", host);

	return 0;
}

/*! \brief Function called to discovery hostname */
static int discovery_hostname(void)
{
	char hostname[1024];

	gethostname(hostname, 1024);
	ast_copy_string(global_config.name, hostname, strlen(hostname) + 1);

	ast_debug(1, "Discovery hostname: %s\n", hostname);

	return 0;
}

/*! \brief Function called to generate uuid */
static int generate_uuid_id_consul(void)
{
	const char *uuid;
	char uuid_str[256];

	uuid = ast_uuid_generate_str(uuid_str, sizeof(uuid_str));
	ast_copy_string(global_config.id, uuid, strlen(uuid) + 1);

	ast_debug(1, "Auto ID: %s\n", uuid);

	return 0;
}


/*! \brief Function called to load the resource */
static int load_res(int start)
{
	CURL *curl;
	CURLcode rcode;

	curl = curl_easy_init();
	if (!curl) {
		return -1;
	}

	if (start == 1) {
		rcode = consul_register(curl);
	} else {
		rcode = consul_deregister(curl);
	}

	if (rcode != CURLE_OK) {
		ast_log(LOG_NOTICE, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rcode));
	}
 
	curl_easy_cleanup(curl);

	return 0;
}

/*! \brief Function called to exec CLI */
static char *discovery_cli_settings(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "discovery show settings";
		e->usage =
			"Usage: discovery show settings\n"
			"       Get the settings of discovery service.\n\n"
			"       Example:\n"
			"	    discovery show settings\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd, "\n\nGlobal Settings:\n");
	ast_cli(a->fd, "----------------\n");
	ast_cli(a->fd, "ID service: %s\n", global_config.id);
	ast_cli(a->fd, "Name service: %s\n", global_config.name);
	ast_cli(a->fd, "Tags service: %s\n\n", global_config.tags);
	ast_cli(a->fd, "Discovery Settings:\n");
	ast_cli(a->fd, "-------------------\n");
	ast_cli(a->fd, "Discovery ip: %s\n", global_config.discovery_ip);
	ast_cli(a->fd, "Discovery port: %d\n", global_config.discovery_port);
	ast_cli(a->fd, "Discovery interface: %s\n\n", global_config.discovery_interface);
	ast_cli(a->fd, "Consul Settings:\n");
	ast_cli(a->fd, "----------------\n");
	ast_cli(a->fd, "Connection: %s:%d\n", global_config.host, global_config.port);
	ast_cli(a->fd, "Token: %s\n", global_config.token);
	ast_cli(a->fd, "Check: %d\n", global_config.check);
	ast_cli(a->fd, "Check http port: %d\n\n", global_config.check_http_port);
	ast_cli(a->fd, "----\n");

	return NULL;
}

/*! \brief Function called to exec CLI */
static char *discovery_cli_set_maintenance(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	CURL *curl;
	CURLcode rcode;

	switch (cmd) {
	case CLI_INIT:
		e->command = "discovery set maintenance {on|off}";
		e->usage =
			"Usage: discovery set maintenance {on|off}\n"
			"       Enable/disable service in maintenance mode.\n\n"
			"       Example:\n"
			"           discovery set maintenance\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}

	curl = curl_easy_init();

	if (ast_true(a->argv[3])) {
		rcode = consul_maintenance_service(curl, "true");
		ast_cli(a->fd, "Maintenance mode for service %s is set\n", global_config.id);
	} else if (ast_false(a->argv[3])) {
		rcode = consul_maintenance_service(curl, "false");
		ast_cli(a->fd, "Maintenance mode for service %s is unset\n", global_config.id);
	} else {
		curl_easy_cleanup(curl);
		return CLI_SHOWUSAGE;
	}

	if (rcode != CURLE_OK) {
		ast_log(LOG_NOTICE, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rcode));
	}

	curl_easy_cleanup(curl);

	return NULL;
}

static int manager_maintenance(struct mansession *s, const struct message *m)
{
	CURL *curl;
	CURLcode rcode;
	const char *enable = astman_get_header(m,"Enable");

	if (ast_strlen_zero(enable)) {
		astman_send_error(s, m, "No action to enable or disable specified");
		return 0;
	}

	curl = curl_easy_init();

	rcode = consul_maintenance_service(curl, enable);

	if (rcode != CURLE_OK) {
		ast_log(LOG_NOTICE, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rcode));
	}

	curl_easy_cleanup(curl);

	return RESULT_SUCCESS;
}

/*! \brief Function called to define CLI */
static struct ast_cli_entry cli_discovery[] = {
	AST_CLI_DEFINE(discovery_cli_settings, "Show discovery settings"),
	AST_CLI_DEFINE(discovery_cli_set_maintenance, "Set discovery service in maintenance mode")
};

static int reload_module(void)
{
	load_config(1);
	return 0;
}

static int unload_module(void)
{
	load_res(0);
	ast_cli_unregister_multiple(cli_discovery, ARRAY_LEN(cli_discovery));
	ast_manager_unregister("DiscoverySetMaintenance");
	return 0;
}

static int load_module(void)
{
	if (!ast_module_check("res_curl.so")) {
		if (ast_load_resource("res_curl.so") != AST_MODULE_LOAD_SUCCESS) {
			ast_log(LOG_ERROR, "Cannot load res_curl, so res_discovery_consul cannot be loaded\n");
			return AST_MODULE_LOAD_DECLINE;
		}
	}

	load_config(0);

	if (global_config.enabled == 0) {
		ast_log(LOG_NOTICE, "This module is disabled\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	if (load_res(1)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_cli_register_multiple(cli_discovery, ARRAY_LEN(cli_discovery));
	ast_manager_register_xml("DiscoverySetMaintenance", EVENT_FLAG_SYSTEM, manager_maintenance);
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "Asterisk Discovery CONSUL",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.reload = reload_module,
);
