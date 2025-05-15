/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) <2015-2015>, Sylvain Boily
 *
 * Sylvain Boily <sylvainboilydroid@gmail.com>
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
 * https://docs.asterisk.org/Development/Policies-and-Procedures/Coding-Guidelines/
 */

/*! \file
 *
 * \brief Consul discovery module ressource
 *
 * \author\verbatim Sylvain Boily <sylvainboilydroid@gmail.com> \endverbatim
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
	<depend>http</depend>
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
#include "asterisk/utils.h"
#include "asterisk/http.h"

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
			<ref type="managerEvent">DiscoveryRegister</ref>
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
#define MAX_CHECK_ID_LENGTH 280

struct curl_put_data {
	char *original_data_ptr;
	const char *current_read_ptr;
	size_t remaining_size;
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
	char check_interval[16];
	long consul_timeout_ms;
	char ari_port[16];
	char ari_scheme[16];
	char check_timeout[16];
	char check_deregister_after[16];
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
	.check_http_port = 8088,
	.check_interval = "15s",
	.consul_timeout_ms = 2000,
	.ari_port = "",
	.ari_scheme = "",
	.check_timeout = "3s",
	.check_deregister_after = "30s",
};

static const char config_file[] = "res_discovery_consul.conf";

// HTTP Callback function for EID check
static int handle_http_check_eid(struct ast_tcptls_session_instance *ser,
                                 const struct ast_http_uri *urih,
                                 const char *uri_path, 
                                 enum ast_http_method method,
                                 struct ast_variable *get_params,
                                 struct ast_variable *headers)
{
	struct ast_variable *param;
	const char *expected_eid = NULL;
	char response_text[560];

	ast_debug(3, "HTTP EID Check: Callback entered. URI path: '%s', Method: %d\n", uri_path ? uri_path : "(null)", method);

	if (!ser) {
		ast_log(LOG_ERROR, "HTTP EID Check: Session (ser) is NULL in callback! Cannot proceed.\n");
		return 0;
	}

	if (method != AST_HTTP_GET) {
		ast_http_error(ser, 405, "Method Not Allowed", "Only GET is allowed for this endpoint.");
		return 0; 
	}

	for (param = get_params; param; param = param->next) {
		if (param->name && strcasecmp(param->name, "expected_eid") == 0) {
			expected_eid = param->value;
			break;
		}
	}

	if (ast_strlen_zero(expected_eid)) {
		ast_log(LOG_WARNING, "HTTP EID Check: 'expected_eid' parameter missing or empty.\n");
		ast_http_error(ser, 400, "Bad Request", "Required query parameter 'expected_eid' is missing.");
		return 0;
	}

	if (ast_strlen_zero(global_config.id)) {
		ast_log(LOG_ERROR, "HTTP EID Check: global_config.id is empty! Cannot perform EID comparison.\n");
		ast_http_error(ser, 500, "Internal Server Error", "Server configuration error: instance EID not set.");
		return 0;
	}

	if (strcmp(global_config.id, expected_eid) == 0) {
		snprintf(response_text, sizeof(response_text), "OK - EID Match: %s", global_config.id);
		ast_debug(1, "HTTP EID Check: Match for EID '%s'. Responding 200 OK.\n", global_config.id);

		struct ast_str *body_str = NULL;
		struct ast_str *headers_str = NULL;

		body_str = ast_str_create(strlen(response_text) + 16);
		headers_str = ast_str_create(128);

		if (body_str && headers_str) {
			ast_str_set(&body_str, 0, "%s", response_text);
			ast_str_set(&headers_str, 0, "Content-Type: text/plain; charset=utf-8\r\n\r\n");

			ast_http_send(ser, method, 200, "OK", headers_str, body_str, -1, 0); 
			body_str = NULL;
			headers_str = NULL;
		} else {
			ast_log(LOG_ERROR, "HTTP EID Check: Failed to allocate memory for response/headers.\n");
			if (body_str) {
				ast_free(body_str);
			}
			if (headers_str) {
				ast_free(headers_str);
			}
			ast_http_error(ser, 500, "Internal Server Error", "Failed to allocate response buffer.");
		}
	} else {
		snprintf(response_text, sizeof(response_text), "EID Mismatch. Expected: %s, Instance has: %s", expected_eid, global_config.id);
		ast_log(LOG_NOTICE, "HTTP EID Check: Mismatch. Expected EID: '%s', Instance EID: '%s'. Responding 404 Not Found.\n", expected_eid, global_config.id);
		ast_http_error(ser, 404, "Not Found", response_text);
	}
	return 0; 
}

// HTTP URI handler structure for EID check
static struct ast_http_uri EID_CHECK_URI = {
	.uri = "consul_check", 
	.description = "Consul EID Check for res_discovery_consul",
	.callback = handle_http_check_eid,
	.has_subtree = 1,
	.data = NULL,
	.key = "res_discovery_consul", 
};

static size_t read_data(char *ptr, size_t size, size_t nmemb, void* data);
static CURLcode consul_deregister(CURL *curl);
static CURLcode consul_register(CURL *curl);
static CURLcode consul_maintenance_service(CURL *curl, const char *enable);
static int discovery_ip_address(void);
static int discovery_hostname(void);
static int generate_uuid_id_consul(void);
static int discover_ari_settings(void);

/* Manager Handler Prototype */
static int manager_maintenance(struct mansession *s, const struct message *m);

/* CLI Handlers */
static char *discovery_cli_settings(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *discovery_cli_set_maintenance(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *discovery_cli_show_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

/* Dummy write callback for cURL when we don't need the response body */
static size_t write_callback_noop(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    /* Do nothing with the data, just return the number of bytes processed */
    return size * nmemb;
}

/*!
 * \brief cURL read callback function for PUT requests with in-memory data.
 *
 * This function is used with CURLOPT_READFUNCTION to provide data for an HTTP PUT request
 * from a memory buffer. It reads up to `size` * `nmemb` bytes from the buffer pointed
 * to by `data` (which is a `struct curl_put_data *`) into the buffer pointed to by `ptr`.
 *
 * \param ptr Buffer to write the data into for libcurl to send.
 * \param size Size of each data element.
 * \param nmemb Number of data elements.
 * \param data User-defined pointer, expected to be a `struct curl_put_data *` \
 *             containing the source buffer and tracking information.
 * \return The number of bytes actually copied to `ptr`, or 0 if no more data or error.
 */
static size_t read_data(char *ptr, size_t size, size_t nmemb, void* data)
{
	size_t realsize = size * nmemb;
	if (realsize < 1) {
		return 0;
	}

	struct curl_put_data* mem = (struct curl_put_data*) data;
	if (mem->remaining_size > 0) {
		size_t bytes_to_copy = (mem->remaining_size > realsize) ? realsize : mem->remaining_size;
		memcpy(ptr, mem->current_read_ptr, bytes_to_copy);
		mem->current_read_ptr += bytes_to_copy;
		mem->remaining_size -= bytes_to_copy;
		return bytes_to_copy;
	}

	return 0;
}

/*!
 * \brief Creates the JSON payload for registering a service with Consul.
 *
 * This function constructs an `ast_json` object representing the service definition
 * according to Consul's API requirements. It populates fields such as ID, Name,
 * Address, Port, Tags, and health Check details based on the `global_config`.
 * If 'auto' is specified for IP, hostname, or ID, it calls helper functions
 * to determine these values.
 *
 * \note The caller is responsible for decrementing the reference count of the
 *       returned `ast_json` object using `ast_json_unref` when it's no longer needed.
 *
 * \return A pointer to the newly created `ast_json` object, or NULL on failure.
 */
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
	} else if (!strcasecmp(global_config.id, "asterisk")) {
		ast_copy_string(global_config.id, eid, strlen(eid) + 1);
	}

	ast_json_object_set(obj, "ID", ast_json_string_create(global_config.id));
	ast_json_object_set(obj, "Name", ast_json_string_create(global_config.name));
	ast_json_object_set(obj, "Address", ast_json_string_create(global_config.discovery_ip));
	ast_json_object_set(obj, "Port", ast_json_integer_create(global_config.discovery_port));
	ast_json_object_set(obj, "Tags", ast_json_ref(tags));
	ast_json_object_set(meta, "eid", ast_json_string_create(eid));

	if (!ast_strlen_zero(global_config.ari_port)) {
		ast_json_object_set(meta, "ari_port", ast_json_string_create(global_config.ari_port));
	}
	if (!ast_strlen_zero(global_config.ari_scheme)) {
		ast_json_object_set(meta, "ari_scheme", ast_json_string_create(global_config.ari_scheme));
	}

	ast_json_object_set(obj, "Meta", ast_json_ref(meta));

	ast_json_array_append(tags, ast_json_string_create(global_config.tags));

	if (global_config.check == 1) {
		char url_check[MAX_URL_LENGTH];
		char check_id_str[MAX_CHECK_ID_LENGTH];

		snprintf(check_id_str, sizeof(check_id_str), "check-asterisk-eid-%s", global_config.id);

		snprintf(url_check, sizeof(url_check), "http://%s:%d/consul_check?expected_eid=%s",
				global_config.discovery_ip, global_config.check_http_port, global_config.id);

		ast_json_object_set(obj, "Check", ast_json_ref(check));

		ast_json_object_set(check, "CheckID", ast_json_string_create(check_id_str));
		ast_json_object_set(check, "Name", ast_json_string_create("Asterisk Instance EID Verification"));
		ast_json_object_set(check, "HTTP", ast_json_string_create(url_check));
		ast_json_object_set(check, "Interval", ast_json_string_create(global_config.check_interval));
		ast_json_object_set(check, "Timeout", ast_json_string_create(global_config.check_timeout));
		ast_json_object_set(check, "DeregisterCriticalServiceAfter", ast_json_string_create(global_config.check_deregister_after));
	}

	ast_debug(1, "The json object created: %s\n", ast_json_dump_string_format(obj, AST_JSON_COMPACT));

	return ast_json_ref(obj);
}

/*!
 * \brief Creates the JSON payload for a Consul service maintenance request.
 *
 * Currently, Consul's API for enabling/disabling maintenance mode via the
 * `/v1/agent/service/maintenance/:service_id` endpoint does not expect a JSON body
 * for the PUT request. The parameters are sent via the URL query string.
 * Therefore, this function creates an empty JSON object as a placeholder,
 * though it may not be strictly necessary for current Consul versions.
 *
 * \note The caller is responsible for decrementing the reference count of the
 *       returned `ast_json` object using `ast_json_unref` when it's no longer needed.
 *
 * \return A pointer to a newly created, empty `ast_json` object, or NULL on failure.
 */
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

/*!
 * \brief Constructs the base URL for Consul API requests.
 * \param str Pointer to an ast_str that will be populated with the base URL.
 * \param path The specific API path to append to the base Consul agent URL (e.g., "/v1/agent/service/register").
 *
 * This function takes the configured Consul host and port from global_config
 * and combines it with the provided API path to form a complete URL.
 * The result is stored in the ast_str pointed to by str.
 */
static void set_base_url(struct ast_str **str, const char *path)
{
	ast_str_set(str, 0, "http://%s:%d%s",global_config.host, global_config.port, path);
}


/*!
 * \brief Function called to deregister via curl on consul
 *
 * This function sends a PUT request to the Consul agent's
 * `/v1/agent/service/deregister/:service_id` endpoint.
 * It constructs the URL with the service ID from global configuration
 * and includes the token if provided.
 */
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
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, global_config.consul_timeout_ms);

	ast_debug(1, "Deregister node %s with url %s\n", global_config.id, ast_str_buffer(url));

	rcode = curl_easy_perform(curl);
	if (rcode == CURLE_OK) {
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code >= 200 && http_code < 300) {
			manager_event(EVENT_FLAG_SYSTEM, "DiscoveryDeregister", NULL);
		} else {
			ast_log(LOG_WARNING, "Consul deregister request for %s failed with HTTP status %ld\n", global_config.id, http_code);
		}
	}
	curl_slist_free_all(headers);

	return rcode;
}

/*!
 * \brief Enables or disables maintenance mode for the service in Consul.
 *
 * This function sends a PUT request to the Consul agent's
 * `/v1/agent/service/maintenance/:service_id` endpoint.
 * It constructs the URL with the service ID from global configuration
 * and includes the `enable` status ("true" or "false") and a reason in the query string.
 * An empty JSON object is sent as the body, as per current Consul API (though it might not be strictly required).
 *
 * \param curl A CURL easy handle, assumed to be initialized.
 * \param enable A string indicating whether to enable ("true") or disable ("false") maintenance mode.
 * \return CURLcode indicating the result of the cURL operation (e.g., CURLE_OK on success).
 */
static CURLcode consul_maintenance_service(CURL *curl, const char *enable)
{
	CURLcode rcode = CURLE_OK;
	struct curl_put_data put_data = { .original_data_ptr = NULL, .current_read_ptr = NULL, .remaining_size = 0 };
	struct curl_slist *headers = NULL;
	struct ast_str *url = ast_str_alloca(MAX_URL_LENGTH);
	struct ast_json *obj = NULL;
	char *reason = curl_easy_escape(curl, "Maintenance activated by Asterisk module", 41);
	const char *json_str = NULL;
	size_t json_len = 0;
	char *allocated_buffer = NULL;

	obj = consul_put_maintenance_json();

	set_base_url(&url, "/v1/agent/service/maintenance");
	ast_str_append(&url, 0, "/%s?enable=%s&reason=%s", global_config.id, enable, reason);
	if (!ast_strlen_zero(global_config.token)) {
		ast_str_append(&url, 0, "&token=%s", global_config.token);
	}

	headers = set_headers_json();

	json_str = ast_json_dump_string_format(obj, AST_JSON_COMPACT);
	if (json_str) {
		json_len = strlen(json_str);
		allocated_buffer = ast_strndup(json_str, json_len);
		if (!allocated_buffer) {
			ast_log(LOG_ERROR, "Failed to duplicate JSON string for Consul maintenance request\n");
			ast_json_free(obj);
			if (headers) { curl_slist_free_all(headers); }
			if (reason) { curl_free(reason); }
			return CURLE_OUT_OF_MEMORY;
		}
		put_data.original_data_ptr = allocated_buffer;
		put_data.current_read_ptr = allocated_buffer;
		put_data.remaining_size = json_len;
	} else {
		ast_log(LOG_WARNING, "JSON string for maintenance object is NULL\n");
	}


	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, ast_str_buffer(url));
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, global_config.consul_timeout_ms);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) put_data.remaining_size);

	curl_easy_setopt(curl, CURLOPT_READDATA, (void *) &put_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_data);

	rcode = curl_easy_perform(curl);

	manager_event(EVENT_FLAG_SYSTEM, "DiscoverySetMaintenance", "Maintenance: %s\n", enable);

	ast_json_free(obj);
	curl_slist_free_all(headers);
	curl_free(reason);
	ast_free(put_data.original_data_ptr);

	return rcode;
}

/*!
 * \brief Function called to register via curl on consul
 *
 * This function sends a PUT request to the Consul agent's
 * `/v1/agent/service/register` endpoint.
 * It constructs the URL with the service ID from global configuration
 * and includes the token if provided.
 */
static CURLcode consul_register(CURL *curl)
{
	CURLcode rcode = CURLE_OK;
	struct curl_put_data put_data = { .original_data_ptr = NULL, .current_read_ptr = NULL, .remaining_size = 0 };
	struct curl_slist *headers = NULL;
	struct ast_str *url = ast_str_alloca(MAX_URL_LENGTH);
	struct ast_json *obj = NULL;
	const char *json_str = NULL;
	size_t json_len = 0;
	char *allocated_buffer = NULL;

	headers = set_headers_json();
	obj = consul_put_json();

	set_base_url(&url, "/v1/agent/service/register");
	if (!ast_strlen_zero(global_config.token)) {
		ast_str_append(&url, 0, "?token=%s", global_config.token);
	}

	if (obj) {
		json_str = ast_json_dump_string_format(obj, AST_JSON_COMPACT);
		if (json_str) {
			json_len = strlen(json_str);
			allocated_buffer = ast_strndup(json_str, json_len);
			if (!allocated_buffer) {
				ast_log(LOG_ERROR, "Failed to duplicate JSON string for Consul registration request\n");
				ast_json_free(obj);
				if (headers) { curl_slist_free_all(headers); }
				return CURLE_OUT_OF_MEMORY;
			}
			put_data.original_data_ptr = allocated_buffer;
			put_data.current_read_ptr = allocated_buffer;
			put_data.remaining_size = json_len;
		} else {
			ast_log(LOG_ERROR, "JSON string for registration object is NULL\n");
			put_data.remaining_size = 0; 
		}
	} else {
		ast_log(LOG_ERROR, "Failed to create JSON for Consul registration\n");
		if (headers) {
			curl_slist_free_all(headers);
		}
		return CURLE_OUT_OF_MEMORY;
	}


	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_URL, ast_str_buffer(url));
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, global_config.consul_timeout_ms);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) put_data.remaining_size);

	curl_easy_setopt(curl, CURLOPT_READDATA, (void *) &put_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_data);

	rcode = curl_easy_perform(curl);

	manager_event(EVENT_FLAG_SYSTEM, "DiscoveryRegister", NULL);

	ast_json_free(obj);
	curl_slist_free_all(headers);
	ast_free(put_data.original_data_ptr);

	return rcode;
}

/*!
 * \brief Function called to load or reload the configuration file
 *
 * This function loads the configuration file and updates the global configuration
 * based on the values found in the file.
 */
static void load_config(int reload)
{
	struct ast_config *cfg = NULL;

	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	struct ast_variable *v;
	char *endptr;

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
			ast_copy_string(global_config.id, v->value, sizeof(global_config.id));
		} else if (!strcasecmp(v->name, "host")) {
			ast_copy_string(global_config.host, v->value, sizeof(global_config.host));
		} else if (!strcasecmp(v->name, "port")) {
			long val = strtol(v->value, &endptr, 10);
			if (*endptr == '\0' && val > 0 && val <= 65535) {
				global_config.port = (int)val;
			} else {
				ast_log(LOG_WARNING, "Invalid port value for 'port': %s. Using default %d.\n", v->value, global_config.port);
			}
		} else if (!strcasecmp(v->name, "tags")) {
			ast_copy_string(global_config.tags, v->value, sizeof(global_config.tags));
		} else if (!strcasecmp(v->name, "name")) {
			ast_copy_string(global_config.name, v->value, sizeof(global_config.name));
		} else if (!strcasecmp(v->name, "discovery_ip")) {
			ast_copy_string(global_config.discovery_ip, v->value, sizeof(global_config.discovery_ip));
		} else if (!strcasecmp(v->name, "discovery_port")) {
			long val = strtol(v->value, &endptr, 10);
			if (*endptr == '\0' && val > 0 && val <= 65535) {
				global_config.discovery_port = (int)val;
			} else {
				ast_log(LOG_WARNING, "Invalid port value for 'discovery_port': %s. Using default %d.\n", v->value, global_config.discovery_port);
			}
		} else if (!strcasecmp(v->name, "discovery_interface")) {
			ast_copy_string(global_config.discovery_interface, v->value, sizeof(global_config.discovery_interface));
		} else if (!strcasecmp(v->name, "token")) {
			ast_copy_string(global_config.token, v->value, sizeof(global_config.token));
		} else if (!strcasecmp(v->name, "check")) {
			if (ast_true(v->value) == 0) {
				check = 0;
			}
			global_config.check = check;
		} else if (!strcasecmp(v->name, "check_http_port")) {
			long val = strtol(v->value, &endptr, 10);
			if (*endptr == '\0' && val > 0 && val <= 65535) {
				global_config.check_http_port = (int)val;
			} else {
				ast_log(LOG_WARNING, "Invalid port value for 'check_http_port': %s. Using default %d.\n", v->value, global_config.check_http_port);
			}
		} else if (!strcasecmp(v->name, "check_interval")) {
			ast_copy_string(global_config.check_interval, v->value, sizeof(global_config.check_interval));
		} else if (!strcasecmp(v->name, "consul_timeout_ms")) {
			long val = strtol(v->value, &endptr, 10);
			if (*endptr == '\0' && val > 0) {
				global_config.consul_timeout_ms = val;
			} else {
				ast_log(LOG_WARNING, "Invalid value for 'consul_timeout_ms': %s. Using default %ldms.\n", v->value, global_config.consul_timeout_ms);
			}
		} else if (!strcasecmp(v->name, "check_timeout")) {
			ast_copy_string(global_config.check_timeout, v->value, sizeof(global_config.check_timeout));
		} else if (!strcasecmp(v->name, "check_deregister_after")) {
			ast_copy_string(global_config.check_deregister_after, v->value, sizeof(global_config.check_deregister_after));
		} else if (strcasecmp(v->name, "enabled") != 0 && strcasecmp(v->name, "description") != 0) {
			ast_log(LOG_WARNING, "Unknown option in %s: %s\n", config_file, v->name);
		}
	}

	ast_config_destroy(cfg);

	return;
}

/*!
 * \brief Function called to discovery ip
 *
 * This function discovers the IP address of the system
 * and updates the global configuration with the discovered IP address.
 */
static int discovery_ip_address(void)
{
	int fd;
	struct ifreq ifr;
	char host[16];

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		ast_log(LOG_ERROR, "Failed to create socket for IP discovery: %s\n", strerror(errno));
		return -1;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, global_config.discovery_interface, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		ast_log(LOG_ERROR, "ioctl(SIOCGIFADDR) failed for interface %s: %s\n", global_config.discovery_interface, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	sprintf(host, "%s", ast_inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	ast_copy_string(global_config.discovery_ip, host, sizeof(global_config.discovery_ip));

	ast_debug(1,"Discovery IP: %s\n", host);

	return 0;
}

/*!
 * \brief Function called to discovery hostname
 *
 * This function discovers the hostname of the system
 * and updates the global configuration with the discovered hostname.
 */
static int discovery_hostname(void)
{
	char hostname[1024];

	if (gethostname(hostname, sizeof(hostname)) != 0) {
		ast_log(LOG_ERROR, "Failed to get hostname: %s\n", strerror(errno));
		/* Optionally set a default name or return an error */
		ast_copy_string(global_config.name, "asterisk-unknown", sizeof(global_config.name));
		return -1;
	}
	ast_copy_string(global_config.name, hostname, sizeof(global_config.name));

	ast_debug(1, "Discovery hostname: %s\n", hostname);

	return 0;
}

/*!
 * \brief Function called to generate uuid
 *
 * This function generates a UUID and updates the global configuration with the generated UUID.
 */
static int generate_uuid_id_consul(void)
{
	const char *uuid;
	char uuid_str[256];

	uuid = ast_uuid_generate_str(uuid_str, sizeof(uuid_str));
	ast_copy_string(global_config.id, uuid, sizeof(global_config.id));

	ast_debug(1, "Auto ID: %s\n", uuid);

	return 0;
}

static int discover_ari_settings(void) {
    struct ast_config *http_cfg;
    struct ast_variable *v;
    const char *http_conf_file = "http.conf";
    int http_enabled = 0;
    const char *port_str = NULL;
    int tls_enabled = 0;
    struct ast_flags config_load_flags = { CONFIG_FLAG_NOCACHE }; 

    ast_copy_string(global_config.ari_port, "", sizeof(global_config.ari_port));
    ast_copy_string(global_config.ari_scheme, "", sizeof(global_config.ari_scheme));

    http_cfg = ast_config_load(http_conf_file, config_load_flags);
    if (!http_cfg || http_cfg == CONFIG_STATUS_FILEINVALID || http_cfg == CONFIG_STATUS_FILEUNCHANGED) {
        ast_log(LOG_NOTICE, "Could not load '%s' for HTTP settings discovery. HTTP metadata will be omitted.\n", http_conf_file);
        if (http_cfg && http_cfg != CONFIG_STATUS_FILEINVALID && http_cfg != CONFIG_STATUS_FILEUNCHANGED) {
            ast_config_destroy(http_cfg);
        }
        return -1;
    }

    for (v = ast_variable_browse(http_cfg, "general"); v; v = v->next) {
        if (!strcasecmp(v->name, "enabled")) {
            if (ast_true(v->value)) {
                http_enabled = 1;
            }
        } else if (!strcasecmp(v->name, "bindport")) {
            port_str = v->value;
        } else if (!strcasecmp(v->name, "tlsenable")) {
            if (ast_true(v->value)) {
                tls_enabled = 1;
            }
        }
    }

    if (!http_enabled) {
        ast_log(LOG_DEBUG, "HTTP is not enabled in '%s'. HTTP metadata will be omitted.\n", http_conf_file);
        ast_config_destroy(http_cfg);
        return 0;
    }

    if (port_str) {
        ast_copy_string(global_config.ari_port, port_str, sizeof(global_config.ari_port));
        ast_debug(1, "Discovered HTTP Port: %s\n", global_config.ari_port);
    } else {
        ast_log(LOG_WARNING, "HTTP port not found in '%s'. HTTP port metadata will be omitted.\n", http_conf_file);
    }

    if (tls_enabled) {
        ast_copy_string(global_config.ari_scheme, "https", sizeof(global_config.ari_scheme));
    } else {
        ast_copy_string(global_config.ari_scheme, "http", sizeof(global_config.ari_scheme));
    }
    ast_debug(1, "Discovered ARI Scheme: %s\n", global_config.ari_scheme);

    ast_config_destroy(http_cfg);
    return 0;
}

/*!
 * \brief Function called to load the resource
 *
 * This function loads the resource and updates the global configuration
 * based on the values found in the file.
 */
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

/*!
 * \brief Function called to exec CLI
 *
 * This function executes the CLI command and returns the result.
 */
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
	ast_cli(a->fd, "ARI Port (Discovered): %s\n", !ast_strlen_zero(global_config.ari_port) ? global_config.ari_port : "Not Discovered/Enabled");
	ast_cli(a->fd, "ARI Scheme (Discovered): %s\n", !ast_strlen_zero(global_config.ari_scheme) ? global_config.ari_scheme : "Not Discovered/Enabled");
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
	ast_cli(a->fd, "Check interval: %s\n", global_config.check_interval);
	ast_cli(a->fd, "Check timeout: %s\n", global_config.check_timeout);
	ast_cli(a->fd, "Check deregister after: %s\n\n", global_config.check_deregister_after);
	ast_cli(a->fd, "----\n");

	return NULL;
}

/*!
 * \brief Function called to exec CLI
 *
 * This function executes the CLI command and returns the result.
 */
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
	if (!curl) {
		ast_log(LOG_ERROR, "Failed to initialize cURL handle for maintenance CLI\n");
		return CLI_FAILURE;
	}

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

/*!
 * \brief Function called to show current discovery status
 *
 * This function shows the current operational status of the Consul discovery module,
 * including connection to Consul and service registration details.
 */
static char *discovery_cli_show_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	CURL *curl_handle = NULL;
	CURLcode rcode;
	long http_code = 0;
	struct ast_str *url = ast_str_alloca(MAX_URL_LENGTH); /* Use ast_str_alloca for stack allocation */
	struct curl_slist *headers = NULL;
	char service_health_url[MAX_URL_LENGTH];
	int required_len_for_health_url;

	switch (cmd) {
	case CLI_INIT:
		e->command = "discovery show status";
		e->usage =
			"Usage: discovery show status\n"
			"       Shows the current operational status of the Consul discovery module,\n"
			"       including connection to Consul and service registration details.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd, "--- Consul Discovery Status ---\n");
	ast_cli(a->fd, "Module Enabled: %s\n", global_config.enabled ? "Yes" : "No");

	if (!global_config.enabled) {
		ast_cli(a->fd, "Module is disabled. No active connection to Consul.\n");
		return CLI_SUCCESS;
	}

	ast_cli(a->fd, "Consul Agent: http://%s:%d\n", global_config.host, global_config.port);
	ast_cli(a->fd, "Registered Service ID: %s\n", global_config.id);
	ast_cli(a->fd, "Registered Service Name: %s\n", global_config.name);
	ast_cli(a->fd, "Registered Address:Port: %s:%d\n", global_config.discovery_ip, global_config.discovery_port);

	curl_handle = curl_easy_init();
	if (!curl_handle) {
		ast_cli(a->fd, "Consul Connection Status: Failed to initialize cURL handle for status check.\n");
		return CLI_FAILURE;
	}

	required_len_for_health_url = snprintf(service_health_url, sizeof(service_health_url),
			 "http://%s:%d/v1/agent/health/service/id/%s",
			 global_config.host, global_config.port, global_config.id);

	if (required_len_for_health_url < 0) {
		ast_log(LOG_ERROR, "snprintf encoding error while constructing health URL for status check.\n");
		if (curl_handle) { curl_easy_cleanup(curl_handle); }
		return CLI_FAILURE;
	}
	if ((size_t)required_len_for_health_url >= sizeof(service_health_url)) {
		ast_log(LOG_WARNING, "Health URL was truncated. Hostname ('%s') or Service ID ('%s') may be too long. Cannot perform live status check.\n",
				global_config.host, global_config.id);
		ast_cli(a->fd, "Consul Live Status: Could not construct valid health check URL (hostname/ID too long for buffer %d).\n", MAX_URL_LENGTH);
		if (curl_handle) { curl_easy_cleanup(curl_handle); }
		return CLI_SUCCESS;
	}

	if (!ast_strlen_zero(global_config.token)) {
		ast_str_set(&url, 0, "%s?token=%s", service_health_url, global_config.token);
	} else {
		ast_str_set(&url, 0, "%s", service_health_url);
	}

	headers = curl_slist_append(NULL, "Accept: application/json");

	curl_easy_setopt(curl_handle, CURLOPT_URL, ast_str_buffer(url));
	curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, global_config.consul_timeout_ms);
	curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback_noop);

	rcode = curl_easy_perform(curl_handle);
	if (rcode == CURLE_OK) {
		curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 200) {
			ast_cli(a->fd, "Consul Live Status: Connected. Service '%s' is Healthy (HTTP 200 on /v1/agent/health/service/id endpoint).\n", global_config.id);
		} else if (http_code == 404) {
			ast_cli(a->fd, "Consul Live Status: Connected. Service '%s' Not Found (HTTP 404). May be deregistered or ID mismatch.\n", global_config.id);
		} else if (http_code == 429) {
			ast_cli(a->fd, "Consul Live Status: Connected. Service '%s' has Warning status (HTTP 429).\n", global_config.id);
		} else if (http_code == 503) {
			ast_cli(a->fd, "Consul Live Status: Connected. Service '%s' has Critical status (HTTP 503).\n", global_config.id);
		} else {
			ast_cli(a->fd, "Consul Live Status: Connected. Unexpected HTTP status %ld for service health query.\n", http_code);
		}
	} else {
		ast_cli(a->fd, "Consul Live Status: Failed to connect to Consul agent at http://%s:%d. Error: %s\n",
				 global_config.host, global_config.port, curl_easy_strerror(rcode));
	}

	ast_cli(a->fd, "Service Health Check Config (as registered by this module):\n");
	ast_cli(a->fd, "  Enabled: %s\n", global_config.check ? "Yes" : "No");
	if (global_config.check) {
		ast_cli(a->fd, "  Type: HTTP GET http://%s:%d/res_discovery_consul/check_eid?expected_eid=%s\n", global_config.discovery_ip, global_config.check_http_port, global_config.id);
		ast_cli(a->fd, "  Interval: %s\n", global_config.check_interval);
		ast_cli(a->fd, "  Timeout: %s\n", global_config.check_timeout);
		ast_cli(a->fd, "  DeregisterCriticalServiceAfter: %s\n", global_config.check_deregister_after);
	}

	if (headers) {
		curl_slist_free_all(headers);
	}
	if (curl_handle) {
		curl_easy_cleanup(curl_handle);
	}

	return CLI_SUCCESS;
}

/*!
 * \brief Function called to define CLI
 *
 * This function defines the CLI commands for the discovery module.
 */
static struct ast_cli_entry cli_discovery[] = {
	AST_CLI_DEFINE(discovery_cli_settings, "Show discovery settings"),
	AST_CLI_DEFINE(discovery_cli_set_maintenance, "Set discovery service in maintenance mode"),
	AST_CLI_DEFINE(discovery_cli_show_status, "Show current discovery module status")
};

/*!
 * \brief Function called to reload the module
 *
 * This function reloads the module and updates the global configuration
 * based on the values found in the file.
 */
static int reload_module(void)
{
	ast_debug(1, "Reloading res_discovery_consul module\n");

	if (global_config.enabled) {
		ast_debug(1, "Deregistering service %s due to reload\n", global_config.id);
		load_res(0);
	}

	load_config(1);

	if (global_config.enabled) {
		ast_debug(1, "Attempting to register service %s with new configuration after reload\n", global_config.id);
		if (load_res(1)) {
			ast_log(LOG_WARNING, "Failed to register with Consul after reload with new configuration\n");
		} else {
			ast_debug(1, "Successfully re-registered with Consul after reload.\n");
		}
	} else {
		ast_debug(1, "Module is disabled after reload. Not registering with Consul.\n");
	}
	return 0;
}

/*!
 * \brief Function called to unload the module
 *
 * This function unloads the module and updates the global configuration
 * based on the values found in the file.
 */
static int unload_module(void)
{
	if (global_config.enabled) {
		load_res(0);
	}
	ast_http_uri_unlink(&EID_CHECK_URI);
	ast_cli_unregister_multiple(cli_discovery, ARRAY_LEN(cli_discovery));
	ast_manager_unregister("DiscoverySetMaintenance");
	return 0;
}

/*!
 * \brief Function called to load the module
 *
 * This function loads the module and updates the global configuration
 * based on the values found in the file.
 */
static int load_module(void)
{
	int ret;

	if (!ast_module_check("res_curl.so")) {
		if (ast_load_resource("res_curl.so") != AST_MODULE_LOAD_SUCCESS) {
			ast_log(LOG_ERROR, "Cannot load res_curl, so res_discovery_consul cannot be loaded\\n");
			return AST_MODULE_LOAD_DECLINE;
		}
	}

	// Configuration settings load first
	load_config(0);
	discover_ari_settings(); // Discover ARI settings after loading config

	if (global_config.enabled != 1) { // Check enabled status after loading config
		ast_log(LOG_NOTICE, "res_discovery_consul module is disabled in configuration.\\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	if (ast_cli_register_multiple(cli_discovery, ARRAY_LEN(cli_discovery))) {
		return AST_MODULE_LOAD_FAILURE;
	}

	if (ast_manager_register_xml("DiscoverySetMaintenance", EVENT_FLAG_SYSTEM, manager_maintenance)) {
		ast_log(LOG_ERROR, "Unable to register manager action DiscoverySetMaintenance\\n");
		ast_cli_unregister_multiple(cli_discovery, ARRAY_LEN(cli_discovery));
		return AST_MODULE_LOAD_FAILURE;
	}

	// Register our HTTP URI handler
	ast_log(LOG_NOTICE, "Attempting to link HTTP URI handler for: %s\\n", EID_CHECK_URI.uri);
	ast_log(LOG_NOTICE, "  EID_CHECK_URI details before link: uri='%s', callback=%p\\n", EID_CHECK_URI.uri, (void *)EID_CHECK_URI.callback);
	ret = ast_http_uri_link(&EID_CHECK_URI);
	if (ret) { // ast_http_uri_link returns 0 on success, non-zero on failure
		ast_log(LOG_ERROR, "Failed to link Consul EID check HTTP URI handler. ast_http_uri_link returned: %d\\n", ret);
		ast_cli_unregister_multiple(cli_discovery, ARRAY_LEN(cli_discovery));
		ast_manager_unregister("DiscoverySetMaintenance");
		return AST_MODULE_LOAD_FAILURE;
	}
	ast_log(LOG_NOTICE, "Successfully registered HTTP EID check at %s\\n", EID_CHECK_URI.uri);


	if (load_res(1)) {
		ast_log(LOG_WARNING, "Failed to register with Consul\\n");
		// Optionally, decide if this is fatal. For now, module load will continue.
	} else {
		ast_log(LOG_NOTICE, "Successfully registered with Consul\\n");
	}

	return AST_MODULE_LOAD_SUCCESS;
}

/*!
 * \brief Function called to manager maintenance
 *
 * This function manages the maintenance of the service in Consul.
 */
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
	if (!curl) {
		ast_log(LOG_ERROR, "Failed to initialize cURL handle for manager maintenance\n");
		astman_send_error(s, m, "cURL initialization failed");
		return 0;
	}

	rcode = consul_maintenance_service(curl, enable);

	if (rcode != CURLE_OK) {
		ast_log(LOG_NOTICE, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rcode));
	}

	curl_easy_cleanup(curl);

	return RESULT_SUCCESS;
}

/*!
 * \brief Function called to define the module
 *
 * This function defines the module and updates the global configuration
 * based on the values found in the file.
 */
AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "Asterisk Discovery CONSUL",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.reload = reload_module,
);

