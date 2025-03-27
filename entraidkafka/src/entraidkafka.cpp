#include "entraidkafka.h"
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <stdexcept>  
#include <stdio.h>
#include <inttypes.h>
#include <azure/core/base64.hpp>
#include <azure/core/internal/json/json.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/identity/workload_identity_credential.hpp>

#ifdef _WIN32
#include "entraidwindowscert.h"
namespace entraidkafka {
#else
namespace entraidkafka {
	Azure::Core::Credentials::AccessToken get_entra_id_token_from_cert(const std::string& client_id, const std::string& tenant_id,
		const std::string& scope, const std::string& certificate_store_location, const std::string& certificate_sub_name, int timeout) {
		throw std::invalid_argument("Feature for using SN+I Cert is not available in Linux");
	}
#endif
	Azure::Core::Credentials::AccessToken get_entra_id_token_msi(const std::string& mi_client, const std::string& scope, int timeout) {
		Azure::Identity::ManagedIdentityCredential msi(mi_client);
		Azure::Core::Credentials::TokenRequestContext trc;
		trc.Scopes.push_back(scope);
		Azure::Core::Context rootContext;
		Azure::Core::Context context = rootContext.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(timeout));
		return msi.GetToken(trc, context);
	}

	Azure::Core::Credentials::AccessToken get_entra_id_token_fic(const std::string& mi_client, const std::string& client_id, const std::string& tenant_id, const std::string& scope, int timeout) {
		const std::string FIC_SCOPE = "api://AzureADTokenExchange";
		Azure::Identity::ManagedIdentityCredential msi(mi_client);
		Azure::Core::Credentials::TokenRequestContext trc;
		trc.Scopes.push_back(scope);
		Azure::Core::Credentials::TokenRequestContext fic_trc;
		fic_trc.Scopes.push_back(FIC_SCOPE);
		Azure::Core::Context root_context;
		Azure::Core::Context context = root_context.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(timeout));
		const std::string& msi_token = msi.GetToken(fic_trc, context).Token;
		Azure::Identity::ClientAssertionCredential cac(tenant_id, client_id,
			[&msi_token](const Azure::Core::Context& /*c*/) -> const std::string& {
				return msi_token;
			});
		return cac.GetToken(trc, context);
	}

	Azure::Core::Credentials::AccessToken get_entra_id_token_workload(const std::string& scope, int timeout) {
		Azure::Identity::WorkloadIdentityCredential workload;
		Azure::Core::Credentials::TokenRequestContext trc;
		trc.Scopes.push_back(scope);
		Azure::Core::Context root_context;
		Azure::Core::Context context = root_context.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(timeout));
		return workload.GetToken(trc, context);
	}

	static const std::string CONFIG_TOKEN_SCOPE = "tokenScope";
	static const std::string CONFIG_MANAGED_IDENTITY_CLIENT_ID = "msiClientId";
	static const std::string CONFIG_TENANT_ID = "tenantId";
	static const std::string CONFIG_CLIENT_ID = "clientId";
	static const std::string CONFIG_CERT_LOCATION = "certLocation";
	static const std::string CONFIG_CERT_SUB = "certSub";
	static const std::string CONFIG_TOKEN_REQUEST_TIMEOUT = "tokenRequestTimeout";
	static const std::string DEFAULT_CERT_LOCATION = "LocalMachine/My";
	static const std::string DEFAULT_TIMEOUT_SECONDS = "30";
	static const std::string EMPTY_STRING = "";

	void parse_string_to_map(const std::string& input, std::map<std::string, std::string>& kv_map) {
		std::istringstream stream(input);
		std::string token;

		// Read each key-value pair split by space
		while (stream >> token) {
			size_t pos = token.find('=');
			if (pos != std::string::npos) {
				std::string key = token.substr(0, pos);
				std::string value = token.substr(pos + 1);
				kv_map[key] = value;  // Insert into the map
			}
			else {
				throw std::invalid_argument("Invalid oauthbearer_config: no = found ");
			}
		}
	}

	const std::string& get_or_default(std::map<std::string, std::string>& kv_map, const std::string& key, const std::string& default_val) {
		auto it = kv_map.find(key);
		if (it == kv_map.end()) {
			return default_val;
		}
		return it->second;
	}

	Azure::Core::Credentials::AccessToken get_access_token(const std::string& config_string) {
		std::map<std::string, std::string> kv_map;
		// Parse the string into the map
		parse_string_to_map(config_string, kv_map);
		const std::string& scope = get_or_default(kv_map, CONFIG_TOKEN_SCOPE, EMPTY_STRING);
		if (scope.empty()) {
			throw std::invalid_argument("Invalid oauthbearer_config: tokenScope not found ");
		}
		const std::string& timeout_str = get_or_default(kv_map, CONFIG_TOKEN_REQUEST_TIMEOUT, DEFAULT_TIMEOUT_SECONDS);
		int	timeout = 0;
		std::size_t pos;
		try {
			timeout = std::stoi(timeout_str, &pos);
		}
		catch (const std::invalid_argument&) {
			throw std::invalid_argument("Invalid oauthbearer_config: tokenRequestTimeout value is not a number. ");
		}
		catch (const std::out_of_range&) {
			throw std::invalid_argument("Invalid oauthbearer_config: tokenRequestTimeout value is out of range. ");
		}
		if (pos < timeout_str.size()) {
			throw std::invalid_argument("Invalid oauthbearer_config: tokenRequestTimeout value is not a number. ");
		}
		if (timeout <= 0) {
			throw std::invalid_argument("Invalid oauthbearer_config: tokenRequestTimeout value is negative. ");
		}
		const std::string& mi_client = get_or_default(kv_map, CONFIG_MANAGED_IDENTITY_CLIENT_ID, EMPTY_STRING);
		const std::string& client_id = get_or_default(kv_map, CONFIG_CLIENT_ID, EMPTY_STRING);
		const std::string& tenant_id = get_or_default(kv_map, CONFIG_TENANT_ID, EMPTY_STRING);
		if (!mi_client.empty()) {
			if (client_id.empty() || tenant_id.empty()) {
				return get_entra_id_token_msi(mi_client, scope, timeout);
			}
			return get_entra_id_token_fic(mi_client, client_id, tenant_id, scope, timeout);
		}
		const std::string& cert_location = get_or_default(kv_map, CONFIG_CERT_LOCATION, DEFAULT_CERT_LOCATION);
		const std::string& cert_sub = get_or_default(kv_map, CONFIG_CERT_SUB, EMPTY_STRING);
		if (!client_id.empty() && !tenant_id.empty() && !cert_sub.empty()) {
			return get_entra_id_token_from_cert(client_id, tenant_id, scope, cert_location, cert_sub, timeout);
		}
		if (!client_id.empty() || !tenant_id.empty() || !cert_sub.empty()) {
			throw std::invalid_argument("Invalid oauthbearer_config: only partial of configs provided. ");
		}
		return get_entra_id_token_workload(scope, timeout);
	}

	// Function to parse the JWT and get the oid using Azure SDK
	std::string parse_jwt_get_oid(const std::string& jwt) {
		// Split the JWT into its components
		std::vector<std::string> parts;
		std::string token;
		std::istringstream token_stream(jwt);
		while (std::getline(token_stream, token, '.')) {
			parts.push_back(token);
		}
		if (parts.size() != 3) {
			throw std::runtime_error("Invalid JWT format");
		}

		// Base64 decode the payload (second part of the JWT) using Azure SDK Base64 decoder
		std::vector<uint8_t> decoded_payload = Azure::Core::_internal::Base64Url::Base64UrlDecode(parts[1]);

		// Parse the decoded payload as JSON using Azure SDK JSON parser
		Azure::Core::Json::_internal::json json_payload = Azure::Core::Json::_internal::json::parse(decoded_payload);

		// Extract the "oid" field
		if (json_payload.contains("oid")) {
			return json_payload["oid"].get<std::string>();
		}
		else {
			throw std::runtime_error("OID not found in JWT payload");
		}
	}

	int64_t get_epochmillis_unix(Azure::DateTime time) {
		const int64_t UNIX_EPOCH_DOTNET_MS = 62135596800000;
		int64_t time_raw_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
		if (time_raw_ms > UNIX_EPOCH_DOTNET_MS) {
			// Assume this is .NET epoch TS.
			time_raw_ms -= UNIX_EPOCH_DOTNET_MS;
		}
		return time_raw_ms;
	}
}

std::mutex g_token_mutex;
std::string g_token;
std::string g_oid;
int64_t g_expire;
std::atomic<bool> g_initialized{ false };
std::thread g_refresh_thread;
std::atomic<bool> g_stop_thread{ false };

void log_and_crash() {
	//log token could not be initialized or could not be renewed, crashing.....
	// crash();
}

void start_refresh_thread(std::string config_string) {
	g_refresh_thread = std::thread([config_string]() {
		while (!g_stop_thread.load()) {
			std::this_thread::sleep_for(std::chrono::seconds(10)); //check interval
			auto now = std::chrono::system_clock::now();
			auto nowMillis = std::chrono::duration_cast<std::chrono::milliseconds>(
				now.time_since_epoch()).count();
			if (g_expire > nowMillis) {
				log_and_crash();
			}
			if (g_expire > (nowMillis - 1800000)) {
				try {
					Azure::Core::Credentials::AccessToken token = entraidkafka::get_access_token(config_string);
					g_token = token.Token;
					g_oid = entraidkafka::parse_jwt_get_oid(token.Token);
					g_expire = entraidkafka::get_epochmillis_unix(token.ExpiresOn);
				}
				catch (const std::exception& ex) {
					// log error, skip retry this round
				}
			}
		}
		});
}

extern "C" EXPORT void token_refresh_cb(rd_kafka_t* rk, const char* oauthbearer_config, void* /*opaque*/) {
	try {
		char errstr[1024];
		errstr[0] = '\0';
		if (!g_initialized.load()) {
			std::lock_guard<std::mutex> lock(g_token_mutex);
			if (!g_initialized.load()) {
				Azure::Core::Credentials::AccessToken token = entraidkafka::get_access_token(oauthbearer_config);
				g_token = token.Token;
				g_oid = entraidkafka::parse_jwt_get_oid(token.Token);
				g_expire = entraidkafka::get_epochmillis_unix(token.ExpiresOn);
				g_initialized.store(true);
				start_refresh_thread(oauthbearer_config);
			}
		}
		if (rd_kafka_oauthbearer_set_token(rk, g_token.c_str(), g_expire, g_oid.c_str(),
			(const char**)NULL, 0, errstr, sizeof(errstr)) != RD_KAFKA_RESP_ERR_NO_ERROR) {
			//log errorstr
			rd_kafka_oauthbearer_set_token_failure(rk, errstr);
		}
	}
	catch (const std::exception& e) {
		rd_kafka_oauthbearer_set_token_failure(rk, e.what());
		log_and_crash();
	}
}

extern "C" EXPORT rd_kafka_resp_err_t conf_init(rd_kafka_conf_t* conf, void** /*plug_opaquep*/, char* /*errstr*/, size_t /*errstr_size*/)
{
	rd_kafka_conf_set_oauthbearer_token_refresh_cb(conf, token_refresh_cb);
	// See:  https://docs.confluent.io/platform/current/clients/librdkafka/html/rdkafka_8h.html#a988395722598f63396d7a1bedb22adaf
	// Customer should be responsible to determine if they need to set following config.
	// rd_kafka_sasl_background_callbacks_enable(rk); 
	// rd_kafka_conf_enable_sasl_queue(conf, 1);
	return RD_KAFKA_RESP_ERR_NO_ERROR;
}

void EntraIDOAuthBearerTokenRefreshCallback::oauthbearer_token_refresh_cb(RdKafka::Handle* handle, const std::string& oauthbearer_config) {
	try {
		std::string error_str = "";
		Azure::Core::Credentials::AccessToken token = entraidkafka::get_access_token(oauthbearer_config);
		int64_t epoch_expire = entraidkafka::get_epochmillis_unix(token.ExpiresOn);
		std::string oid = entraidkafka::parse_jwt_get_oid(token.Token);
		RdKafka::ErrorCode err = handle->oauthbearer_set_token(token.Token, epoch_expire, oid, {}, error_str);
		if (err != RdKafka::ERR_NO_ERROR) {
			handle->oauthbearer_set_token_failure("Failed to set OAuth token: " + RdKafka::err2str(err) + " " + error_str);
		}
	}
	catch (const std::exception& e) {
		handle->oauthbearer_set_token_failure(e.what());
	}
}
