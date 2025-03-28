#pragma once
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#include <librdkafka/rdkafka.h>
#include <librdkafka/rdkafkacpp.h>

// Use via plugin.library.paths
extern "C" EXPORT rd_kafka_resp_err_t conf_init(rd_kafka_conf_t* conf, void** plug_opaquep, char* errstr, size_t errstr_size);

// Use directly if desired (see conf_init). 
extern "C" EXPORT void token_refresh_cb(rd_kafka_t* rk, const char* oauthbearer_config, void* opaque);

class EntraIDOAuthBearerTokenRefreshCallback : public RdKafka::OAuthBearerTokenRefreshCb {
public:
	// Override the OAuth token refresh callback method
	void oauthbearer_token_refresh_cb(RdKafka::Handle* handle, const std::string& oauthbearer_config) override;
};