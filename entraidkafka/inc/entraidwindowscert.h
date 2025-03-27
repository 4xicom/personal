#pragma once
#ifdef _WIN32
#include <azure/identity/client_assertion_credential.hpp>
#include <azure/identity/client_certificate_credential.hpp>
namespace entraidkafka {
	Azure::Core::Credentials::AccessToken get_entra_id_token_from_cert(const std::string& client_id, const std::string& tenant_id,
		const std::string& scope, const std::string& certificate_store_location, const std::string& certificate_sub_name, int timeout);
}
#endif