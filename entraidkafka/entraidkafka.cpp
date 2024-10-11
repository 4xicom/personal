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
#include <azure/identity/client_assertion_credential.hpp>
#include <azure/identity/client_certificate_credential.hpp>
/*
* This section contains the feature for using sn+i certificate from windows store
*/
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
struct PEMCertificate {
	std::string certString = "";
	std::string privateKeyString = "";
	FILETIME notAfter = { 0,0 };
};

std::string ConvertTCHARToString(const TCHAR* tcharStr) {
#ifdef UNICODE
	// If using Unicode, convert from wide char to narrow string
	int size_needed = WideCharToMultiByte(CP_ACP, 0, tcharStr, -1, NULL, 0, NULL, NULL);
	std::string str(size_needed, 0);
	WideCharToMultiByte(CP_ACP, 0, tcharStr, -1, &str[0], size_needed, NULL, NULL);
	return str;
#else
	// If using MBCS, just directly convert to std::string
	return std::string(tcharStr);
#endif
}

std::string LoadContentToBase64(PBYTE pbBlob, DWORD cbBlob) {
	DWORD size = 0;
	std::string ret;
	if (CryptBinaryToString(pbBlob, cbBlob,
		CRYPT_STRING_BASE64, NULL, &size)) {
		std::unique_ptr<TCHAR[]> pemCert(new TCHAR[size]);
		if (CryptBinaryToString(pbBlob, cbBlob,
			CRYPT_STRING_BASE64, pemCert.get(), &size)) {
			ret = ConvertTCHARToString(pemCert.get());
		}
	}
	return ret;
}

// Tag CRYPT_STRING_BASE64HEADER can only get CERTIFICATE header, made this function for PRIVATE KEY header
std::string ApplyHeader(std::string content, std::string header) {
	std::stringstream ss;
	ss << "-----BEGIN " << header << "-----\n";
	ss << content;
	ss << "-----END " << header << "-----";
	return ss.str();
}

std::string exportPrivateKey(NCRYPT_KEY_HANDLE hPrivateKey) {
	DWORD cbKeyBlob = 0;
	SECURITY_STATUS  status = NCryptExportKey(
		hPrivateKey,
		NULL,
		NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
		NULL,
		NULL,
		0,
		&cbKeyBlob,
		0
	);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Fail to get private key, NCryptExportKey (get size) failed");
	}
	// Allocate memory for the key blob
	std::unique_ptr<BYTE[]> pbKeyBlob(new BYTE[cbKeyBlob]);
	if (!pbKeyBlob)
	{
		throw std::runtime_error("Fail to get private key, malloc failed");
	}
	DWORD cbResult = 0;
	status = NCryptExportKey(
		hPrivateKey,
		NULL,
		NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
		NULL,
		pbKeyBlob.get(),
		cbKeyBlob,
		&cbResult,
		0
	);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Fail to get private key, NCryptExportKey failed");
	}
	std::string ret = LoadContentToBase64(pbKeyBlob.get(), cbKeyBlob);
	return ret;
}

std::string readCertificatePrivateKey(PCCERT_CONTEXT pCertContext) {
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = 0;
	DWORD dwKeySpec = 0;
	BOOL fCallerFreeProvOrNCryptKey = FALSE;
	//Need to use NCrypt flag to get private key in NCrypt format
	//For recent versions of window only NCrypt is supported
	if (!CryptAcquireCertificatePrivateKey(
		pCertContext,
		CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
		NULL,
		&hCryptProvOrNCryptKey,
		&dwKeySpec,
		&fCallerFreeProvOrNCryptKey
	)) {
		throw std::runtime_error("Fail to readCertificatePrivateKey");
	}
	return exportPrivateKey((NCRYPT_KEY_HANDLE)hCryptProvOrNCryptKey);
}

PEMCertificate readCertificate(PCCERT_CONTEXT pCertContext) {
	PEMCertificate ret;
	std::string certpart = LoadContentToBase64(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
	if (certpart.empty()) {
		throw std::runtime_error("Fail to load certificate content");
	}
	std::string keypart = readCertificatePrivateKey(pCertContext);
	if (keypart.empty()) {
		throw std::runtime_error("Fail to load certificate private key");
	}
	ret.certString = ApplyHeader(certpart, "CERTIFICATE");
	ret.privateKeyString = ApplyHeader(keypart, "PRIVATE KEY");
	ret.notAfter.dwLowDateTime = pCertContext->pCertInfo->NotAfter.dwLowDateTime;
	ret.notAfter.dwHighDateTime = pCertContext->pCertInfo->NotAfter.dwHighDateTime;
	return ret;
}

PEMCertificate loadByCertName(HCERTSTORE hCertStore, std::string certName) {
	PCCERT_CONTEXT pCertContext = NULL;
	PCCERT_CONTEXT pPrevCertContext = NULL;
	PEMCertificate ret;
	std::string lastError = "No matching certificate found.";
	// only accept wide string
	std::wstring wstr(certName.begin(), certName.end());
	do {
		pCertContext = CertFindCertificateInStore(
			hCertStore,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_STR,
			static_cast<const void*>(wstr.c_str()),
			pPrevCertContext);
		if (pCertContext) {
			try {
				PEMCertificate certificate = readCertificate(pCertContext);
				if ((CompareFileTime(&ret.notAfter, &certificate.notAfter) < 0)) {
					ret = certificate;
				}
			}
			catch (const std::exception& e) {
				lastError = e.what();
			}
		}
		if (pPrevCertContext) {
			CertFreeCertificateContext(pPrevCertContext); // Free last
		}
		pPrevCertContext = pCertContext;
	} while (pCertContext);
	CertCloseStore(hCertStore, 0);
	if (ret.notAfter.dwLowDateTime == 0 && ret.notAfter.dwHighDateTime == 0) {
		throw std::runtime_error(lastError.c_str());
	}
	return ret;
}

PEMCertificate loadFromWindowsStore(std::string certLocation, std::string certName) {
	size_t delimiter_pos = certLocation.find('/');
	if (delimiter_pos == std::string::npos) {
		throw std::invalid_argument("Invalid certlocation config, no separator / found");
	}
	std::string location = certLocation.substr(0, delimiter_pos);
	std::string store = certLocation.substr(delimiter_pos + 1);
	std::transform(location.begin(), location.end(), location.begin(), ::tolower);
	DWORD storeTag;
	if (location == "localmachine") { //only support LocalMachine and CurrentUser for this POC
		storeTag = CERT_SYSTEM_STORE_LOCAL_MACHINE;
	}
	else if (location == "currentuser") {
		storeTag = CERT_SYSTEM_STORE_CURRENT_USER;
	}
	else {
		throw std::invalid_argument("Invalide certlocation config, not localmachine or currentuser");
	}
	// CertOpenStore only accept wide string
	std::wstring wstr(store.begin(), store.end());
	HCERTSTORE hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		storeTag,
		static_cast<const void*>(wstr.c_str())
	);
	if (!hCertStore) {
		throw std::runtime_error("Failed to open the certificate store.");
	}
	return loadByCertName(hCertStore, certName);
}

Azure::Core::Credentials::AccessToken getEntraIDTokenFromCert(std::string clientID, std::string tenantID, std::string scope, std::string certificateStoreLocation, std::string certificateSN) {
	PEMCertificate cert = loadFromWindowsStore(certificateStoreLocation, certificateSN);
	auto options = Azure::Identity::ClientCertificateCredentialOptions{};
	options.SendCertificateChain = true;
	Azure::Identity::ClientCertificateCredential clientCertificateCredential(tenantID, clientID, cert.certString, cert.privateKeyString, options);
	Azure::Core::Credentials::AccessToken token;
	Azure::Core::Credentials::TokenRequestContext trc;
	trc.Scopes.push_back(scope);
	Azure::Core::Context rootContext;
	Azure::Core::Context context = rootContext.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(30));
	return clientCertificateCredential.GetToken(trc, context);
}
#else
Azure::Core::Credentials::AccessToken getEntraIDTokenFromCert(std::string clientID, std::string tenantID, std::string scope, std::string certificateStoreLocation, std::string certificateSN) {
	throw std::invalid_argument("Feature for using SN+I Cert is available in Linux");
}
#endif



extern "C" EXPORT rd_kafka_resp_err_t conf_init(rd_kafka_conf_t* conf, void** plug_opaquep, char* errstr, size_t errstr_size)
{
	// See:  https://docs.confluent.io/platform/current/clients/librdkafka/html/rdkafka_8h.html#a988395722598f63396d7a1bedb22adaf
	rd_kafka_conf_set_oauthbearer_token_refresh_cb(conf, token_refresh_cb);
	// TODO: needed? see above doc rd_kafka_conf_enable_sasl_queue(rk, 1); -> rd_kafka_sasl_background_callbacks_enable(rk); 
	rd_kafka_conf_enable_sasl_queue(conf, 1);
	return RD_KAFKA_RESP_ERR_NO_ERROR;
}

extern "C" EXPORT void token_refresh_cb(rd_kafka_t* rk, const char* oauthbearer_config, void* opaque) {
	try {
		handle_token_refresh(rk, oauthbearer_config, opaque);
	}
	catch (const std::exception& e) {
		fprintf(stderr, "Exception in token refresh callback: %s\n", e.what());
		rd_kafka_oauthbearer_set_token_failure(rk, e.what());
	}
}

int64_t getEpochMillisUnix(Azure::DateTime time) {
	const int64_t UNIX_EPOCH_DOTNET_MS = 62135596800000;
	int64_t time_raw_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
	if (time_raw_ms > UNIX_EPOCH_DOTNET_MS) {
		// Assume this is .NET epoch TS.
		time_raw_ms -= UNIX_EPOCH_DOTNET_MS;
	}
	return time_raw_ms;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}
	return tokens;
}

// Function to parse the JWT and get the oid using Azure SDK
std::string parseJwtGetOid(const std::string& jwt) {
	// Split the JWT into its components
	std::vector<std::string> parts = split(jwt, '.');
	if (parts.size() != 3) {
		throw std::runtime_error("Invalid JWT format");
	}

	// Base64 decode the payload (second part of the JWT) using Azure SDK Base64 decoder
	std::vector<uint8_t> decoded_payload = Azure::Core::_internal::Base64Url::Base64UrlDecode(parts[1]);

	// Parse the decoded payload as JSON using Azure SDK JSON parser
	Azure::Core::Json::_internal::json jsonPayload = Azure::Core::Json::_internal::json::parse(decoded_payload);

	// Extract the "oid" field
	if (jsonPayload.contains("oid")) {
		return jsonPayload["oid"].get<std::string>();
	}
	else {
		throw std::runtime_error("OID not found in JWT payload");
	}
}

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


static const std::string CONFIG_TOKEN_SCOPE = "tokenScope";
static const std::string CONFIG_MANAGED_IDENTITY_CLIENT_ID = "msiClientId";
static const std::string CONFIG_TENANT_ID = "tenantId";
static const std::string CONFIG_CLIENT_ID = "clientId";
static const std::string CONFIG_CERT_LOCATION = "certLocation";
static const std::string CONFIG_CERT_SUB = "certSub";
static const std::string FIC_SCOPE = "api://AzureADTokenExchange";
static const std::string DEFAULT_CERT_LOCATION = "LocalMachine/My";

Azure::Core::Credentials::AccessToken getEntraIDTokenMSI(std::string miClient, std::string scope) {
	Azure::Identity::ManagedIdentityCredential msi(miClient);
	Azure::Core::Credentials::AccessToken token;
	Azure::Core::Credentials::TokenRequestContext trc;
	trc.Scopes.push_back(scope);
	Azure::Core::Context rootContext;
	Azure::Core::Context context = rootContext.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(30));
	return msi.GetToken(trc, context);
}

Azure::Core::Credentials::AccessToken getEntraIDTokenFIC(std::string miClient, std::string clientID, std::string tenantID, std::string scope) {
	Azure::Identity::ManagedIdentityCredential msi(miClient);
	Azure::Core::Credentials::AccessToken token;
	Azure::Core::Credentials::TokenRequestContext trc;
	trc.Scopes.push_back(scope);
	Azure::Core::Credentials::TokenRequestContext ficTrc;
	ficTrc.Scopes.push_back(FIC_SCOPE);
	Azure::Core::Context rootContext;
	Azure::Core::Context context = rootContext.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(30));
	std::string msiToken = msi.GetToken(ficTrc, context).Token;
	Azure::Identity::ClientAssertionCredential cac(tenantID, clientID, [msiToken](const Azure::Core::Context& c) { return msiToken; });
	return cac.GetToken(trc, context);
}

Azure::Core::Credentials::AccessToken getEntraIDTokenWorkLoad(std::string scope) {
	Azure::Identity::WorkloadIdentityCredential workload;
	Azure::Core::Credentials::AccessToken token;
	Azure::Core::Credentials::TokenRequestContext trc;
	trc.Scopes.push_back(scope);
	Azure::Core::Context rootContext;
	Azure::Core::Context context = rootContext.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(30));
	return workload.GetToken(trc, context);
}

Azure::Core::Credentials::AccessToken getAccessToken(std::string config_string) {
	std::map<std::string, std::string> kv_map;
	// Parse the string into the map
	parse_string_to_map(config_string, kv_map);
	if (kv_map.find(CONFIG_TOKEN_SCOPE) == kv_map.end()) {
		throw std::invalid_argument("Invalid oauthbearer_config: tokenScope not found ");
	}
	std::string scope = kv_map.at(CONFIG_TOKEN_SCOPE);
	if (kv_map.find(CONFIG_MANAGED_IDENTITY_CLIENT_ID) != kv_map.end()) {
		std::string miClient = kv_map.at(CONFIG_MANAGED_IDENTITY_CLIENT_ID);
		if (kv_map.find(CONFIG_CLIENT_ID) != kv_map.end() && kv_map.find(CONFIG_TENANT_ID) != kv_map.end()) {
			std::string clientID = kv_map.at(CONFIG_CLIENT_ID);
			std::string tenantID = kv_map.at(CONFIG_TENANT_ID);
			return getEntraIDTokenFIC(miClient, clientID, tenantID, scope);
		}
		return getEntraIDTokenMSI(miClient, scope);
	}
	if (kv_map.find(CONFIG_CLIENT_ID) != kv_map.end() && kv_map.find(CONFIG_TENANT_ID) != kv_map.end()
		&& kv_map.find(CONFIG_CERT_SUB) != kv_map.end()) {
		std::string clientID = kv_map.at(CONFIG_CLIENT_ID);
		std::string tenantID = kv_map.at(CONFIG_TENANT_ID);
		std::string certLocation;
		std::string certSub = kv_map.at(CONFIG_CERT_SUB);
		if (kv_map.find(CONFIG_CERT_LOCATION) != kv_map.end()) {
			certLocation = kv_map.at(CONFIG_CERT_LOCATION);
		}
		else {
			certLocation = DEFAULT_CERT_LOCATION;
		}
		return getEntraIDTokenFromCert(clientID, tenantID, scope, certLocation, certSub);
	}
	return getEntraIDTokenWorkLoad(scope);
}



void handle_token_refresh(rd_kafka_t* rk, const char* oauthbearer_config, void* opaque) {
	char errstr[1024];
	errstr[0] = '\0';
	Azure::Core::Credentials::AccessToken token = getAccessToken(oauthbearer_config);
	int64_t epochExpire = getEpochMillisUnix(token.ExpiresOn);
	std::string oid = parseJwtGetOid(token.Token);
	if (rd_kafka_oauthbearer_set_token(rk, token.Token.c_str(), epochExpire, oid.c_str(),
		(const char**)NULL, 0, errstr, sizeof(errstr)) != RD_KAFKA_RESP_ERR_NO_ERROR) {
		std::string errString(errstr);
		std::stringstream  ss;
		ss << "Error in setting oauthbearer token to librdkafka:" << errString;
		throw std::runtime_error(ss.str().c_str());
	}
}
