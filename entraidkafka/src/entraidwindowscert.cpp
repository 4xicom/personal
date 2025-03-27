#include "entraidwindowscert.h"
/*
* This section contains the feature for using sn+i certificate from windows store
*/
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
namespace entraidkafka {

	// Tag CRYPT_STRING_BASE64HEADER can only get CERTIFICATE header, made this function for PRIVATE KEY header
	// This will change the base64 string to PEM format
	std::string apply_header(const std::string& content, const std::string& header) {
		return  "-----BEGIN " + header + "-----\n" + content + "-----END " + header + "-----";
	}

	struct PEMCertificate {
		std::string cert_string;
		std::string privatekey_string;
		FILETIME not_after;
		PEMCertificate(const std::string& cert, const std::string& private_key, FILETIME expiration)
			: cert_string(apply_header(cert, "CERTIFICATE")), privatekey_string(apply_header(private_key, "PRIVATE KEY")), not_after(expiration) {
		}
	};

#ifdef UNICODE
	std::string convert_tchar_to_string(const TCHAR* tchar_str) {
		int size_needed = WideCharToMultiByte(CP_UTF8, 0, tchar_str, -1, NULL, 0, NULL, NULL);
		if (size_needed == 0) {
			throw std::runtime_error("Failed to calculate size needed for UTF-8 conversion.");
		}
		std::string str(size_needed, 0);
		int bytes_written = WideCharToMultiByte(CP_UTF8, 0, tchar_str, -1, &str[0], size_needed, NULL, NULL);
		if (bytes_written == 0) {
			DWORD error_code = GetLastError();
			throw std::runtime_error("WideCharToMultiByte conversion failed with error code: " + std::to_string(error_code));
		}
		return str;
	}
#else
	std::string convert_tchar_to_string(const TCHAR* tchar_str) {
		// If using MBCS, just directly convert to std::string
		return std::string(tchar_str);
	}
#endif

	std::string load_content_to_base64(PBYTE pb_blob, DWORD cb_blob) {
		DWORD size = 0;
		std::string ret;
		if (CryptBinaryToString(pb_blob, cb_blob,
			CRYPT_STRING_BASE64, NULL, &size)) {
			std::unique_ptr<TCHAR[]> pem_cert(new TCHAR[size]);
			if (CryptBinaryToString(pb_blob, cb_blob,
				CRYPT_STRING_BASE64, pem_cert.get(), &size)) {
				ret = convert_tchar_to_string(pem_cert.get());
			}
		}
		return ret;
	}

	std::string export_privatekey(NCRYPT_KEY_HANDLE hprivatekey) {
		DWORD cb_key_blob = 0;
		SECURITY_STATUS  status = NCryptExportKey(
			hprivatekey,
			NULL,
			NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
			NULL,
			NULL,
			0,
			&cb_key_blob,
			0
		);
		if (status != ERROR_SUCCESS)
		{
			throw std::runtime_error("Fail to get private key, NCryptExportKey (get size) failed. ErrorCode: " + std::to_string(status));
		}
		// Allocate memory for the key blob
		std::unique_ptr<BYTE[]> pb_key_blob(new BYTE[cb_key_blob]);
		if (!pb_key_blob)
		{
			throw std::runtime_error("Fail to get private key, malloc failed");
		}
		DWORD cb_result = 0;
		status = NCryptExportKey(
			hprivatekey,
			NULL,
			NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
			NULL,
			pb_key_blob.get(),
			cb_key_blob,
			&cb_result,
			0
		);
		if (status != ERROR_SUCCESS)
		{
			throw std::runtime_error("Fail to get private key, NCryptExportKey failed. ErrorCode: " + std::to_string(status));
		}
		std::string ret = load_content_to_base64(pb_key_blob.get(), cb_key_blob);
		return ret;
	}

	class KeyHandle {
	public:
		KeyHandle(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle, DWORD keySpec, BOOL shouldFree)
			: handle_(handle), keySpec_(keySpec), shouldFree_(shouldFree) {
		}

		~KeyHandle() {
			if (shouldFree_ && handle_) {
				if (keySpec_ == CERT_NCRYPT_KEY_SPEC) {
					NCryptFreeObject((NCRYPT_KEY_HANDLE)handle_);
				}
				else {
					CryptReleaseContext((HCRYPTPROV)handle_, 0);
				}
			}
		}
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE get() const { return handle_; }
		// Disable copying
		KeyHandle(const KeyHandle&) = delete;
		KeyHandle& operator=(const KeyHandle&) = delete;

	private:
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle_;
		DWORD keySpec_;
		BOOL shouldFree_;
	};
	std::string read_certificate_privateKey(PCCERT_CONTEXT p_cert_context) {
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hcrypt_prov_or_ncrypt_key = 0;
		DWORD dw_key_spec = 0;
		BOOL fcaller_free_prov_or_ncrypt_key = FALSE;
		//Need to use NCrypt flag to get private key in NCrypt format
		//For recent versions of window only NCrypt is supported
		if (!CryptAcquireCertificatePrivateKey(
			p_cert_context,
			CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
			NULL,
			&hcrypt_prov_or_ncrypt_key,
			&dw_key_spec,
			&fcaller_free_prov_or_ncrypt_key
		)) {
			throw std::runtime_error("Fail to read_certificate_privateKey. Error: " + std::to_string(GetLastError()));
		}
		KeyHandle managedHandle(hcrypt_prov_or_ncrypt_key, dw_key_spec, fcaller_free_prov_or_ncrypt_key);
		return export_privatekey((NCRYPT_KEY_HANDLE)managedHandle.get());;
	}

	PEMCertificate read_certificate(PCCERT_CONTEXT pcert_context) {
		std::string certpart = load_content_to_base64(pcert_context->pbCertEncoded, pcert_context->cbCertEncoded);
		if (certpart.empty()) {
			throw std::runtime_error("Fail to load certificate content");
		}
		std::string keypart = read_certificate_privateKey(pcert_context);
		if (keypart.empty()) {
			throw std::runtime_error("Fail to load certificate private key");
		}
		return PEMCertificate(certpart, keypart, pcert_context->pCertInfo->NotAfter);
	}

	PEMCertificate load_by_cert_sub_name(HCERTSTORE hcert_store, const std::string& cert_sub_name) {
		PCCERT_CONTEXT pcert_context = NULL;
		PCCERT_CONTEXT pprev_cert_context = NULL;
		PEMCertificate latest_certificate("", "", { 0, 0 });
		std::string last_error = "No matching certificate found.";
		// only accept wide string
		std::wstring wstr(cert_sub_name.begin(), cert_sub_name.end());
		do {
			pcert_context = CertFindCertificateInStore(
				hcert_store,
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				0,
				CERT_FIND_SUBJECT_STR,
				static_cast<const void*>(wstr.c_str()),
				pprev_cert_context);
			if (pcert_context) {
				try {
					PEMCertificate candidate = read_certificate(pcert_context);
					if ((CompareFileTime(&latest_certificate.not_after, &candidate.not_after) < 0)) {
						latest_certificate = std::move(candidate);
					}
				}
				catch (const std::exception& e) {
					last_error = e.what();
				}
			}
			if (pprev_cert_context) {
				CertFreeCertificateContext(pprev_cert_context); // Free last
			}
			pprev_cert_context = pcert_context;
		} while (pcert_context);
		CertCloseStore(hcert_store, 0);
		if (latest_certificate.not_after.dwLowDateTime == 0 && latest_certificate.not_after.dwHighDateTime == 0) {
			throw std::runtime_error(last_error.c_str());
		}
		return latest_certificate;
	}

	PEMCertificate load_from_windows_cert_store(const std::string& certificate_store_location, const std::string& cert_name) {
		size_t delimiter_pos = certificate_store_location.find('/');
		if (delimiter_pos == std::string::npos) {
			throw std::invalid_argument("Invalid certlocation config, no separator / found");
		}
		std::string location = certificate_store_location.substr(0, delimiter_pos);
		std::string store = certificate_store_location.substr(delimiter_pos + 1);
		std::transform(location.begin(), location.end(), location.begin(), [](char c) {
			return static_cast<char>(std::tolower(c));
			});
		DWORD store_tag;
		if (location == "localmachine") { //only support LocalMachine and CurrentUser for this lib
			store_tag = CERT_SYSTEM_STORE_LOCAL_MACHINE;
		}
		else if (location == "currentuser") {
			store_tag = CERT_SYSTEM_STORE_CURRENT_USER;
		}
		else {
			throw std::invalid_argument("Invalide certlocation config, not localmachine or currentuser");
		}
		// CertOpenStore only accept wide string
		std::wstring wstr(store.begin(), store.end());
		HCERTSTORE hcert_store = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,
			NULL,
			store_tag,
			static_cast<const void*>(wstr.c_str())
		);
		if (!hcert_store) {
			throw std::runtime_error("Failed to open the certificate store. Error: " + std::to_string(GetLastError()));
		}
		return load_by_cert_sub_name(hcert_store, cert_name);
	}

	Azure::Core::Credentials::AccessToken get_entra_id_token_from_cert(const std::string& client_id, const std::string& tenant_id,
		const std::string& scope, const std::string& certificate_store_location, const std::string& certificate_sub_name, int timeout) {
		PEMCertificate cert = load_from_windows_cert_store(certificate_store_location, certificate_sub_name);
		auto options = Azure::Identity::ClientCertificateCredentialOptions{};
		options.SendCertificateChain = true; //Use x5c header
		Azure::Identity::ClientCertificateCredential clientCertificateCredential(tenant_id, client_id, cert.cert_string, cert.privatekey_string, options);
		Azure::Core::Credentials::TokenRequestContext trc;
		trc.Scopes.push_back(scope);
		Azure::Core::Context root_context;
		Azure::Core::Context context = root_context.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(timeout));
		return clientCertificateCredential.GetToken(trc, context);
	}
}
#endif
