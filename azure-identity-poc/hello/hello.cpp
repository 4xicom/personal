using namespace std;
#include <azure/identity/client_certificate_credential.hpp>
#include "hello.h"
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

struct PEMCertificate {
	std::string certString = "";
	std::string privateKeyString = "";
	FILETIME notAfter = { 0,0 };
};

std::string LoadContentToBase64(PBYTE pbBlob, DWORD cbBlob) {
	DWORD size = 0;
	std::string ret;
	if (CryptBinaryToString(pbBlob, cbBlob,
		CRYPT_STRING_BASE64, NULL, &size)) {
		char* pemCert = new char[size];
		if (CryptBinaryToString(pbBlob, cbBlob,
			CRYPT_STRING_BASE64, pemCert, &size)) {
			ret = std::string(pemCert);
		}
		delete[] pemCert;
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
		throw std::exception("Fail to get private key, NCryptExportKey (get size) failed");
	}
	// Allocate memory for the key blob
	PBYTE pbKeyBlob = (PBYTE)malloc(cbKeyBlob);
	if (!pbKeyBlob)
	{
		throw std::exception("Fail to get private key, malloc failed");
	}
	DWORD cbResult = 0;
	status = NCryptExportKey(
		hPrivateKey,
		NULL,
		NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
		NULL,
		pbKeyBlob,
		cbKeyBlob,
		&cbResult,
		0
	);
	if (status != ERROR_SUCCESS)
	{
		delete pbKeyBlob;
		throw std::exception("Fail to get private key, NCryptExportKey failed");
	}
	std::string ret = LoadContentToBase64(pbKeyBlob, cbKeyBlob);
	delete pbKeyBlob;
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
		throw std::exception("Fail to readCertificatePrivateKey");
	}
	return exportPrivateKey((NCRYPT_KEY_HANDLE)hCryptProvOrNCryptKey);
}

PEMCertificate readCertificate(PCCERT_CONTEXT pCertContext) {
	PEMCertificate ret;
	std::string certpart = LoadContentToBase64(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
	if (certpart.empty()) {
		throw std::exception("Fail to load certificate content");
	}
	std::string keypart = readCertificatePrivateKey(pCertContext);
	if (keypart.empty()) {
		throw std::exception("Fail to load certificate private key");
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
		throw std::exception(lastError.c_str());
	}
	return ret;
}

PEMCertificate loadFromWindowsStore(std::string certLocation, std::string certName) {
	size_t delimiter_pos = certLocation.find('/');
	if (delimiter_pos == std::string::npos) {
		throw std::exception("Invalid certlocation config, no separator / found");
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
		throw std::exception("Invalide certlocation config, not localmachine or currentuser");
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
		throw std::exception("Failed to open the certificate store.");
	}
	return loadByCertName(hCertStore, certName);
}



std::string GetTenantId() { return "72f988bf-86f1-41af-91ab-2d7cd011db47"; }
std::string GetClientId() { return "1c3c7e45-4c3d-41dc-9691-74240fe974c5"; }
std::string GetScope() { return "https://graph.microsoft.com/.default"; }
// Sub CN of the certificate
std::string GetCertificateSN() { return  "*.magnetarcerttest.binginternal.com"; }
// Could be LocalMachine/My , LocalMachine/Root, CurrentUser/My, etc.
std::string GetCertificateStoreLocation() { return  "LocalMachine/My"; }
int main()
{
	try
	{
		//Load the certificate from Windows Store with SN
		//Contains both cert (not cert chain) and private key , in PEM file format as string
		PEMCertificate cert = loadFromWindowsStore(GetCertificateStoreLocation(), GetCertificateSN());

		//set the config to add x5c header in the exchange token
		auto options = Azure::Identity::ClientCertificateCredentialOptions{};
		options.SendCertificateChain = true;

		auto clientCertificateCredential = std::make_shared<Azure::Identity::ClientCertificateCredential>(
			GetTenantId(), GetClientId(), cert.certString, cert.privateKeyString, options);

		Azure::Core::Context context = Azure::Core::Context::ApplicationContext.WithDeadline(std::chrono::system_clock::now() + std::chrono::seconds(30));

		Azure::Core::Credentials::TokenRequestContext tokenRequestContext;
		tokenRequestContext.Scopes = { GetScope() };

		auto token = clientCertificateCredential.get()->GetToken(tokenRequestContext, context);

		std::cout << "Success!" << std::endl;
		std::cout << token.Token << std::endl;
	}
	catch (const Azure::Core::Credentials::AuthenticationException& exception)
	{
		std::cout << "Authentication error: " << exception.what() << std::endl;
		return 1;
	}
	return 0;
}
