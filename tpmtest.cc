
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/bio.h>

#include <stdexcept>
#include <memory>
#include <cstring>

using namespace std;

template<typename T, typename D>
std::unique_ptr<T, D> make_handle(T* handle, D deleter) {
	return std::unique_ptr<T, D>{handle, deleter};
}

/// @brief Generate private key
/// @param path The path to store the key
static void genkey(const char *filename = "private.key", const char *password = "password", size_t mbits = 2048) {

	auto pkey = make_handle(EVP_PKEY_Q_keygen(NULL, "provider=tpm2", "RSA", mbits), EVP_PKEY_free);
	if(!pkey) {
		throw runtime_error("Error generating key");
	}

	auto file = make_handle(fopen(filename, "wb"),fclose); 

	if(PEM_write_PrivateKey(
			file.get(), 
			pkey.get(), 
			EVP_get_cipherbyname("aes-256-cbc"), 
			(unsigned char *) password, 
			(password ? strlen(password) : 0), 
			NULL, 
			NULL
	) != 1) {
		throw runtime_error("Error writing key");
	}
	
}

int main(int argc, char *argv[]) {

	OSSL_PROVIDER *defprov = NULL, *tpm2prov = NULL;

    if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL) {
        throw runtime_error("Error loading OSSL default provider");
	}

    if ((tpm2prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL) {
        throw runtime_error("Error loading OSSL tpm2 provider");
	}

	if(argc < 2) {
		printf("Usage: %s <command>\n", argv[0]);
		printf("Commands:\n");
		printf("  genkey       Generate a private key using the TPM2 provider\n");
		return 0;
	}

	for(int i = 1; i < argc; i++) {
		if (strcasecmp(argv[i], "genkey") == 0) {
			genkey();
		}
	}
	
	return 0;
}
