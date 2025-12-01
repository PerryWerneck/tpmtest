
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

static string get_filename(const char *private_key_path, const char *extension) {
	string filename = string{private_key_path};
	auto pos = filename.find_last_of('.');
	if(pos != string::npos) {
		filename = filename.substr(0, pos) + "." + extension;
	} else {
		filename = filename + "." + extension;
	}
	return filename;
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
		throw runtime_error("Error writing private key");
	}

	auto bio = make_handle(BIO_new_file(get_filename(filename,"pub").c_str(), "w"), BIO_free_all);
	if(!bio) {
		throw runtime_error("Error creating bio to write key");
	}

	if(PEM_write_bio_PUBKEY(bio.get(), pkey.get()) != 1) {
		throw runtime_error("Error writing public key");
	}

}

/// @brief Generate CSR
/// @param filename The path to store the CSR
/// @param keyfile The path to the private key file
/// @param password The password for the private key
static void gencsr(const char *filename = "private.key", const char *password = "password" ) {

	auto bio = make_handle(BIO_new_file(get_filename(filename,"pub").c_str(), "r"), BIO_free_all);
	if(!bio) {
		throw runtime_error("Error opening public key file");
	}

	auto pkey = make_handle(PEM_read_bio_PUBKEY(bio.get(), NULL, NULL, NULL), EVP_PKEY_free);
	if(!pkey) {
		throw runtime_error("Error loading public key");
	}

	auto req = make_handle(X509_REQ_new(), X509_REQ_free);
	if(!req) {
		throw runtime_error("Error creating X509_REQ");
	}

	if(!X509_REQ_set_version(req.get(), 0L)) {
		throw runtime_error("Unable to set X509 version");
	}

	X509_REQ_set_pubkey(req.get(), pkey.get());

	// Set the subject name
	struct {
			int type;
			const char *name;
			const char *value;
	} nids[] = {
		{ NID_commonName,				"commonName",			"TPM2 Test Certificate"				},
	};

 	X509_NAME *name = X509_NAME_new();

	for(const auto &nid : nids) {
		X509_NAME_add_entry_by_NID(
			name, 
			nid.type,
			MBSTRING_ASC, 
			(unsigned char *) nid.value, 
			-1, 
			-1, 
			0
		);
	}

	if(X509_REQ_set_subject_name(req.get(), name) != 1) {
		throw runtime_error("Error setting subject name");
	}

	// Sign the request
	if(X509_REQ_sign(req.get(), pkey.get(), EVP_sha256()) == 0) {
		throw runtime_error("Error signing certificate request");
	}

	auto csrfile = make_handle(fopen(get_filename(filename,"csr").c_str(), "wb"), fclose);
	if(!csrfile) {
		throw runtime_error("Error creating CSR file");
	}

	if(PEM_write_X509_REQ(csrfile.get(), req.get()) != 1) {
		throw runtime_error("Error writing CSR");
	}	
}

int main(int argc, char *argv[]) {

	auto defprov = make_handle(OSSL_PROVIDER_load(NULL, "default"), OSSL_PROVIDER_unload);
	if(!defprov) {
		throw runtime_error("Error loading OSSL default provider");
	}

	auto tpm2prov = make_handle(OSSL_PROVIDER_load(NULL, "tpm2"), OSSL_PROVIDER_unload);
	if(!tpm2prov) {
		throw runtime_error("Error loading OSSL tpm2 provider");
	}

	if(argc < 2) {
		printf("Usage: %s <command>\n", argv[0]);
		printf("Commands:\n");
		printf("  genkey       Generate a private key using the TPM2 provider\n");
		printf("  gencsr       Generate a CSR\n");
		return 0;
	}

	string keyfile = string{getenv("HOSTNAME")}.append(".key");
	string passwd = "password";

	for(int i = 1; i < argc; i++) {
		if (strcasecmp(argv[i], "genkey") == 0) {
			genkey(keyfile.c_str(), passwd.c_str());
		} else if (strcasecmp(argv[i], "gencsr") == 0) {
			gencsr(keyfile.c_str(), passwd.c_str());
		}
	}
		
	return 0;
}
