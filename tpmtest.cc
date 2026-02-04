/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Copyright (C) 2025 Perry Werneck <perry.werneck@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits>
#include <glib.h>
#include <iostream>

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
#include <NetworkManager.h>

using namespace std;

template<typename T, typename D>
std::unique_ptr<T, D> make_handle(T* handle, D deleter) {
	return std::unique_ptr<T, D>{handle, deleter};
}

struct MainLoop {

	GMainLoop *loop;
	GError *error = NULL;

	MainLoop() : loop{g_main_loop_new(NULL, FALSE)} {
	}

	~MainLoop() {
		if(error) {
			g_error_free(error);
			error = NULL;
		}
		g_main_loop_unref(loop);
	}

	inline void run() {
		g_main_loop_run(loop);
	}
};

static string get_filename(const char *path, const char *extension = nullptr) {

	string filename = string{path};

	if(extension) {
		// Replace extension...
		auto pos = filename.find_last_of('.');
		if(pos != string::npos) {
			filename = filename.substr(0, pos) + "." + extension;
		} else {
			filename = filename + "." + extension;
		}
	}

	// .. and get full path.
	char fullpath[PATH_MAX+1];
	memset(fullpath, 0, sizeof(fullpath));	// Just in case. (:
	realpath(filename.c_str(), fullpath);

	return string{fullpath};

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
/// @param filename The path to the private key file
/// @param password The password for the private key
static void gencsr(const char *filename = "private.key", const char *password = "password" ) {

	auto req = make_handle(X509_REQ_new(), X509_REQ_free);
	if(!req) {
		throw runtime_error("Error creating X509_REQ");
	}

	if(!X509_REQ_set_version(req.get(), 0L)) {
		throw runtime_error("Unable to set X509 version");
	}

	// Set pubkey
	{
		auto bio = make_handle(BIO_new_file(get_filename(filename,"pub").c_str(), "r"), BIO_free_all);
		if(!bio) {
			throw runtime_error("Error opening public key file");
		}

		auto pkey = make_handle(PEM_read_bio_PUBKEY(bio.get(), NULL, NULL, NULL), EVP_PKEY_free);
		if(!pkey) {
			throw runtime_error("Error loading public key");
		}

		X509_REQ_set_pubkey(req.get(), pkey.get());
	}

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
	{
		auto bio = make_handle(BIO_new_file(filename, "r"), BIO_free_all);
		if(!bio) {
			throw runtime_error("Error opening private key file");
		}

		auto pkey = make_handle(PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, (void *) password), EVP_PKEY_free);
		if(!pkey) {
			throw runtime_error("Error loading private key");
		}

		if(X509_REQ_sign(req.get(), pkey.get(), EVP_sha256()) == 0) {
			throw runtime_error("Error signing certificate request");
		}

	}

	auto csrfile = make_handle(fopen(get_filename(filename,"csr").c_str(), "wb"), fclose);
	if(!csrfile) {
		throw runtime_error("Error creating CSR file");
	}

	if(PEM_write_X509_REQ(csrfile.get(), req.get()) != 1) {
		throw runtime_error("Error writing CSR");
	}	
}

static void added_cb(GObject *client, GAsyncResult *result, gpointer user_data) {

	MainLoop &data = *((MainLoop *) user_data);

    // NM responded to our request; either handle the resulting error or
    // print out the object path of the connection we just added.
    NMRemoteConnection *remote = nm_client_add_connection_finish(NM_CLIENT(client), result, &data.error);

    if (!data.error) {
        cout << "Added connection '" << nm_connection_get_path(NM_CONNECTION(remote)) << "'" << endl;
		g_object_unref(remote);
    }

    /* Tell the mainloop we're done and we can quit now */
    g_main_loop_quit(data.loop);
}

static void throw_exception(GError *error) {
	runtime_error exception{error->message};
	g_error_free(error);
	throw exception;
}

/// @brief Setup network manager
/// @param privkey The path to the private key file (certificate should be in the same path with .crt extension)
/// @param password The password for the private key
static void netsetup(const char *privkey = "private.key", const char *password = "password" ) {

	// https://github.com/H-HChen/libnm_example/blob/main/example/add_ethernet_connection.cpp
	// https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html

	// Load private key


	// Execute as root user
	GError *error = NULL;
	
	NMClient *client = nm_client_new(NULL, &error);
	if (!client) {
		throw_exception(error);
	}

	NMConnection *connection = nm_simple_connection_new();

	{
		char *uuid = nm_utils_uuid_generate();
		NMSettingConnection *s_con = (NMSettingConnection *)nm_setting_connection_new();
		g_object_set(G_OBJECT(s_con),
				NM_SETTING_CONNECTION_UUID,uuid,
				NM_SETTING_CONNECTION_ID,"TPM Based secure connection",
				NM_SETTING_CONNECTION_TYPE,"802-3-ethernet",
				NULL
		);
		g_free(uuid);
		nm_connection_add_setting(connection, NM_SETTING(s_con));
	}

	{
		NMSettingWired *s_wired = (NMSettingWired *)nm_setting_wired_new();
		nm_connection_add_setting(connection, NM_SETTING(s_wired));
	}

	{
		NMSettingIP4Config *s_ip4 = (NMSettingIP4Config *)nm_setting_ip4_config_new();

		// set ipv4.method auto
		g_object_set(G_OBJECT(s_ip4),
				NM_SETTING_IP_CONFIG_METHOD,NM_SETTING_IP4_CONFIG_METHOD_AUTO,
				NULL
		);

		nm_connection_add_setting(connection, NM_SETTING(s_ip4));

	}

	{
		// https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/authenticating-a-rhel-client-to-the-network-using-the-802-1x-standard-with-a-certificate-stored-on-the-file-system_configuring-and-managing-networking#configuring-802-1x-network-authentication-on-an-existing-ethernet-connection-by-using-nmcli_authenticating-a-rhel-client-to-the-network-using-the-802-1x-standard-with-a-certificate-stored-on-the-file-system

		NMSetting8021x *s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();

		g_object_set(
			G_OBJECT(s_8021x),
				NM_SETTING_802_1X_OPTIONAL,TRUE,
				NULL
			);

		// https://cpp.hotexamples.com/examples/-/-/nm_setting_802_1x_new/cpp-nm_setting_802_1x_new-function-examples.html
		
		{
			NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
			GError *error = NULL;

			// set 802-1x.optional true

			nm_setting_802_1x_set_private_key(
				s_8021x,
				get_filename(privkey).c_str(),
				password,
				NM_SETTING_802_1X_CK_SCHEME_PATH,
				&format,
				&error
			);

			if(error) {
				throw_exception(error);
			}

			/*
			if(Config::Value<bool>{"network-setup","use_est_ca_certs",true}.get()) {

				Logger::String{"Enabling EST CA certs"}.trace();

				NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
				nm_setting_802_1x_set_ca_cert (
					s_8021x,
					build_ssl_file_path("ca").c_str(),
					NM_SETTING_802_1X_CK_SCHEME_PATH,
					&format,
					&error
				);

				if(error) {
					Logger::String{(const char *)  error->message," (NM_SETTING_802_1X_CK_SCHEME_PATH)"}.error("nmsetup");
					Udjat::Exception exception{"Erro ao definir EST CAs ",error->message};
					g_error_free(error);
					throw exception;
				}
			}
			*/

		}

		{
			NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
			GError *error = NULL;

			nm_setting_802_1x_set_client_cert(s_8021x,
				get_filename(privkey,"crt").c_str(),
				NM_SETTING_802_1X_CK_SCHEME_PATH,
				&format,
				&error
			);

			if(error) {
				throw_exception(error);
			}

		}

		g_object_set(G_OBJECT(s_8021x),
			NM_SETTING_802_1X_SYSTEM_CA_CERTS, TRUE,
			NULL
		);

		/*
		if(identity && *identity) {
			g_object_set(G_OBJECT(s_8021x),
				NM_SETTING_802_1X_IDENTITY,
				identity,
				NULL
			);			
		}
		*/


		/*
		for(const auto &eap : Config::Value<std::vector<std::string>>{"network-setup","eap","tls"}) {
			if(!nm_setting_802_1x_add_eap_method(s_8021x,eap.c_str())) {
				throw Udjat::Exception{"Erro ao adicionar método EAP '",eap.c_str(),"'"};
			}
		}
		*/

		if(!nm_setting_802_1x_add_eap_method(s_8021x,"tls")) {
			throw runtime_error("Error adding eap method");
		}

		nm_connection_add_setting(connection, NM_SETTING(s_8021x));

	}

	MainLoop mainloop;

	nm_client_add_connection_async(client, connection, TRUE, NULL, added_cb, &mainloop);

	mainloop.run();

	g_object_unref(connection);
	g_object_unref(client);

	if(mainloop.error) {
		throw_exception(mainloop.error);
	}

}

int main(int argc, char *argv[]) {

	if(argc < 2) {
		printf("Usage: %s <command>\n\n", argv[0]);
		printf("Commands:\n\n");
		printf("  genkey       Generate a private key using the TPM2 provider\n");
		printf("  gencsr       Generate a CSR\n");
		printf("  netsetup     Setup NetworkManager using the generated key and certificate\n\n");
		return -1;
	}

	auto defprov = make_handle(OSSL_PROVIDER_load(NULL, "default"), OSSL_PROVIDER_unload);
	if(!defprov) {
		throw runtime_error("Error loading OSSL default provider");
	}

	auto tpm2prov = make_handle(OSSL_PROVIDER_load(NULL, "tpm2"), OSSL_PROVIDER_unload);
	if(!tpm2prov) {
		throw runtime_error("Error loading OSSL tpm2 provider");
	}

	string keyfile = string{getenv("HOSTNAME")}.append(".key");
	string passwd = "password";

	for(int i = 1; i < argc; i++) {
		if (strcasecmp(argv[i], "genkey") == 0) {
			genkey(keyfile.c_str(), passwd.c_str());
		} else if (strcasecmp(argv[i], "gencsr") == 0) {
			gencsr(keyfile.c_str(), passwd.c_str());
		} else if (strcasecmp(argv[i], "netsetup") == 0) {
			netsetup(keyfile.c_str(), passwd.c_str());
		}
	}
		
	return 0;
}
