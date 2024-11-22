#ifndef CRYPTO_KEYMGR_H_INCLUDED
#define CRYPTO_KEYMGR_H_INCLUDED

#include "crypto_const.hpp"
#include "crypto_ecckey.hpp"
#include "qa/rsa_gen.hpp"
#include "crypto_history.hpp"
#include "data.hpp"
#include "crypto_key_parser.hpp"
#include "random_engine.hpp"
#include "crc32a.hpp"
#include "c_plus_plus_serializer.h"
#include "crypto_dbmgr.hpp"
#include "SHA256.h"

namespace cryptoAL
{
namespace keymgr
{
    struct public_key_desc_exporting
    {
        std::string         path_private_db;
        std::string         public_filename;
        std::string         public_other_short_filename;
        CRYPTO_FILE_TYPE    filetype;
        cryptodata*         buffer = nullptr;

        public_key_desc_exporting(const std::string& f, CRYPTO_FILE_TYPE t)
            :   path_private_db(f),
                filetype(t)
        {
            if (t == CRYPTO_FILE_TYPE::RSA_PUBLIC)
            {
                public_filename = path_private_db + RSA_MY_PUBLIC_DB;
                public_other_short_filename = RSA_OTHER_PUBLIC_DB;
            }
            else if (t == CRYPTO_FILE_TYPE::ECC_PUBLIC)
            {
                public_filename = path_private_db + ECCKEY_MY_PUBLIC_DB;
                public_other_short_filename = ECCKEY_OTHER_PUBLIC_DB;
            }
			else if (t == CRYPTO_FILE_TYPE::ECC_DOMAIN)
            {
                public_filename = path_private_db + ECC_DOMAIN_PUBLIC_DB;
                public_other_short_filename = ECC_DOMAIN_OTHER_DB;
            }
            else if (t == CRYPTO_FILE_TYPE::HH_PUBLIC)
            {
                public_filename = path_private_db + HHKEY_MY_PUBLIC_DECODE_DB; 	// reading the exported file
                public_other_short_filename = HHKEY_OTHER_PUBLIC_DECODE_DB;		// remote name
            }
		}
    };

	struct status_key_desc_exporting
    {
        std::string         path_other_public_db;
        std::string         public_filename;
        std::string         public_other_short_filename;
        CRYPTO_FILE_TYPE    filetype;
        cryptodata*         buffer = nullptr;

        status_key_desc_exporting(const std::string& f, CRYPTO_FILE_TYPE t)
            :   path_other_public_db(f),
                filetype(t)
        {
			if (t == CRYPTO_FILE_TYPE::RSA_KEY_STATUS)
			{
				public_filename = path_other_public_db + RSA_OTHER_STATUS_DB;
                public_other_short_filename = RSA_MY_STATUS_DB;
			}
			else if (t == CRYPTO_FILE_TYPE::ECC_KEY_STATUS)
			{
				public_filename = path_other_public_db + ECC_OTHER_STATUS_DB;
                public_other_short_filename = ECC_MY_STATUS_DB;
			}
			else if (t == CRYPTO_FILE_TYPE::ECC_DOM_STATUS)
			{
				public_filename = path_other_public_db + ECCDOM_OTHER_STATUS_DB;
                public_other_short_filename = ECCDOM_MY_STATUS_DB;
			}
			else if (t == CRYPTO_FILE_TYPE::HH_KEY_STATUS)
			{
				public_filename = path_other_public_db + HH_OTHER_STATUS_DB;
                public_other_short_filename = HH_MY_STATUS_DB;
			}
		}
    };

	// OTHER_PUBLIC_DB have been marked for delete
	bool delete_public_keys_marked_for_deleting(const std::string& path_public_db, CRYPTO_FILE_TYPE t, bool& key_deleted, bool verbose = false);
	bool merge_other_ecc_domain(const std::string& path_ecc_private_db, const std::string& path_ecc_other_db, bool& key_merged, [[maybe_unused]] bool verbose = false);
	bool status_confirm_or_delete(cryptoAL::db::db_mgr& dbmgr, const std::string& path_private_db, CRYPTO_FILE_TYPE t, bool& key_updated, [[maybe_unused]] bool verbose = false);

	// my ((k.confirmed == false) || (k.deleted == true)) - resending until confirmed
	bool export_public_status_key(const std::string& path_public_db, CRYPTO_FILE_TYPE t, bool& key_exist, [[maybe_unused]] bool verbose = false);
    
	// FULL copy of my public keys send to recipient (on encoding) - not incremental...TODO
	// We maintain a quota of maximum keys, creating new ones and deleting confirmed old ones
	bool export_public_key(const std::string& path_private_db, CRYPTO_FILE_TYPE t, bool& key_exist, [[maybe_unused]] bool verbose = false);
    
	bool export_public_keys(std::vector<public_key_desc_exporting>& vout,
		const std::string& folder_my_private_rsa,
		const std::string& folder_my_private_ecc,
		const std::string& folder_my_private_hh,
		bool verbose = false);

	
	bool export_public_status_keys(std::vector<status_key_desc_exporting>& vout,
		const std::string& folder_other_public_rsa,
		const std::string& folder_other_public_ecc,
		const std::string& folder_other_public_hh,
		bool verbose = false);

	bool sortkey(const std::string& a, const std::string& b);

	
	// With ECC keys we can generate new r,rG keys when encoding with recipient r'G public key
	bool get_n_keys(keyspec_type t, uint32_t n, bool first, bool last, bool random, bool newkeys,
		std::vector<std::string>& vkeys_out,
		const std::string& folder_other_public_rsa,
		const std::string& folder_other_public_ecc,
		const std::string& folder_my_private_hh,
		const std::string& folder_my_private_ecc,
		const std::string& folder_local,
		const std::string& wbaes_other_public_path,
		[[maybe_unused]] bool verbose = false);


	bool materialize_keys(keyspec& key_in,
		const std::string& folder_other_public_rsa,
		const std::string& folder_other_public_ecc,
		const std::string& folder_my_private_hh,
		const std::string& folder_my_private_ecc,
		const std::string& folder_local,
		const std::string& wbaes_other_public_path,
		bool verbose = false);

}
}
#endif
