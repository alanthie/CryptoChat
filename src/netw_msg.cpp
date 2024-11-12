#include "../include/netw_msg.hpp"

constexpr bool DEBUG_INFO = false;

//struct MSG
//{
//	uint8_t type_msg = MSG_EMPTY; // buffer[0]
//	// digest of key = buffer[1]...buffer[32]
//
//	uint32_t buffer_len = 0;
//	uint8_t* buffer = nullptr;
//}

size_t MSG::size() { return buffer_len; };
uint8_t* MSG::get_buffer()
{
    return buffer;
}

std::string MSG::get_data_as_string()
{
    if (buffer_len > 33)
        return std::string((char*)buffer + 33, buffer_len-33);
    return std::string{};
}

bool MSG::is_same(MSG& msgin)
{
    if (this->type_msg != msgin.type_msg) return false;
    if (this->buffer_len != msgin.buffer_len) return false;
    if (memcmp(this->buffer,msgin.buffer,buffer_len)!=0) return false;
    return true;
}

void MSG::make_encrypt_msg(MSG& msgin, std::string& key)
{
    std::vector<char> vmsgin(msgin.buffer_len - 33);
    for (size_t i = 33; i < msgin.buffer_len; i++) vmsgin[i-33] = msgin.buffer[i];
    std::string b64_str = Base64::encode(vmsgin);
    std::string s = encrypt_simple_string(b64_str, key);
    make_msg(msgin.type_msg, s, msgin.buffer+1);

    if (DEBUG_INFO)
        std::cout << "Encrypt ["
            + get_summary_hex((char*)msgin.buffer+33, msgin.buffer_len - 33) + "]=>["
            + get_summary_hex((char*)this->buffer + 33, this->buffer_len - 33)
            + "]" << std::endl;
}

void MSG::make_decrypt_msg(MSG& msgin, std::string& key)
{
    std::string s = msgin.get_data_as_string();
    std::string b64_encoded_str = decrypt_simple_string(s, key);
    std::vector<char> b64_decode_vec = Base64::decode(b64_encoded_str);

    buffer = new uint8_t[33 + b64_decode_vec.size()]{ 0 };
    buffer_len = 33 + (uint32_t)b64_decode_vec.size();
    buffer[0] = msgin.type_msg;
    type_msg = msgin.type_msg;
    for (size_t i = 0; i < b64_decode_vec.size(); i++) buffer[i+33] = b64_decode_vec[i];
    //memcpy(buffer + 1, digestkey, 32);
    memcpy(buffer + 1, msgin.buffer + 1, 32);

    if (DEBUG_INFO)
        std::cout << "Decrypt ["
        + get_summary_hex((char*)msgin.buffer + 33, msgin.buffer_len - 33) + "]=>["
        + get_summary_hex((char*)this->buffer + 33, this->buffer_len - 33)
        << std::endl;
}

void MSG::make_msg(uint8_t t, const std::string& s, const std::string& key)
{
    SHA256 sha;
    sha.update((uint8_t*)key.data(), key.size());
    uint8_t* digestkey = sha.digest();

    make_msg(t, s.size(), (uint8_t*)s.data(), digestkey);
    delete[]digestkey;
}

void MSG::make_msg(uint8_t t, uint32_t len_data, uint8_t* data, uint8_t* digestkey)
{
    if (data == nullptr)
    {
        return;
    }

    type_msg = t;
    buffer_len = len_data + 33;
    buffer = new uint8_t[buffer_len]{ 0 };

    buffer[0] = t;
    memcpy(buffer + 1, digestkey, 32);
    memcpy(buffer+33, data, len_data);
}

void MSG::make_msg(uint8_t* buffer_in, size_t len)
{
    if (buffer_in == nullptr)
    {
        return;
    }
    if (len == 0)
    {
        return;
    }

    buffer = new uint8_t[len]{ 0 };

    type_msg = buffer_in[0];
    buffer_len = (uint32_t)len;
    memcpy(buffer, buffer_in, len);
}

void MSG::make_msg(uint8_t t, const std::string& s, uint8_t* digestkey)
{
    make_msg(t, (uint32_t)s.size(), (uint8_t*) s.data(), digestkey);
}

bool MSG::parse(char* message_buffer, size_t len, std::string key)
{
    if (len < 33)
    {
        type_msg = MSG_EMPTY;
        std::cerr << "WARNING MSG_EMPTY msg_len = " << len << std::endl;
        return false;
    }

    if (key.size() == 0)
    {
        std::cerr << "WARNING KEY EMPTY " << std::endl;
        return false;
    }

    SHA256 sha;
    sha.update((uint8_t*)key.data(), key.size());
    uint8_t* digestkey = sha.digest();

    if (memcmp(message_buffer + 1, digestkey, 32) != 0)
    {
        std::cerr << "WARNING INVALID key digest in MSG::parse() " << std::endl;
    }
    delete[]digestkey;

    MSG m;
    m.make_msg( (uint8_t*)message_buffer, len);
    this->make_decrypt_msg(m, key);
    return true;
}

MSG::~MSG()
{
    delete buffer;
    buffer = nullptr;
}

bool MSG::encode_idea(cryptoAL::cryptodata& data_temp, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_temp_next)
{
    bool r = true;
    char c;

    if (data_temp.buffer.size() % 8 != 0)
    {
        r = false;
        std::cerr << "ERROR " << "encode_idea data file must be multiple of 8 bytes idea: " << data_temp.buffer.size() << std::endl;
        return r;
    }
    if (data_temp.buffer.size() == 0)
    {
        r = false;
        std::cerr << "ERROR " << "encode_idea data file is empty " << std::endl;
        return r;
    }

    if (key_size % 16 != 0)
    {
        r = false;
        std::cerr << "ERROR " << "encode_idea key must be multiple of 16 bytes: " << key_size << std::endl;
        return r;
    }
    if (key_size == 0)
    {
        std::cerr << "ERROR encode_idea - key_size = 0 " << std::endl;
        return false;
    }

    uint32_t nround = 1;
    uint32_t nblock = data_temp.buffer.size() / 8;
    uint32_t nkeys = key_size / 16;

    if (data_temp.buffer.size() > 0)
    {
        if (key_size > data_temp.buffer.size())
        {
            nround = key_size / data_temp.buffer.size();
            nround++;
        }
    }

    //if (verbose)
    //{
    //	std::cout.flush();
    //	std::string message = "Encoding idea";
    //	size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
    //	std::string message_space(sz, ' ');
    //	std::cout << message << message_space <<
    //		", number of rounds : " << nround <<
    //		", number of blocks (8 bytes): " << nblock <<
    //		", number of keys (16 bytes): " << nkeys << ", shuffling: " << shufflePerc << "%" << std::endl;
    //}

    uint8_t KEY[16 + 1];
    uint8_t DATA[8 + 1];
    uint32_t key_idx = 0;

    for (size_t roundi = 0; roundi < nround; roundi++)
    {
        if (r == false)
            break;

        if (roundi > 0)
            data_temp_next.buffer.seek_begin();

        for (size_t blocki = 0; blocki < nblock; blocki++)
        {
            if (roundi == 0)
            {
                for (size_t j = 0; j < 8; j++)
                {
                    c = data_temp.buffer.getdata()[8 * blocki + j];
                    DATA[j] = c;
                }
                DATA[8] = 0; // Data must be 128 bits long
            }
            else
            {
                for (size_t j = 0; j < 8; j++)
                {
                    c = data_temp_next.buffer.getdata()[8 * blocki + j];
                    DATA[j] = c;
                }
                DATA[8] = 0; // Data must be 128 bits long
            }

            for (size_t j = 0; j < 16; j++)
            {
                c = key[16 * key_idx + j];
                KEY[j] = c;
            }
            KEY[16] = 0;

            key_idx++;
            if (key_idx >= nkeys) key_idx = 0;

            idea algo;
            algo.IDEA(DATA, KEY, true);

            data_temp_next.buffer.write((char*)&DATA[0], (uint32_t)8, -1);
        }
    }

    return r;
}

bool MSG::decode_idea(cryptoAL::cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptoAL::cryptodata& data_decrypted)
{
    bool r = true;
    char c;

    if (key_size % 16 != 0)
    {
        r = false;
        std::cerr << "ERROR " << "decode_idea key must be multiple of 16 bytes " << key_size << std::endl;
        return r;
    }
    if (data_encrypted.buffer.size() % 8 != 0)
    {
        r = false;
        std::cerr << "ERROR " << "decode_idea data must be multiple of 8 bytes " << data_encrypted.buffer.size() << std::endl;
        return r;
    }
    if (key_size == 0)
    {
        std::cerr << "ERROR decode_sidea - key_size = 0 " << "" << std::endl;
        return false;
    }
    if (data_encrypted.buffer.size() == 0)
    {
        std::cerr << "ERROR decode_sidea - data file is empty " << std::endl;
        return false;
    }

    uint32_t nround = 1;
    uint32_t nblock = data_encrypted.buffer.size() / 8;
    uint32_t nkeys = key_size / 16;


    if (data_encrypted.buffer.size() > 0)
    {
        if (key_size > data_encrypted.buffer.size())
        {
            nround = key_size / data_encrypted.buffer.size();
            nround++;
        }
    }

    //if (verbose)
    //{
    //	std::string message = "Decoding idea";
    //	size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
    //	std::string message_space(sz, ' ');
    //	std::cout << message << message_space <<
    //		", number of rounds : " << nround <<
    //		", number of blocks (8 bytes): " << nblock <<
    //		", number of keys (16 bytes): " << nkeys << std::endl;
    //}

    uint8_t KEY[16 + 1];
    uint8_t DATA[8 + 1];
    uint32_t key_idx = 0;

    for (size_t roundi = 0; roundi < nround; roundi++)
    {
        if (roundi > 0)
        {
            data_decrypted.buffer.seek_begin();
        }

        if (nround > 0)
        {
            key_idx = ((nround - roundi - 1) * nblock) % nkeys;
        }
        //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

        if (r == false)
            break;

        for (size_t blocki = 0; blocki < nblock; blocki++)
        {
            if (roundi == 0)
            {
                for (size_t j = 0; j < 8; j++)
                {
                    c = data_encrypted.buffer.getdata()[8 * blocki + j];
                    DATA[j] = c;
                }
                DATA[8] = 0;
            }
            else
            {
                for (size_t j = 0; j < 8; j++)
                {
                    c = data_decrypted.buffer.getdata()[8 * blocki + j];
                    DATA[j] = c;
                }
                DATA[8] = 0;
            }

            for (size_t j = 0; j < 16; j++)
            {
                c = key[16 * key_idx + j];
                KEY[j] = c;
            }
            KEY[16] = 0;

            key_idx++;
            if (key_idx >= nkeys) key_idx = 0;

            idea algo;
            algo.IDEA(DATA, KEY, false);

            data_decrypted.buffer.write((char*)&DATA[0], 8, -1);
        }
    }

    return r;
}
