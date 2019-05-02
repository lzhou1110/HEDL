#include <cstddef>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <stdlib.h>

#include "seal/seal.h"
#include "cppwrapper.h"



using namespace std;
using namespace seal;

namespace wrapper {
    Wrapper::Wrapper () {}

    /*
    Noise budget in a freshly made ciphertext = log2(coeff_modulus/plain_modulus) (bits)

    - scheme
        - Brakerski/Fan-Vercauteren (BFV) scheme (https://eprint.iacr.org/2012/144), with FullRNS optimization
          (https://eprint.iacr.org/2016/510).
        - Cheon-Kim-Kim-Song (CKKS) scheme (https://eprint.iacr.org/2016/421), with FullRNS optimization
          (https://eprint.iacr.org/2018/931).
    - poly_modulus_degree (degree of polynomial modulus)
        - Must be a power of 2, representing the degree of a power-of-2 cyclotomic polynomial.
        - Larger degree -> More secure, larger ciphertext sizes, slower operations.
        - Recommended degrees are 1024, 2048, 4096, 8192, 16384, 32768
    - coeff_modulus ([ciphertext] coefficient modulus) : size of the bit length of the product of primes
        - Bigger coefficient -> More noise bugget, Lower security
        - 128-bits and 192-bits already available, following Security Standard Draft http://HomomorphicEncryption.org
        - Defaults:
            DefaultParams::coeff_modulus_128(int)
            DefaultParams::coeff_modulus_192(int)
            DefaultParams::coeff_modulus_256(int)
    - plain_modulus (plaintext modulus)
        - any positive integer
        - affects:
            - size of the plaintext data type
            - noise budget in freshly encrypted cyphertext
            - consumption of noise budget in homomorphic (encrypted) multiplications
    - noise_standard_deviation (default to 3.20, should not be necessary to modify unless there are specific reasons)
    - random_generator
    */
    Wrapper::Wrapper(string scheme,
    int security_level, int poly_modulus_degree, int coeff_modulus, int plain_modulus) {
        EncryptionParameters*parms;
        // Construct the corresponding encryption parameters based on scheme
        if (scheme == "BFV") {
            parms = new EncryptionParameters(scheme_type::BFV);
        } else if (scheme == "CKKS") {
            parms = new EncryptionParameters(scheme_type::CKKS);
        } else {
            throw invalid_argument("unsupported scheme, choose among BFV, CKKS");
        }

        parms->set_poly_modulus_degree(poly_modulus_degree);

        if (security_level == 128) {
            parms->set_coeff_modulus(DefaultParams::coeff_modulus_128(poly_modulus_degree));
        } else if (security_level == 192) {
            parms->set_coeff_modulus(DefaultParams::coeff_modulus_192(poly_modulus_degree));
        } else if (security_level == 256) {
            parms->set_coeff_modulus(DefaultParams::coeff_modulus_256(poly_modulus_degree));
        } else {
            throw invalid_argument("unsupported security level, choose among 128, 192, 256");
        }

        // CKKS does not use the plain modulus coefficient
        if (scheme == "BFV") {
            parms->set_plain_modulus(plain_modulus);
        }
        this->context = SEALContext::Create(*parms);

        // Creating keys
        KeyGenerator keygen(context);
        auto public_key = keygen.public_key();
        auto secret_key = keygen.secret_key();
        auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

        // Creating encryptor, evaluator, decryptor
        this->encryptor = new Encryptor(this->context, public_key);
        this->evaluator = new Evaluator(this->context);
        this->decryptor = new Decryptor(this->context, secret_key);

    }

    Wrapper::~Wrapper () {}

    void Wrapper::clear_all_stored_pointers() {
        this->plaintext_map.clear();
    }

    void Wrapper::print_seal_version() {
        #ifdef SEAL_VERSION
        cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
        #endif
    }

    void Wrapper::print_parameters() {
        // Verify parameters
        if (!this->context)
        {
            throw invalid_argument("context is not set");
        }
        auto &context_data = *(this->context)->context_data();

        /*
        Which scheme are we using?
        */
        string scheme_name;
        switch (context_data.parms().scheme())
        {
        case scheme_type::BFV:
            scheme_name = "BFV";
            break;
        case scheme_type::CKKS:
            scheme_name = "CKKS";
            break;
        default:
            throw invalid_argument("unsupported scheme");
        }

        cout << "/ Encryption parameters:" << endl;
        cout << "| scheme: " << scheme_name << endl;
        cout << "| poly_modulus_degree: " <<
            context_data.parms().poly_modulus_degree() << endl;

        /*
        Print the size of the true (product) coefficient modulus.
        */
        cout << "| coeff_modulus size: " << context_data.
            total_coeff_modulus_bit_count() << " bits" << endl;

        /*
        For the BFV scheme print the plain_modulus parameter.
        */
        if (context_data.parms().scheme() == scheme_type::BFV)
        {
            cout << "| plain_modulus: " << context_data.
                parms().plain_modulus().value() << endl;
        }

        cout << "\\ noise_standard_deviation: " << context_data.
            parms().noise_standard_deviation() << endl;
        cout << endl;
    }

    void Wrapper::print_allocated_memory() {
        cout << "\nTotal memory allocated from the current memory pool: "
        << (MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB" << endl;
    }

    string Wrapper::plaintext_to_string(uintptr_t plaintext_pointer) {
        Plaintext plaintext = get_plaintext(plaintext_pointer);
        cout << plaintext.to_string() <<endl;
        string plaintext_string = plaintext.to_string();
        return plaintext_string;
    }

    void Wrapper::init_integer_encoder() {
        this->integerEncoder = new IntegerEncoder(this->context);
    }

    uintptr_t Wrapper::integer_encoder(int integer) {
        Plaintext plaintext = this->integerEncoder->encode(integer);
        uintptr_t plaintext_pointer = reinterpret_cast<std::uintptr_t>(&plaintext);
        this->plaintext_map[plaintext_pointer] = &plaintext;
//        cout << plaintext.to_string() << endl;
        return plaintext_pointer;
    }

    int64_t Wrapper::integer_decoder(uintptr_t plaintext_pointer) {
        Plaintext plaintext = get_plaintext(plaintext_pointer);
        return this->integerEncoder->decode_int64(plaintext);
    }

    // Private methods
    Plaintext Wrapper::get_plaintext(uintptr_t plaintext_pointer) {
        Plaintext* c_plaintext_pointer = this->plaintext_map[plaintext_pointer];
        return *(c_plaintext_pointer);
    }

    Ciphertext Wrapper::get_ciphertext(uintptr_t ciphertext_pointer) {
        Ciphertext* c_ciphertext_pointer = reinterpret_cast<Ciphertext*>(ciphertext_pointer);
        return (*c_ciphertext_pointer);
    }
}

int main() {}

