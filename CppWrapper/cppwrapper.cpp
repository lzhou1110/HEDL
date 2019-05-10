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

// Helper functions
vector<long unsigned int> convert_parms_array_to_vector(array<long unsigned int, 4> parms_id) {
    std::vector<long unsigned int> result(std::begin(parms_id), std::end(parms_id));
    return result;
}

array<long unsigned int, 4> convert_parms_vector_to_array(vector<long unsigned int> parms_id) {
    array<long unsigned int, 4> result;
    copy_n(std::make_move_iterator(parms_id.begin()), 4, result.begin());
    return result;
}

namespace wrapper {

    /* Constructor & Destructor */
    Wrapper::Wrapper () {}

    Wrapper::Wrapper(
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
        string scheme,
        int security_level,
        int poly_modulus_degree,
        int coeff_modulus,
        int plain_modulus
    ) {
        // Construct the corresponding encryption parameters based on scheme
        if (scheme == "BFV") {
            this->parms = new EncryptionParameters(scheme_type::BFV);
        } else if (scheme == "CKKS") {
            this->parms = new EncryptionParameters(scheme_type::CKKS);
        } else {
            throw invalid_argument("unsupported scheme, choose among BFV, CKKS");
        }

        this->parms->set_poly_modulus_degree(poly_modulus_degree);

        if (security_level == 128) {
            this->parms->set_coeff_modulus(DefaultParams::coeff_modulus_128(poly_modulus_degree));
        } else if (security_level == 192) {
            this->parms->set_coeff_modulus(DefaultParams::coeff_modulus_192(poly_modulus_degree));
        } else if (security_level == 256) {
            this->parms->set_coeff_modulus(DefaultParams::coeff_modulus_256(poly_modulus_degree));
        } else {
            throw invalid_argument("unsupported security level, choose among 128, 192, 256");
        }

        // CKKS does not use the plain modulus coefficient
        if (scheme == "BFV") {
            this->parms->set_plain_modulus(plain_modulus);
        }
        this->context = SEALContext::Create(*this->parms);

        // Creating keys
        this->keygen = new KeyGenerator(context);
        this->public_key = this->keygen->public_key();
        this->secret_key = this->keygen->secret_key();

        // Creating encryptor, evaluator, decryptor
        this->encryptor = new Encryptor(this->context, public_key);
        this->decryptor = new Decryptor(this->context, secret_key);
        this->evaluator = new Evaluator(this->context);
        print_info();
    }

    Wrapper::~Wrapper () {}

    /* Methods */
    // context
    vector<size_t> Wrapper::context_chain_get_all_indexes() {
        vector<size_t> result;
        for (
            auto context_data = this->context->context_data();
            context_data;
            context_data = context_data->next_context_data()
        ) {
            result.push_back(context_data->chain_index());
        }
        return result;
    }

    vector<long unsigned int> Wrapper::context_chain_get_parms_id_at_index(size_t index) {
        vector<long unsigned int> result;
        for (
            auto context_data = this->context->context_data();
            context_data;
            context_data = context_data->next_context_data()
        ) {
            if (index == context_data->chain_index()) {
                result = convert_parms_array_to_vector(context_data->parms().parms_id());
            }
        }
        return result;
    }

    void Wrapper::context_chain_print_coeff_modulus_primes_at_index(size_t index) {
        for (
            auto context_data = this->context->context_data();
            context_data;
            context_data = context_data->next_context_data()
        ) {
            if (index == context_data->chain_index()) {
                cout << "coeff_modulus primes: ";
                cout << hex;
                for(const auto &prime : context_data->parms().coeff_modulus()) {
                    cout << prime.value() << " ";
                }
                cout << dec << endl;
            }
        }
    }

    vector<long unsigned int> Wrapper::get_parms_id_for_encryption_parameters() {
        return convert_parms_array_to_vector(this->parms->parms_id());
    }

    vector<long unsigned int> Wrapper::get_parms_id_for_public_key() {
        return convert_parms_array_to_vector(this->public_key.parms_id());
    }

    vector<long unsigned int> Wrapper::get_parms_id_for_secret_key() {
        return convert_parms_array_to_vector(this->secret_key.parms_id());
    }

    vector<long unsigned int> Wrapper::get_parms_id_for_plaintext(string plaintext_name) {
        return convert_parms_array_to_vector(get_plaintext(plaintext_name).parms_id());
    }

    vector<long unsigned int> Wrapper::get_parms_id_for_ciphertext(string ciphertext_name) {
        return convert_parms_array_to_vector(get_ciphertext(ciphertext_name).parms_id());
    }

    // pointers management
    void Wrapper::clear_all_stored_pointers() {
        this->plaintext_map.clear();
        this->ciphertext_map.clear();
    }

    void Wrapper::clear_plaintext(string plaintext_name) {
        check_plaintext_name_exist(plaintext_name);
        this->ciphertext_map.erase(plaintext_name);
    }

    void Wrapper::clear_ciphertext(string ciphertext_name){
        check_ciphertext_name_exist(ciphertext_name);
        this->ciphertext_map.erase(ciphertext_name);
    }

    // plaintext
    string Wrapper::plaintext_to_string(string plaintext_name) {
        return get_plaintext(plaintext_name).to_string();

    }

    string Wrapper::plaintext_create(string expression, string plaintext_name) {
        check_plaintext_name_not_exist(plaintext_name);
        plaintext_map[plaintext_name] = Plaintext(expression);
        return plaintext_name;
    }

    // ciphertext
    int Wrapper::ciphertext_size(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        return get_ciphertext(ciphertext_name).size();
    }

    // integer encoder
    void Wrapper::init_integer_encoder() {
        cout << "Initialising integer encoder" << endl;
        this->integerEncoder = new IntegerEncoder(this->context);
    }

    string Wrapper::integer_encoder(int integer, string plaintext_name) {
        check_plaintext_name_not_exist(plaintext_name);
        this->plaintext_map[plaintext_name] = this->integerEncoder->encode(integer);
        return plaintext_name;
    }

    int64_t Wrapper::integer_decoder(string plaintext_name) {
        check_plaintext_name_exist(plaintext_name);
        return this->integerEncoder->decode_int64(get_plaintext(plaintext_name));
    }

    // batch encoder
    void Wrapper::init_batch_encoder() {
        cout << "Initialising batch encoder" << endl;
        this->batchEncoder = new BatchEncoder(this->context);
        this->batching_slot_count = this->batchEncoder->slot_count();
        this->batching_row_count = this->batching_slot_count / 2;
        cout << "Slot count: " << this->batching_slot_count << endl;
        cout << "Plaintext matrix row size: " << this->batching_row_count << endl;
    }

    string Wrapper::batch_encoder(vector<uint64_t> pod_matrix, string plaintext_name) {
        check_plaintext_name_not_exist(plaintext_name);
        this->batchEncoder->encode(pod_matrix, this->plaintext_map[plaintext_name]);
        return plaintext_name;
    }

    vector<uint64_t> Wrapper::batch_decoder(string plaintext_name) {
        vector<uint64_t> pod_result;
        check_plaintext_name_exist(plaintext_name);
        this->batchEncoder->decode(get_plaintext(plaintext_name), pod_result);
        return pod_result;
    }

    // ckks encoder
    void Wrapper::init_ckks_encoder() {
        cout << "Initialising ckks encoder" << endl;
        this -> ckksEncoder = new CKKSEncoder(this->context);
        cout << "Slot count: " << this -> ckksEncoder -> slot_count() << endl;
    }

    string Wrapper::ckks_encoder(vector<double> input, double scale, string plaintext_name) {
        check_plaintext_name_not_exist(plaintext_name);
        this -> ckksEncoder -> encode(input, scale, this->plaintext_map[plaintext_name]);
        return plaintext_name;
    }

    string Wrapper::ckks_encoder(
        vector<double> input,
        vector<long unsigned int> parms_id,
        double scale,
        string plaintext_name
    ) {
        check_plaintext_name_not_exist(plaintext_name);
        array<long unsigned int, 4> parms_array = convert_parms_vector_to_array(parms_id);
        this -> ckksEncoder -> encode(input, parms_array, scale, this->plaintext_map[plaintext_name]);
        return plaintext_name;
    }

    vector<double> Wrapper::ckks_decoder(string plaintext_name, int size) {
        vector<double> result;
        check_plaintext_name_exist(plaintext_name);
        this -> ckksEncoder -> decode(get_plaintext(plaintext_name), result);
        result.resize(size);
        return result;
    }

    // encrypt & decrypt
    int Wrapper::decryptor_noise_budget(string ciphertext_name) {
        Ciphertext ciphertext = get_ciphertext(ciphertext_name);
        return this->decryptor->invariant_noise_budget(ciphertext);
    }

    string Wrapper::encryptor_encrypt(string plaintext_name, string ciphertext_name) {
        Plaintext plaintext = get_plaintext(plaintext_name);
        check_ciphertext_name_not_exist(ciphertext_name);
        this->encryptor->encrypt(plaintext, this->ciphertext_map[ciphertext_name]);
        return ciphertext_name;
    }

    string Wrapper::decryptor_decrypt(string ciphertext_name, string plaintext_name) {
        Ciphertext ciphertext = get_ciphertext(ciphertext_name);
        check_plaintext_name_not_exist(plaintext_name);
        this->decryptor->decrypt(ciphertext, this->plaintext_map[plaintext_name]);
        return plaintext_name;
    }

    // evaluator
    void Wrapper::evaluator_relinearize_inplace(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        this->evaluator->relinearize_inplace(get_ciphertext(ciphertext_name), this->relinearize_keys);
    }

    void Wrapper::evaluator_negate_inplace(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        this->evaluator->negate_inplace(get_ciphertext(ciphertext_name));
    }

    void Wrapper::evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2) {
        check_ciphertext_name_exist(ciphertext_name1);
        check_ciphertext_name_exist(ciphertext_name2);
        cout << "passed checking" << endl;
        this->evaluator->add_inplace(
            get_ciphertext(ciphertext_name1),
            get_ciphertext(ciphertext_name2));
    }

    void Wrapper::evaluator_multiply_inplace(string ciphertext_name1, string ciphertext_name2) {
        check_ciphertext_name_exist(ciphertext_name1);
        check_ciphertext_name_exist(ciphertext_name2);
        this->evaluator->multiply_inplace(
            get_ciphertext(ciphertext_name1),
            get_ciphertext(ciphertext_name2));
    }

    void Wrapper::evaluator_square_inplace(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        this->evaluator->square_inplace(
            get_ciphertext(ciphertext_name));
    }

    void Wrapper::evaluator_add_plain_inplace(string ciphertext_name, string plaintext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        check_plaintext_name_exist(plaintext_name);
        this->evaluator->add_plain_inplace(
            get_ciphertext(ciphertext_name),
            get_plaintext(plaintext_name));
    }

    void Wrapper::evaluator_rotate_rows_inplace(string ciphertext_name, int steps) {
        check_ciphertext_name_exist(ciphertext_name);
        this->evaluator->rotate_rows_inplace(get_ciphertext(ciphertext_name), steps, this->galois_keys);
    }

    void Wrapper::evaluator_rotate_columns_inplace(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        this->evaluator->rotate_columns_inplace(get_ciphertext(ciphertext_name), this->galois_keys);
    }

    void Wrapper::evaluator_mod_switch_to_next_inplace(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        this->evaluator->mod_switch_to_next_inplace(get_ciphertext(ciphertext_name));
    }

    // relinearization
    void Wrapper::relinearization_generate_keys(int decomposition_bit_count, size_t count) {
        /*
        Relinearization can reduce the size of ciphertexts back to initial size (2).
        Large decomposition bit count -> fast relinearization -> more noise budget consumption
        Small decomposition bit count -> slow relinearization -> less noise budget consumption

        Reducing a ciphertext of size M >= 2 back to size 2 will need M-2 relinearization keys
        */
        this->relinearize_keys = this->keygen->relin_keys(decomposition_bit_count, count);
    }

    int Wrapper::relinearization_dbc_max() {
        // Roughly 60
        return DefaultParams::dbc_max();
    }

    int Wrapper::relinearization_dbc_min() {
        // Roughly 1
        return DefaultParams::dbc_min();
    }

    // batching
    bool Wrapper::batching_is_enabled() {
        auto qualifiers = this->context->context_data()->qualifiers();
        return qualifiers.using_batching;
    }

    void Wrapper::batching_generate_galois_keys(int decomposition_bit_count) {
        /*
        Galois keys:
        Large decomposition bit count -> fast matrix row/column rotation -> more noise budget consumption
        Small decomposition bit count -> slow matrix row/column rotation -> less noise budget consumption
        */
        this->galois_keys = this->keygen->galois_keys(decomposition_bit_count);
    }

    // ckks
    double Wrapper::get_scale_for_plaintext(string plaintext_name) {
        check_plaintext_name_exist(plaintext_name);
        return get_plaintext(plaintext_name).scale();
    }

    double Wrapper::get_scale_for_ciphertext(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        return get_ciphertext(ciphertext_name).scale();
    }

    /* Private Methods */
    // logging
    void Wrapper::print_info() {
        #ifdef SEAL_VERSION
        cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
        #endif
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
        cout << "| noise_standard_deviation: " << context_data.
            parms().noise_standard_deviation() << endl;
        cout << "\\Total memory allocated from the current memory pool: "
            << (MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB" << endl;
        cout << endl;
    }

    void Wrapper::check_plaintext_name_exist(string plaintext_name) {
        auto search_result = this->plaintext_map.find(plaintext_name);
        if (search_result == this->plaintext_map.end()) {
            std::stringstream msg;
            msg << "Plaintext name '" << plaintext_name << "' does not exist";
            throw std::invalid_argument(msg.str());
        }
    }

    void Wrapper::check_ciphertext_name_exist(string ciphertext_name){
        auto search_result = this->ciphertext_map.find(ciphertext_name);
        if (search_result == this->ciphertext_map.end()) {
            std::stringstream msg;
            msg << "Ciphertext name '" << ciphertext_name << "' does not exist";
            throw std::invalid_argument(msg.str());
        }
    }

    void Wrapper::check_plaintext_name_not_exist(string plaintext_name){
        auto search_result = this->plaintext_map.find(plaintext_name);
        if (search_result != this->plaintext_map.end()) {
            std::stringstream msg;
            msg << "Plaintext name '" << plaintext_name << "' already exists";
            throw std::invalid_argument(msg.str());
        }
    }

    void Wrapper::check_ciphertext_name_not_exist(string ciphertext_name){
        auto search_result = this->ciphertext_map.find(ciphertext_name);
        if (search_result != this->ciphertext_map.end()) {
            std::stringstream msg;
            msg << "Ciphertext name '" << ciphertext_name << "' already exists";
            throw std::invalid_argument(msg.str());
        }
    }

    Plaintext& Wrapper::get_plaintext(string plaintext_name) {
        check_plaintext_name_exist(plaintext_name);
        return plaintext_map[plaintext_name];
    }

    Ciphertext& Wrapper::get_ciphertext(string ciphertext_name) {
        check_ciphertext_name_exist(ciphertext_name);
        return this->ciphertext_map[ciphertext_name];
    }

    void Wrapper::print_matrix(vector<uint64_t> pod_matrix) {
        size_t row_size = this->batching_row_count;
        auto print_matrix = [row_size](auto &matrix) {
            cout << endl;

            /*
            We're not going to print every column of the matrix (there are 2048). Instead
            print this many slots from beginning and end of the matrix.
            */
            size_t print_size = 5;

            cout << "    [";
            for (size_t i = 0; i < print_size; i++)
            {
                cout << setw(3) << matrix[i] << ",";
            }
            cout << setw(3) << " ...,";
            for (size_t i = row_size - print_size; i < row_size; i++)
            {
                cout << setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
            }
            cout << "    [";
            for (size_t i = row_size; i < row_size + print_size; i++)
            {
                cout << setw(3) << matrix[i] << ",";
            }
            cout << setw(3) << " ...,";
            for (size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
            {
                cout << setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
            }
            cout << endl;
        };
        print_matrix(pod_matrix);
    }
}

int main() {}

