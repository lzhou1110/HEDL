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
#include "cppperformance.h"

using namespace std;
using namespace seal;


/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(shared_ptr <SEALContext> context) {
    // Verify parameters
    if (!context) {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    string scheme_name;
    switch (context_data.parms().scheme()) {
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
    if (context_data.parms().scheme() == scheme_type::BFV) {
        cout << "| plain_modulus: " << context_data.
                parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: " << context_data.
            parms().noise_standard_deviation() << endl;
    cout << endl;
}


namespace performance {

    /* Constructor & Destructor */
    Performance::Performance() {}

    Performance::~Performance() {}

    /* Methods */
    void Performance::run_bfv_performance_test() {

        /*
        In this example we time all the basic operations. We use the following
        lambda function to run the test.
        */
        auto performance_test = [](auto context) {
            chrono::high_resolution_clock::time_point time_start, time_end;

            print_parameters(context);
            auto &curr_parms = context->context_data()->parms();
            auto &plain_modulus = curr_parms.plain_modulus();
            size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

            /*
            Set up keys. For both relinearization and rotations we use a large
            decomposition bit count for best possible computational performance.
            */
            cout << "Generating secret/public keys: ";
            KeyGenerator keygen(context);
            cout << "Done" << endl;

            auto secret_key = keygen.secret_key();
            auto public_key = keygen.public_key();

            /*
            Generate relinearization keys.
            */
            int dbc = DefaultParams::dbc_max();
            cout << "Generating relinearization keys (dbc = " << dbc << "): ";
            time_start = chrono::high_resolution_clock::now();
            auto relin_keys = keygen.relin_keys(dbc);
            time_end = chrono::high_resolution_clock::now();
            auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            cout << "Done [" << time_diff.count() << " microseconds]" << endl;

            /*
            Generate Galois keys. In larger examples the Galois keys can use
            a significant amount of memory, which can be a problem in constrained
            systems. The user should try enabling some of the larger runs of the
            test (see below) and to observe their effect on the memory pool
            allocation size. The key generation can also take a significant amount
            of time, as can be observed from the print-out.
            */
            if (!context->context_data()->qualifiers().using_batching) {
                cout << "Given encryption parameters do not support batching." << endl;
                return;
            }
            cout << "Generating Galois keys (dbc = " << dbc << "): ";
            time_start = chrono::high_resolution_clock::now();
            auto gal_keys = keygen.galois_keys(dbc);
            time_end = chrono::high_resolution_clock::now();
            time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            cout << "Done [" << time_diff.count() << " microseconds]" << endl;

            Encryptor encryptor(context, public_key);
            Decryptor decryptor(context, secret_key);
            Evaluator evaluator(context);
            BatchEncoder batch_encoder(context);
            IntegerEncoder encoder(context);

            /*
            These will hold the total times used by each operation.
            */
            chrono::microseconds time_batch_sum(0);
            chrono::microseconds time_unbatch_sum(0);
            chrono::microseconds time_encrypt_sum(0);
            chrono::microseconds time_decrypt_sum(0);
            chrono::microseconds time_add_sum(0);
            chrono::microseconds time_multiply_sum(0);
            chrono::microseconds time_multiply_plain_sum(0);
            chrono::microseconds time_square_sum(0);
            chrono::microseconds time_relinearize_sum(0);
            chrono::microseconds time_rotate_rows_one_step_sum(0);
            chrono::microseconds time_rotate_rows_random_sum(0);
            chrono::microseconds time_rotate_columns_sum(0);

            /*
            How many times to run the test?
            */
            int count = 10;

            /*
            Populate a vector of values to batch.
            */
            vector <uint64_t> pod_vector;
            random_device rd;
            for (size_t i = 0; i < batch_encoder.slot_count(); i++) {
                pod_vector.push_back(rd() % plain_modulus.value());
            }

            cout << "Running tests ";
            for (int i = 0; i < count; i++) {
                /*
                [Batching]
                There is nothing unusual here. We batch our random plaintext matrix
                into the polynomial. The user can try changing the decomposition bit
                count to something smaller to see the effect. Note how the plaintext
                we create is of the exactly right size so unnecessary reallocations
                are avoided.
                */
                Plaintext plain(curr_parms.poly_modulus_degree(), 0);
                time_start = chrono::high_resolution_clock::now();
                batch_encoder.encode(pod_vector, plain);
                time_end = chrono::high_resolution_clock::now();
                time_batch_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Unbatching]
                We unbatch what we just batched.
                */
                vector <uint64_t> pod_vector2(batch_encoder.slot_count());
                time_start = chrono::high_resolution_clock::now();
                batch_encoder.decode(plain, pod_vector2);
                time_end = chrono::high_resolution_clock::now();
                time_unbatch_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);
                if (pod_vector2 != pod_vector) {
                    throw runtime_error("Batch/unbatch failed. Something is wrong.");
                }

                /*
                [Encryption]
                We make sure our ciphertext is already allocated and large enough to
                hold the encryption with these encryption parameters. We encrypt our
                random batched matrix here.
                */
                Ciphertext encrypted(context);
                time_start = chrono::high_resolution_clock::now();
                encryptor.encrypt(plain, encrypted);
                time_end = chrono::high_resolution_clock::now();
                time_encrypt_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Decryption]
                We decrypt what we just encrypted.
                */
                Plaintext plain2(poly_modulus_degree, 0);
                time_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(encrypted, plain2);
                time_end = chrono::high_resolution_clock::now();
                time_decrypt_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);
                if (plain2 != plain) {
                    throw runtime_error("Encrypt/decrypt failed. Something is wrong.");
                }

                /*
                [Add]
                We create two ciphertexts that are both of size 2, and perform a few
                additions with them.
                */
                Ciphertext encrypted1(context);
                encryptor.encrypt(encoder.encode(i), encrypted1);
                Ciphertext encrypted2(context);
                encryptor.encrypt(encoder.encode(i + 1), encrypted2);
                time_start = chrono::high_resolution_clock::now();
                evaluator.add_inplace(encrypted1, encrypted1);
                evaluator.add_inplace(encrypted2, encrypted2);
                evaluator.add_inplace(encrypted1, encrypted2);
                time_end = chrono::high_resolution_clock::now();
                time_add_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start) / 3;

                /*
                [Multiply]
                We multiply two ciphertexts of size 2. Since the size of the result
                will be 3, and will overwrite the first argument, we reserve first
                enough memory to avoid reallocating during multiplication.
                */
                encrypted1.reserve(3);
                time_start = chrono::high_resolution_clock::now();
                evaluator.multiply_inplace(encrypted1, encrypted2);
                time_end = chrono::high_resolution_clock::now();
                time_multiply_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Multiply Plain]
                We multiply a ciphertext of size 2 with a random plaintext. Recall
                that multiply_plain does not change the size of the ciphertext so we
                use encrypted2 here, which still has size 2.
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.multiply_plain_inplace(encrypted2, plain);
                time_end = chrono::high_resolution_clock::now();
                time_multiply_plain_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Square]
                We continue to use the size 2 ciphertext encrypted2. Now we square
                it; this should be faster than generic homomorphic multiplication.
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.square_inplace(encrypted2);
                time_end = chrono::high_resolution_clock::now();
                time_square_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Relinearize]
                Time to get back to encrypted1; at this point it still has size 3.
                We now relinearize it back to size 2. Since the allocation is
                currently big enough to contain a ciphertext of size 3, no costly
                reallocations are needed in the process.
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.relinearize_inplace(encrypted1, relin_keys);
                time_end = chrono::high_resolution_clock::now();
                time_relinearize_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Rotate Rows One Step]
                We rotate matrix rows by one step left and measure the time.
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.rotate_rows_inplace(encrypted, 1, gal_keys);
                evaluator.rotate_rows_inplace(encrypted, -1, gal_keys);
                time_end = chrono::high_resolution_clock::now();
                time_rotate_rows_one_step_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start) / 2;

                /*
                [Rotate Rows Random]
                We rotate matrix rows by a random number of steps. This is more
                expensive than rotating by just one step.
                */
                size_t row_size = batch_encoder.slot_count() / 2;
                int random_rotation = static_cast<int>(rd() % row_size);
                time_start = chrono::high_resolution_clock::now();
                evaluator.rotate_rows_inplace(encrypted, random_rotation, gal_keys);
                time_end = chrono::high_resolution_clock::now();
                time_rotate_rows_random_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Rotate Columns]
                Nothing surprising here.
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.rotate_columns_inplace(encrypted, gal_keys);
                time_end = chrono::high_resolution_clock::now();
                time_rotate_columns_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                Print a dot to indicate progress.
                */
                cout << ".";
                cout.flush();
            }

            cout << " Done" << endl << endl;
            cout.flush();

            auto avg_batch = time_batch_sum.count() / count;
            auto avg_unbatch = time_unbatch_sum.count() / count;
            auto avg_encrypt = time_encrypt_sum.count() / count;
            auto avg_decrypt = time_decrypt_sum.count() / count;
            auto avg_add = time_add_sum.count() / count;
            auto avg_multiply = time_multiply_sum.count() / count;
            auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
            auto avg_square = time_square_sum.count() / count;
            auto avg_relinearize = time_relinearize_sum.count() / count;
            auto avg_rotate_rows_one_step = time_rotate_rows_one_step_sum.count() / count;
            auto avg_rotate_rows_random = time_rotate_rows_random_sum.count() / count;
            auto avg_rotate_columns = time_rotate_columns_sum.count() / count;

            cout << "Average batch: " << avg_batch << " microseconds" << endl;
            cout << "Average unbatch: " << avg_unbatch << " microseconds" << endl;
            cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
            cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
            cout << "Average add: " << avg_add << " microseconds" << endl;
            cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
            cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
            cout << "Average square: " << avg_square << " microseconds" << endl;
            cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
            cout << "Average rotate rows one step: " << avg_rotate_rows_one_step << " microseconds" << endl;
            cout << "Average rotate rows random: " << avg_rotate_rows_random << " microseconds" << endl;
            cout << "Average rotate columns: " << avg_rotate_columns << " microseconds" << endl;
            cout.flush();
        };

        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(4096);
        parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));
        parms.set_plain_modulus(786433);
        performance_test(SEALContext::Create(parms));

        cout << endl;
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
        parms.set_plain_modulus(786433);
        performance_test(SEALContext::Create(parms));

        cout << endl;
        parms.set_poly_modulus_degree(16384);
        parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(16384));
        parms.set_plain_modulus(786433);
        performance_test(SEALContext::Create(parms));

        /*
        Comment out the following to run the biggest example.
        */
        // cout << endl;
        // parms.set_poly_modulus_degree(32768);
        // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(32768));
        // parms.set_plain_modulus(786433);
        // performance_test(SEALContext::Create(parms));
    }

    void Performance::run_ckks_performance_test() {

        /*
        In this example we time all the basic operations. We use the following
        lambda function to run the test. This is largely similar to the function
        in the previous example.
        */
        auto performance_test = [](auto context) {
            chrono::high_resolution_clock::time_point time_start, time_end;

            print_parameters(context);
            auto &curr_parms = context->context_data()->parms();
            size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

            cout << "Generating secret/public keys: ";
            KeyGenerator keygen(context);
            cout << "Done" << endl;

            auto secret_key = keygen.secret_key();
            auto public_key = keygen.public_key();

            int dbc = DefaultParams::dbc_max();
            cout << "Generating relinearization keys (dbc = " << dbc << "): ";
            time_start = chrono::high_resolution_clock::now();
            auto relin_keys = keygen.relin_keys(dbc);
            time_end = chrono::high_resolution_clock::now();
            auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            cout << "Done [" << time_diff.count() << " microseconds]" << endl;

            if (!context->context_data()->qualifiers().using_batching) {
                cout << "Given encryption parameters do not support batching." << endl;
                return;
            }
            cout << "Generating Galois keys (dbc = " << dbc << "): ";
            time_start = chrono::high_resolution_clock::now();
            auto gal_keys = keygen.galois_keys(dbc);
            time_end = chrono::high_resolution_clock::now();
            time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            cout << "Done [" << time_diff.count() << " microseconds]" << endl;

            Encryptor encryptor(context, public_key);
            Decryptor decryptor(context, secret_key);
            Evaluator evaluator(context);
            CKKSEncoder ckks_encoder(context);

            chrono::microseconds time_encode_sum(0);
            chrono::microseconds time_decode_sum(0);
            chrono::microseconds time_encrypt_sum(0);
            chrono::microseconds time_decrypt_sum(0);
            chrono::microseconds time_add_sum(0);
            chrono::microseconds time_multiply_sum(0);
            chrono::microseconds time_multiply_plain_sum(0);
            chrono::microseconds time_square_sum(0);
            chrono::microseconds time_relinearize_sum(0);
            chrono::microseconds time_rescale_sum(0);
            chrono::microseconds time_rotate_one_step_sum(0);
            chrono::microseconds time_rotate_random_sum(0);
            chrono::microseconds time_conjugate_sum(0);

            /*
            How many times to run the test?
            */
            int count = 10;

            /*
            Populate a vector of floating-point values to batch.
            */
            vector<double> pod_vector;
            random_device rd;
            for (size_t i = 0; i < ckks_encoder.slot_count(); i++) {
                pod_vector.push_back(1.001 * static_cast<double>(i));
            }

            cout << "Running tests ";
            for (int i = 0; i < count; i++) {
                /*
                [Encoding]
                */
                Plaintext plain(curr_parms.poly_modulus_degree() *
                                curr_parms.coeff_modulus().size(), 0);
                time_start = chrono::high_resolution_clock::now();
                ckks_encoder.encode(pod_vector,
                                    static_cast<double>(curr_parms.coeff_modulus().back().value()), plain);
                time_end = chrono::high_resolution_clock::now();
                time_encode_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Decoding]
                */
                vector<double> pod_vector2(ckks_encoder.slot_count());
                time_start = chrono::high_resolution_clock::now();
                ckks_encoder.decode(plain, pod_vector2);
                time_end = chrono::high_resolution_clock::now();
                time_decode_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Encryption]
                */
                Ciphertext encrypted(context);
                time_start = chrono::high_resolution_clock::now();
                encryptor.encrypt(plain, encrypted);
                time_end = chrono::high_resolution_clock::now();
                time_encrypt_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Decryption]
                */
                Plaintext plain2(poly_modulus_degree, 0);
                time_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(encrypted, plain2);
                time_end = chrono::high_resolution_clock::now();
                time_decrypt_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Add]
                */
                Ciphertext encrypted1(context);
                ckks_encoder.encode(i + 1, plain);
                encryptor.encrypt(plain, encrypted1);
                Ciphertext encrypted2(context);
                ckks_encoder.encode(i + 1, plain2);
                encryptor.encrypt(plain2, encrypted2);
                time_start = chrono::high_resolution_clock::now();
                evaluator.add_inplace(encrypted1, encrypted1);
                evaluator.add_inplace(encrypted2, encrypted2);
                evaluator.add_inplace(encrypted1, encrypted2);
                time_end = chrono::high_resolution_clock::now();
                time_add_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start) / 3;

                /*
                [Multiply]
                */
                encrypted1.reserve(3);
                time_start = chrono::high_resolution_clock::now();
                evaluator.multiply_inplace(encrypted1, encrypted2);
                time_end = chrono::high_resolution_clock::now();
                time_multiply_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Multiply Plain]
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.multiply_plain_inplace(encrypted2, plain);
                time_end = chrono::high_resolution_clock::now();
                time_multiply_plain_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Square]
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.square_inplace(encrypted2);
                time_end = chrono::high_resolution_clock::now();
                time_square_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Relinearize]
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.relinearize_inplace(encrypted1, relin_keys);
                time_end = chrono::high_resolution_clock::now();
                time_relinearize_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Rescale]
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.rescale_to_next_inplace(encrypted1);
                time_end = chrono::high_resolution_clock::now();
                time_rescale_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Rotate Vector]
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.rotate_vector_inplace(encrypted, 1, gal_keys);
                evaluator.rotate_vector_inplace(encrypted, -1, gal_keys);
                time_end = chrono::high_resolution_clock::now();
                time_rotate_one_step_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start) / 2;

                /*
                [Rotate Vector Random]
                */
                int random_rotation = static_cast<int>(rd() % ckks_encoder.slot_count());
                time_start = chrono::high_resolution_clock::now();
                evaluator.rotate_vector_inplace(encrypted, random_rotation, gal_keys);
                time_end = chrono::high_resolution_clock::now();
                time_rotate_random_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                [Complex Conjugate]
                */
                time_start = chrono::high_resolution_clock::now();
                evaluator.complex_conjugate_inplace(encrypted, gal_keys);
                time_end = chrono::high_resolution_clock::now();
                time_conjugate_sum += chrono::duration_cast<
                        chrono::microseconds>(time_end - time_start);

                /*
                Print a dot to indicate progress.
                */
                cout << ".";
                cout.flush();
            }

            cout << " Done" << endl << endl;
            cout.flush();

            auto avg_encode = time_encode_sum.count() / count;
            auto avg_decode = time_decode_sum.count() / count;
            auto avg_encrypt = time_encrypt_sum.count() / count;
            auto avg_decrypt = time_decrypt_sum.count() / count;
            auto avg_add = time_add_sum.count() / count;
            auto avg_multiply = time_multiply_sum.count() / count;
            auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
            auto avg_square = time_square_sum.count() / count;
            auto avg_relinearize = time_relinearize_sum.count() / count;
            auto avg_rescale = time_rescale_sum.count() / count;
            auto avg_rotate_one_step = time_rotate_one_step_sum.count() / count;
            auto avg_rotate_random = time_rotate_random_sum.count() / count;
            auto avg_conjugate = time_conjugate_sum.count() / count;

            cout << "Average encode: " << avg_encode << " microseconds" << endl;
            cout << "Average decode: " << avg_decode << " microseconds" << endl;
            cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
            cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
            cout << "Average add: " << avg_add << " microseconds" << endl;
            cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
            cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
            cout << "Average square: " << avg_square << " microseconds" << endl;
            cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
            cout << "Average rescale: " << avg_rescale << " microseconds" << endl;
            cout << "Average rotate vector one step: " << avg_rotate_one_step << " microseconds" << endl;
            cout << "Average rotate vector random: " << avg_rotate_random << " microseconds" << endl;
            cout << "Average complex conjugate: " << avg_conjugate << " microseconds" << endl;
            cout.flush();
        };

        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(4096);
        parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));
        performance_test(SEALContext::Create(parms));

        cout << endl;
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
        performance_test(SEALContext::Create(parms));

        cout << endl;
        parms.set_poly_modulus_degree(16384);
        parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(16384));
        performance_test(SEALContext::Create(parms));

        /*
        Comment out the following to run the biggest example.
        */
        // cout << endl;
        // parms.set_poly_modulus_degree(32768);
        // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(32768));
        // performance_test(SEALContext::Create(parms));

    }
}