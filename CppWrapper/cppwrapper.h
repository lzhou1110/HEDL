#ifndef CPPWRAPPER_H
#define CPPWRAPPER_H

#include <cmath>

using namespace std;
using namespace seal;

namespace wrapper {
    class Wrapper {
        public:
            // constructor & destructor
            Wrapper();
            Wrapper(string scheme, int security_level, int poly_modulus_degree, int coeff_modulus, int plain_modulus);
            ~Wrapper();

            // methods
            void clear_all_stored_pointers();
            void print_seal_version();
            void print_parameters();
            void print_allocated_memory();
            string plaintext_to_string(uintptr_t plaintext_pointer);

            // integer encoder
            void init_integer_encoder();
            uintptr_t integer_encoder(int integer);
            int64_t integer_decoder(uintptr_t plaintext_pointer);


//            void encode(double value)
//            void encrypt(Plaintext plain)
//            void decode(Ciphertext cipher)


        private:
            // members
            map<uintptr_t, Plaintext*> plaintext_map;
            shared_ptr<SEALContext> context;
            IntegerEncoder*integerEncoder;
            Encryptor*encryptor;
            Evaluator*evaluator;
            Decryptor*decryptor;

            // methods
            Plaintext get_plaintext(uintptr_t plaintext_pointer);
            Ciphertext get_ciphertext(uintptr_t plaintext_pointer);
    };
}

#endif