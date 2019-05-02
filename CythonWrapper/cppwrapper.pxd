from libcpp.string cimport string
from libc.stdint cimport int64_t
from libc.stdint cimport uintptr_t

cdef extern from "cppwrapper.cpp":
    pass

# Declare the class with cdef
cdef extern from "cppwrapper.h" namespace "wrapper":
    cdef cppclass Wrapper:

        # constructor & destructor
        Wrapper() except +
        Wrapper(string scheme, int security_level, int poly_modulus_degree, int coeff_modulus,
                int plain_modulus) except +

        # methods
        void print_seal_version()
        void print_parameters()
        void print_allocated_memory()
        string plaintext_to_string(uintptr_t plaintext_pointer);

        # integer encoder
        void init_integer_encoder()
        uintptr_t integer_encoder(int integer)
        int64_t integer_decoder(uintptr_t plaintext_pointer)

