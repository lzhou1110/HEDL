# distutils: language = c++
from libcpp.string cimport string
from libc.stdint cimport uintptr_t
from cppwrapper cimport Wrapper


cdef class CythonWrapper:
    cdef Wrapper wrapper

    def __cinit__(self, string scheme, int security_level, int poly_modulus_degree, int coeff_modulus,
                  int plain_modulus):
        self.wrapper = Wrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)

    def print_seal_version(self):
        self.wrapper.print_seal_version()

    def print_parameters(self):
        self.wrapper.print_parameters()

    def print_allocated_memory(self):
        self.wrapper.print_allocated_memory()

    def plaintext_to_string(self, uintptr_t plaintext_pointer):
        return self.wrapper.plaintext_to_string(plaintext_pointer)

    def init_integer_encoder(self):
        self.wrapper.init_integer_encoder()

    def integer_encoder(self, int integer):
        return self.wrapper.integer_encoder(integer)

    def integer_decoder(self, int plaintext_pointer):
        return self.wrapper.integer_decoder(plaintext_pointer)