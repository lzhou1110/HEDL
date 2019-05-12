
cdef extern from "cppperformance.cpp":
    pass

# Declare the class with cdef
cdef extern from "cppperformance.h" namespace "performance":
    cdef cppclass Performance:

        # constructors
        Performance() except +

        # performance_test
        void run_bfv_performance_test() except +
        void run_ckks_performance_test() except +