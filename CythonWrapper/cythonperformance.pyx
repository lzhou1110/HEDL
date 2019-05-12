# distutils: language = c++
from cppperformance cimport Performance

cdef class CythonPerformance:
    cdef Performance performance

    def __cinit__(self):
        self.performance = Performance()

    # performance_test
    def run_bfv_performance_test(self):
        self.performance.run_bfv_performance_test()

    def run_ckks_performance_test(self):
        self.performance.run_ckks_performance_test()
