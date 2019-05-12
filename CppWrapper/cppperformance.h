#ifndef CPPPERFORMANCE_H
#define CPPPERFORMANCE_H

#include <cmath>

using namespace std;
using namespace seal;

namespace performance {
    class Performance {
        public:
            /* Constructor & Destructor */
            Performance();
            ~Performance();

            /* Methods */
            void run_bfv_performance_test();
            void run_ckks_performance_test();
    };
}

#endif