#ifndef TOPICS_H
#define TOPICS_H

#include <string>
#include <vector>

const std::string COMPUTE_PREFIX = "compute";
const std::string RESULT_PREFIX = "result";

const std::string C_KREYVIUM = "kreyvium";
const std::string C_KREYVIUM12 = "kreyvium12";
const std::string C_KREYVIUM13 = "kreyvium13";
const std::string C_AGRASTA = "agrasta";
const std::string C_FILIP1280 = "filip1280";
const std::string C_LOWMC = "lowmc";
const std::string C_RASTA5 = "rasta5";
const std::string C_RASTA6 = "rasta6";

const std::string B_SEAL = "seal";
const std::string B_HELIB = "helib";
const std::string B_TFHE = "tfhe";

inline std::string make_topic(const std::string &base, const std::string &cipher, const std::string &backend)
{
    return base + "/" + cipher + "/" + backend;
}

const std::string KREYVIUM_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM, B_SEAL);
const std::string KREYVIUM_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM, B_HELIB);
const std::string KREYVIUM_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM, B_TFHE);
const std::string KREYVIUM12_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM12, B_SEAL);
const std::string KREYVIUM12_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM12, B_TFHE);
const std::string KREYVIUM12_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM12, B_HELIB);
const std::string KREYVIUM13_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM13, B_SEAL);
const std::string KREYVIUM13_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM13, B_HELIB);
const std::string KREYVIUM13_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_KREYVIUM13, B_TFHE);
const std::string AGRASTA_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_AGRASTA, B_SEAL);
const std::string AGRASTA_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_AGRASTA, B_HELIB);
const std::string AGRASTA_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_AGRASTA, B_TFHE);
const std::string FILIP1280_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_FILIP1280, B_SEAL);
const std::string FILIP1280_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_FILIP1280, B_HELIB);
const std::string FILIP1280_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_FILIP1280, B_TFHE);
const std::string LOWMC_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_LOWMC, B_SEAL);
const std::string LOWMC_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_LOWMC, B_HELIB);
const std::string LOWMC_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_LOWMC, B_TFHE);
const std::string RASTA5_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_RASTA5, B_SEAL);
const std::string RASTA5_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_RASTA5, B_HELIB);
const std::string RASTA5_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_RASTA5, B_TFHE);
const std::string RASTA6_SEAL_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_RASTA6, B_SEAL);
const std::string RASTA6_HELIB_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_RASTA6, B_HELIB);
const std::string RASTA6_TFHE_COMPUTE_TOPIC = make_topic(COMPUTE_PREFIX, C_RASTA6, B_TFHE);

const std::string KREYVIUM_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM, B_SEAL);
const std::string KREYVIUM_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM, B_HELIB);
const std::string KREYVIUM_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM, B_TFHE);
const std::string KREYVIUM12_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM12, B_SEAL);
const std::string KREYVIUM12_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM12, B_TFHE);
const std::string KREYVIUM12_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM12, B_HELIB);
const std::string KREYVIUM13_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM13, B_SEAL);
const std::string KREYVIUM13_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM13, B_HELIB);
const std::string KREYVIUM13_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_KREYVIUM13, B_TFHE);
const std::string AGRASTA_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_AGRASTA, B_SEAL);
const std::string AGRASTA_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_AGRASTA, B_HELIB);
const std::string AGRASTA_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_AGRASTA, B_TFHE);
const std::string FILIP1280_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_FILIP1280, B_SEAL);
const std::string FILIP1280_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_FILIP1280, B_HELIB);
const std::string FILIP1280_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_FILIP1280, B_TFHE);
const std::string LOWMC_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_LOWMC, B_SEAL);
const std::string LOWMC_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_LOWMC, B_HELIB);
const std::string LOWMC_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_LOWMC, B_TFHE);
const std::string RASTA5_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_RASTA5, B_SEAL);
const std::string RASTA5_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_RASTA5, B_HELIB);
const std::string RASTA5_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_RASTA5, B_TFHE);
const std::string RASTA6_SEAL_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_RASTA6, B_SEAL);
const std::string RASTA6_HELIB_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_RASTA6, B_HELIB);
const std::string RASTA6_TFHE_RESULT_TOPIC = make_topic(RESULT_PREFIX, C_RASTA6, B_TFHE);

#endif
