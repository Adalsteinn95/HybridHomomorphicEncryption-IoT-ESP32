cmake_minimum_required(VERSION 3.10)
project(fhe_mqtt_demo C CXX)
set(CMAKE_CXX_STANDARD 17)

# -----------------------------------------------------------------------------
# Find Required Libraries (Installed by Dockerfile to standard paths)
# -----------------------------------------------------------------------------
find_package(PahoMqttCpp REQUIRED)
message(STATUS "Found PahoMqttCpp version ${PahoMqttCpp_VERSION}")

find_package(SEAL REQUIRED)
message(STATUS "Found SEAL version ${SEAL_VERSION}") # SEAL::seal_shared target available

# --- Find HElib Manually ---
find_path(HELIB_INCLUDE_DIRS NAMES helib/helib.h HINTS /usr/local/include REQUIRED)
find_library(HELIB_LIBRARIES NAMES helib HINTS /usr/local/lib REQUIRED)
if(HELIB_INCLUDE_DIRS AND HELIB_LIBRARIES)
    message(STATUS "Found HElib include (manually): ${HELIB_INCLUDE_DIRS}")
    message(STATUS "Found HElib library (manually): ${HELIB_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find HElib headers or libraries manually.")
endif()

# --- Find NTL Manually (Installed from source to /usr/local by Dockerfile) ---
find_path(NTL_INCLUDE_DIRS NAMES NTL/ZZ.h HINTS /usr/local/include /usr/include REQUIRED)
find_library(NTL_LIBRARIES NAMES ntl HINTS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu REQUIRED)
if(NTL_INCLUDE_DIRS AND NTL_LIBRARIES)
    message(STATUS "Found NTL include (manually): ${NTL_INCLUDE_DIRS}")
    message(STATUS "Found NTL library (manually): ${NTL_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find NTL headers or libraries manually.")
endif()

# --- Find GMP Manually (Installed by apt-get to /usr) ---
find_path(GMP_INCLUDE_DIRS NAMES gmp.h HINTS /usr/include /usr/include/x86_64-linux-gnu REQUIRED)
find_library(GMP_LIBRARIES NAMES gmp HINTS /usr/lib /usr/lib/x86_64-linux-gnu REQUIRED)
if(GMP_INCLUDE_DIRS AND GMP_LIBRARIES)
    message(STATUS "Found GMP include (manually): ${GMP_INCLUDE_DIRS}")
    message(STATUS "Found GMP library (manually): ${GMP_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find GMP headers or libraries manually.")
endif()

# --- Find TFHE Manually (Installed from source to /usr/local by Dockerfile) ---
find_path(TFHE_INCLUDE_DIRS NAMES tfhe/tfhe.h HINTS /usr/local/include REQUIRED)
find_library(TFHE_LIBRARIES NAMES tfhe-spqlios-fma tfhe-spqlios-avx tfhe-fftw HINTS /usr/local/lib REQUIRED)
if(TFHE_INCLUDE_DIRS AND TFHE_LIBRARIES)
    message(STATUS "Found TFHE include (manually): ${TFHE_INCLUDE_DIRS}")
    message(STATUS "Found TFHE library (manually): ${TFHE_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find TFHE headers or libraries manually.")
endif()

# --- Find FFTW Manually (Installed by apt-get to /usr) ---
find_path(FFTW_INCLUDE_DIRS NAMES fftw3.h HINTS /usr/include /usr/include/x86_64-linux-gnu REQUIRED)
find_library(FFTW_LIBRARIES NAMES fftw3 HINTS /usr/lib /usr/lib/x86_64-linux-gnu REQUIRED)
if(FFTW_INCLUDE_DIRS AND FFTW_LIBRARIES)
    message(STATUS "Found FFTW include (manually): ${FFTW_INCLUDE_DIRS}")
    message(STATUS "Found FFTW library (manually): ${FFTW_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find FFTW headers or libraries manually.")
endif()   




# -----------------------------------------------------------------------------
# Add executable
# -----------------------------------------------------------------------------
add_executable(mqtt_client
    src/main.cpp
    src/MQTTCallback.cpp
    src/ThreadPool.cpp
    src/Utils.cpp
    src/handlers/KreyviumSealHandler.cpp
    src/handlers/KreyviumHelibHandler.cpp
    src/handlers/KreyviumTfheHandler.cpp
    src/handlers/Kreyvium12SealHandler.cpp
    src/handlers/Kreyvium12TfheHandler.cpp
    src/handlers/Kreyvium12HelibHandler.cpp
    src/handlers/Kreyvium13SealHandler.cpp
    src/handlers/Kreyvium13HelibHandler.cpp
    src/handlers/Kreyvium13TfheHandler.cpp
    src/handlers/AgrastaSealHandler.cpp
    src/handlers/AgrastaHelibHandler.cpp
    src/handlers/AgrastaTFHEHandler.cpp
    src/handlers/Filip1280SealHandler.cpp
    src/handlers/Filip1280HelibHandler.cpp
    src/handlers/Filip1280TfheHandler.cpp
    src/handlers/LowmcSealHandler.cpp
    src/handlers/LowmcHelibHandler.cpp
    src/handlers/LowmcTFHEHandler.cpp
    src/handlers/Rasta5SealHandler.cpp
    src/handlers/Rasta5HelibHandler.cpp
    src/handlers/Rasta5TfheHandler.cpp
    src/handlers/Rasta6SealHandler.cpp
    src/handlers/Rasta6HelibHandler.cpp
    src/handlers/Rasta6TfheHandler.cpp
    src/ciphers/TFHE_Cipher.cpp
    src/ciphers/HElib_Cipher.cpp
    src/ciphers/kreyvium_plain.cpp
    src/ciphers/kreyvium_seal.cpp
    src/ciphers/kreyvium_12_plain.cpp
    src/ciphers/kreyvium_12_seal.cpp
    src/ciphers/kreyvium_12_helib.cpp
    src/ciphers/agrasta_plain.cpp
    src/ciphers/agrasta_seal.cpp
    src/ciphers/agrasta_helib.cpp
    src/ciphers/agrasta_tfhe.cpp
    src/ciphers/SEAL_Cipher.cpp
    src/ciphers/filip_1280_helib.cpp
    src/ciphers/filip_1280_seal.cpp
    src/ciphers/filip_1280_tfhe.cpp
    src/ciphers/kreyvium_12_tfhe.cpp
    src/ciphers/kreyvium_13_helib.cpp
    src/ciphers/kreyvium_13_plain.cpp
    src/ciphers/kreyvium_13_seal.cpp
    src/ciphers/kreyvium_13_tfhe.cpp
    src/ciphers/kreyvium_helib.cpp
    src/ciphers/kreyvium_tfhe.cpp
    src/ciphers/lowmc_helib.cpp
    src/ciphers/lowmc_plain.cpp
    src/ciphers/lowmc_seal.cpp
    src/ciphers/lowmc_tfhe.cpp
    src/ciphers/rasta_5_helib.cpp
    src/ciphers/rasta_5_plain.cpp
    src/ciphers/rasta_5_seal.cpp
    src/ciphers/rasta_5_tfhe.cpp
    src/ciphers/rasta_6_helib.cpp
    src/ciphers/rasta_6_plain.cpp
    src/ciphers/rasta_6_seal.cpp
    src/ciphers/rasta_6_tfhe.cpp
    src/ciphers/filip_1280_plain.cpp
    util/aes/aes.cpp          
    util/aes/block.cpp        
)

# -----------------------------------------------------------------------------
# Add Include Directories (Target Specific)
# -----------------------------------------------------------------------------
target_include_directories(mqtt_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ciphers
    ${CMAKE_CURRENT_SOURCE_DIR}/include/handlers
    util
    ${NTL_INCLUDE_DIRS}   # Add manually found NTL include path
    ${GMP_INCLUDE_DIRS}   # Add manually found GMP include path
    ${TFHE_INCLUDE_DIRS}  # Add manually found TFHE include path
    ${FFTW_INCLUDE_DIRS}  # Manually found
    # Includes for Paho, SEAL, HElib, M4RI, FFTW should come from targets
)

# -----------------------------------------------------------------------------
# Link Libraries (Target Specific)
# -----------------------------------------------------------------------------
target_link_libraries(mqtt_client PRIVATE
    PahoMqttCpp::paho-mqttpp3
    SEAL::seal_shared
    ${HELIB_LIBRARIES}         # Link the manually found HElib library file
    ${NTL_LIBRARIES}          # Link the manually found NTL library file
    ${GMP_LIBRARIES}          # Link the manually found GMP library file
    ${TFHE_LIBRARIES}         # Link the manually found TFHE library file
    ${M4RI_TARGET_LINK}       # Link M4RI target (found or manually created)
    ${FFTW_LIBRARIES}         # Manually found
    Threads::Threads          # Link pthreads
    # OpenFHE::openfhe
)

# -----------------------------------------------------------------------------
# Compile Options / Flags
# -----------------------------------------------------------------------------
target_compile_options(mqtt_client PRIVATE
    -march=native
)