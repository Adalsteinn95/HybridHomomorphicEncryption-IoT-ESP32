#include "TFHE_Cipher.h"

#include <iostream>

TFHECiphertextVec::TFHECiphertextVec() : ct(nullptr), num(0), params(nullptr) {}

TFHECiphertextVec::TFHECiphertextVec(int size,
                                     TFheGateBootstrappingParameterSet *params)
    : num(size), params(params)
{
  ct = new_gate_bootstrapping_ciphertext_array(size, params);
}

TFHECiphertextVec::TFHECiphertextVec(const TFHECiphertextVec &other)
    : ct(nullptr)
{
  *this = other;
}

TFHECiphertextVec &TFHECiphertextVec::operator=(
    const TFHECiphertextVec &other)
{
  if (this == &other)
    return *this;

  if (!ct || params != other.params || num != other.num)
    init(other.num, other.params);
  auto param = other.params->in_out_params;
  for (int i = 0; i < num; i++)
    lweCopy(&ct[i], &(other.ct[i]), param);
  return *this;
}

void TFHECiphertextVec::init(int size,
                             TFheGateBootstrappingParameterSet *param)
{
  if (ct)
    delete_gate_bootstrapping_ciphertext_array(this->num, ct);
  this->num = size;
  this->params = param;
  ct = new_gate_bootstrapping_ciphertext_array(size, param);
}

TFHECiphertextVec::~TFHECiphertextVec()
{
  if (ct)
    delete_gate_bootstrapping_ciphertext_array(num, ct);
}

LweSample &TFHECiphertextVec::operator[](int i) { return ct[i]; }

const LweSample &TFHECiphertextVec::operator[](int i) const { return ct[i]; }

TFHECiphertext::TFHECiphertext() : ct(nullptr), params(nullptr) {}

TFHECiphertext::TFHECiphertext(TFheGateBootstrappingParameterSet *params)
    : params(params)
{
  ct = new_gate_bootstrapping_ciphertext(params);
}

TFHECiphertext::~TFHECiphertext()
{
  if (ct)
    delete_gate_bootstrapping_ciphertext(ct);
}

void TFHECiphertext::init(TFheGateBootstrappingParameterSet *param)
{
  if (ct)
    delete_gate_bootstrapping_ciphertext(ct);
  this->params = param;
  ct = new_gate_bootstrapping_ciphertext(param);
}

TFHECiphertext::TFHECiphertext(const TFHECiphertext &other) : ct(nullptr)
{
  *this = other;
}

TFHECiphertext &TFHECiphertext::operator=(const TFHECiphertext &other)
{
  if (this == &other)
    return *this;

  if (!ct || params != other.params)
    init(other.params);
  lweCopy(ct, other, other.params->in_out_params);
  return *this;
}

TFHECiphertext &TFHECiphertext::operator=(const LweSample &other)
{
  if (!ct || !params)
    throw std::runtime_error("operator=: LHS not initiliazed");

  lweCopy(ct, &other, params->in_out_params);
  return *this;
}

TFHECipher::TFHECipher(BlockCipherParams params,
                       std::vector<uint8_t> secret_key, int seclevel)
    : secret_key(secret_key), params(params)
{
  context = new_default_gate_bootstrapping_parameters(seclevel);
  he_sk = new_random_gate_bootstrapping_secret_keyset(context);
  he_pk = &he_sk->cloud;
}

TFHECipher::~TFHECipher()
{
  delete_gate_bootstrapping_secret_keyset(he_sk);
  delete_gate_bootstrapping_parameters(context);
}

void TFHECipher::halfAdder(e_bit &c_out, e_bit &s, const e_bit &a,
                           const e_bit &b)
{
  bootsAND(&c_out, &a, &b, he_pk);
  bootsXOR(&s, &a, &b, he_pk);
}

void TFHECipher::fullAdder(e_bit &c_out, e_bit &s, const e_bit &a,
                           const e_bit &b, const e_bit &c_in)
{
  TFHECiphertext tmp_a(context), tmp_b(context), tmp_c(context);
  bootsXOR(tmp_a, &a, &c_in, he_pk);
  bootsXOR(tmp_b, &b, &c_in, he_pk);
  bootsAND(tmp_c, tmp_a, tmp_b, he_pk);
  bootsXOR(tmp_c, tmp_c, &c_in, he_pk);

  bootsXOR(&s, &a, &b, he_pk);
  bootsXOR(&s, &s, &c_in, he_pk);

  lweCopy(&c_out, tmp_c, he_pk->params->in_out_params);
}

void TFHECipher::rippleCarryAdder(e_int &s, const e_int &a, const e_int &b)
{
  size_t n = a.size();
  if (s.size() != n)
    s.init(n, context);
  TFHECiphertext c(context);
  halfAdder(c, s[0], a[0], b[0]);
  for (size_t i = 1; i < n - 1; i++)
    fullAdder(c, s[i], a[i], b[i], c);

  bootsXOR(&s[n - 1], &a[n - 1], &b[n - 1], he_pk);
  bootsXOR(&s[n - 1], &s[n - 1], c, he_pk);
}

void TFHECipher::encrypt(e_int &out, uint16_t in)
{
  size_t bitsize = sizeof(in) * 8;
  out.init(bitsize, context);
  for (size_t i = 0; i < bitsize; i++)
  {
    uint8_t bit = (in >> i) & 1;
    bootsSymEncrypt(&out[i], bit, he_sk);
  }
}

void TFHECipher::encrypt(e_int &out, uint64_t in, size_t bitsize)
{
  out.init(bitsize, context);
  for (size_t i = 0; i < bitsize; i++)
  {
    uint8_t bit = (in >> i) & 1;
    bootsSymEncrypt(&out[i], bit, he_sk);
  }
}

void TFHECipher::decrypt(e_int &in, uint16_t &out)
{
  out = 0;
  size_t bitsize = std::min(sizeof(out) * 8, in.size());
  for (size_t i = 0; i < bitsize; i++)
  {
    uint8_t bit = bootsSymDecrypt(&in[i], he_sk) & 0xFF;
    out |= (bit << i);
  }
}

void TFHECipher::decrypt(e_int &in, uint64_t &out)
{
  out = 0;
  size_t bitsize = std::min(sizeof(out) * 8, in.size());
  for (size_t i = 0; i < bitsize; i++)
  {
    uint8_t bit = bootsSymDecrypt(&in[i], he_sk) & 0xFF;
    out |= (bit << i);
  }
}

void TFHECipher::decode(e_vector &out, TFHECiphertextVec encoded,
                        size_t bitsize)
{
  size_t size = encoded.size() / bitsize;
  if (out.size() != size)
    out.resize(size);

  for (size_t i = 0; i < size; i++)
  {
    out[i].init(bitsize, context);
    for (size_t k = 0; k < bitsize; k++)
    {
      lweCopy(&out[i][k], &encoded[i * bitsize + k],
              he_pk->params->in_out_params);
    }
  }
}

// n x n = n bit multiplier
void TFHECipher::multiply(e_int &s, const e_int &a, const e_int &b)
{
  size_t n = a.size();

  std::vector<e_int> tree(n);
  for (size_t i = 0; i < n; i++)
  {
    if (tree[i].size() != n - 1)
      tree[i].init(n - i, context);
    for (size_t j = 0; j < n - i; j++)
    {
      bootsAND(&tree[i][j], &a[j], &b[i], he_pk);
    }
  }

  treeAddMul(tree);
  s = tree[0];
}

void TFHECipher::treeAddMul(std::vector<e_int> &tree)
{
  auto len = tree.size();

  // tree add
  while (len != 1)
  {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++)
    {
      size_t len1 = tree[2 * i].size();
      size_t len2 = tree[2 * i + 1].size();
      size_t diff = len1 - len2;
      TFHECiphertext c(context);
      if (tree[i].size() != len1)
        tree[i].init(len1, context);
      if (i != 0)
      {
        for (size_t j = 0; j < diff; j++)
          lweCopy(&tree[i][j], &tree[2 * i][j], he_pk->params->in_out_params);
      }
      halfAdder(c, tree[i][diff], tree[2 * i][diff], tree[2 * i + 1][0]);
      for (size_t j = diff + 1; j < len1 - 1; j++)
        fullAdder(c, tree[i][j], tree[2 * i][j], tree[2 * i + 1][j - diff], c);
      if (diff + 1 < len1)
      {
        // already did that
        bootsXOR(&tree[i][len1 - 1], &tree[2 * i][len1 - 1],
                 &tree[2 * i + 1][len1 - 1 - diff], he_pk);
        bootsXOR(&tree[i][len1 - 1], &tree[i][len1 - 1], c, he_pk);
      }
    }
    if (len % 2)
    {
      tree[new_len] = tree[len - 1];
      new_len++;
    }
    len = new_len;
  }
}

void TFHECipher::treeAdd(std::vector<e_int> &tree)
{
  auto len = tree.size();

  // tree add
  while (len != 1)
  {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++)
    {

      rippleCarryAdder(tree[i], tree[2 * i], tree[2 * i + 1]);
    }
    if (len % 2)
    {
      tree[new_len] = tree[len - 1];
      new_len++;
    }
    len = new_len;
  }
}

void TFHECipher::multiplyPlain(e_int &s, const e_int &a, const uint64_t b)
{
  size_t n = a.size();

  if (!b)
  {
    s.init(n, context);
    for (size_t i = 0; i < n; i++)
      bootsCONSTANT(&s[i], 0, he_pk);
  }

  std::vector<e_int> tree;
  tree.reserve(n);
  for (size_t i = 0; i < n; i++)
  {
    int32_t bit = (b >> i) & 1;
    if (!bit)
      continue;
    tree.emplace_back(n - i, context);
    for (size_t j = 0; j < n - i; j++)
      lweCopy(&tree.back()[j], &a[j], he_pk->params->in_out_params);
  }

  treeAddMul(tree);
  if (s.size() != n)
    s.init(n, context);

  size_t diff = n - tree[0].size();
  for (size_t i = 0; i < n; i++)
  {
    if (i < diff)
      bootsCONSTANT(&s[i], 0, he_pk);
    else
      lweCopy(&s[i], &tree[0][i - diff], he_pk->params->in_out_params);
  }
}

void TFHECipher::halfAdderPlain(e_bit &c_out, e_bit &s, const e_bit &a,
                                const bool b)
{
  if (b)
  {
    lweCopy(&c_out, &a, he_pk->params->in_out_params);
    bootsNOT(&s, &a, he_pk);
    return;
  }

  bootsCONSTANT(&c_out, 0, he_pk);
  lweCopy(&s, &a, he_pk->params->in_out_params);
}

void TFHECipher::fullAdderPlain(e_bit &c_out, e_bit &s, const e_bit &a,
                                const bool b, const e_bit &c_in)
{
  TFHECiphertext tmp_a(context), tmp_b(context), tmp_c(context);
  if (b)
  {
    bootsNOT(tmp_a, &a, he_pk);
    bootsAND(tmp_c, tmp_a, &c_in, he_pk);
    bootsXOR(tmp_c, tmp_c, &a, he_pk);

    bootsXOR(&s, &a, &c_in, he_pk);
    bootsNOT(&s, &s, he_pk);
  }
  else
  {
    bootsAND(tmp_c, &a, &c_in, he_pk);
    bootsXOR(&s, &a, &c_in, he_pk);
  }
  lweCopy(&c_out, tmp_c, he_pk->params->in_out_params);
}

void TFHECipher::rippleCarryAdderPlain(e_int &s, const e_int &a,
                                       const uint64_t b)
{
  if (!b)
  {
    s = a;
    return;
  }

  size_t n = a.size();
  if (s.size() != n)
    s.init(n, context);
  TFHECiphertext c(context);

  bool bit = b & 1;
  halfAdderPlain(c, s[0], a[0], bit);
  for (size_t i = 1; i < n - 1; i++)
  {
    bit = (b >> i) & 1;
    fullAdderPlain(c, s[i], a[i], bit, c);
  }
  bit = (b >> (n - 1)) & 1;
  bootsXOR(&s[n - 1], &a[n - 1], c, he_pk);
  if (bit)
    bootsNOT(&s[n - 1], &s[n - 1], he_pk);
}

// vo = M * vi
void TFHECipher::matMul(e_vector &vo, const matrix &M, const e_vector &vi)
{
  size_t cols = vi.size();
  size_t rows = M.size();
  if (vo.size() != rows)
    vo.resize(rows);

  for (size_t row = 0; row < rows; row++)
  {
    std::cout << "row " << row << std::endl;
    std::vector<e_int> tree(cols);
    for (size_t col = 0; col < cols; col++)
    {
      multiplyPlain(tree[col], vi[col], M[row][col]);
    }
    treeAdd(tree);
    vo[row] = tree[0];
  }
}

// vo = vi + b
void TFHECipher::vecAdd(e_vector &vo, const e_vector &vi, const vector &b)
{
  size_t rows = vi.size();
  if (vo.size() != rows)
    vo.resize(rows);

  for (size_t row = 0; row < rows; row++)
  {
    rippleCarryAdderPlain(vo[row], vi[row], b[row]);
  }
}

// vo = M * vi + b
void TFHECipher::affine(e_vector &vo, const matrix &M, const e_vector &vi,
                        const vector &b)
{
  matMul(vo, M, vi);
  vecAdd(vo, vo, b);
}

// This code should be part of the TFHECipher.cpp file or a derived class's .cpp file

// Include necessary TFHE headers for low-level LweSample operations
// Note: The exact header might vary slightly based on the TFHE library version/build.
#include <tfhe/lwesamples.h> // For new_LweSample, delete_LweSample, lweCopy
#include <tfhe/tfhe.h>       // For TFheGateBootstrappingParameterSet, bootsCONSTANT

// Helper function to calculate ceil(log2(n))
size_t ceil_log2(size_t n)
{
  if (n == 0)
    return 0;
  return static_cast<size_t>(std::ceil(std::log2(static_cast<double>(n))));
}

TFHECipher::e_int TFHECipher::computeHammingWeight(const TFHECiphertextVec &bits)
{
  const std::size_t n = bits.size();
  if (n == 0)
    throw std::invalid_argument("computeHammingWeight: empty input");

  const std::size_t k = ceil_log2(n);
  const std::size_t COLS = k + 1;

  /* ────────────────── helpers ────────────────── */
  auto new_zero = [this]()
  {
    e_bit *z = new_LweSample(context->in_out_params);
    bootsCONSTANT(z, 0, he_pk);
    return z;
  };

  /* pre-encoded zero (so we can pad and compare safely later) */
  e_bit *enc_zero = new_zero();

  /* ────────────────── column layout ──────────────────
     Each column holds pointers (NOT objects)           */
  std::vector<std::vector<e_bit *>> columns(COLS);

  columns[0].reserve(n);
  for (std::size_t i = 0; i < n; ++i)
    columns[0].push_back(const_cast<e_bit *>(&bits[i])); // read-only use

  /* pad first column to ⟂length ≡ 0 (mod 3) */
  while (columns[0].size() % 3 != 0)
    columns[0].push_back(enc_zero);

  /* ────────────────── CSA compression ────────────────── */
  bool changed;
  do
  {
    changed = false;

    std::vector<std::vector<e_bit *>> next(COLS);
    for (auto &v : next)
      v.reserve((n + 2) / 3); // worst-case shrink factor 3→1

#pragma omp parallel for schedule(dynamic)
    for (std::size_t col = 0; col < COLS; ++col)
    {
      const auto &bucket = columns[col];
      std::size_t idx = 0;

      while (idx + 2 < bucket.size())
      {
        /* allocate fresh ciphertexts for sum & carry */
        e_bit *sum = new_LweSample(context->in_out_params);
        e_bit *carry = new_LweSample(context->in_out_params);

        fullAdder(*carry, *sum,
                  *bucket[idx],
                  *bucket[idx + 1],
                  *bucket[idx + 2]);

/* push into next layer (critical because of vector re-alloc) */
#pragma omp critical
        {
          next[col].push_back(sum);
          if (col + 1 < COLS)
            next[col + 1].push_back(carry);
        }

        idx += 3;
        changed = true;
      }

      /* copy any tail (<3 elements) through untouched */
      while (idx < bucket.size())
        next[col].push_back(bucket[idx++]);
    }

    columns.swap(next);
  } while (changed);

  /* ────────────────── 2-row ripple-carry adder ────────────────── */
  e_int rowA, rowB;
  rowA.init(COLS, context);
  rowB.init(COLS, context);
  for (std::size_t i = 0; i < COLS; ++i)
  {
    bootsCONSTANT(&rowA[i], 0, he_pk);
    bootsCONSTANT(&rowB[i], 0, he_pk);
  }

  for (std::size_t col = 0; col < COLS; ++col)
  {
    const auto &bucket = columns[col];
    if (bucket.empty())
      continue;

    lweCopy(&rowA[col], bucket[0], he_pk->params->in_out_params);

    if (bucket.size() == 2)
    {
      lweCopy(&rowB[col], bucket[1], he_pk->params->in_out_params);
    }
    else if (bucket.size() > 2)
    {
      throw std::logic_error("CSA stage: bucket has >2 bits — invariant broken");
    }
  }

  rippleCarryAdder(rowA, rowA, rowB);
  return rowA;
}

size_t TFHECipher::get_ciphertexts_size_bytes(const TFHECiphertextVec &ciphs) const
{
  const size_t num_samples = ciphs.size();

  if (num_samples == 0)
  {
    return 0;
  }

  const TFheGateBootstrappingParameterSet *params_ptr = ciphs.get_params();

  if (!params_ptr)
  {
    throw std::runtime_error("TFHECiphertextVec has a null parameters pointer. Was it initialized?");
  }
  if (!params_ptr->in_out_params)
  {
    throw std::runtime_error("TFHE parameters structure (in_out_params) is missing or null.");
  }

  const int n = params_ptr->in_out_params->n;

  if (n < 0)
  {
    throw std::runtime_error("Invalid LWE dimension 'n' found in parameters.");
  }

  const size_t single_lwe_sample_bytes =
      sizeof(LweSample) + (static_cast<size_t>(n) * sizeof(Torus32));

  return num_samples * single_lwe_sample_bytes;
}

size_t TFHECipher::getSecretKeyEncryptedSize() const
{
  return get_ciphertexts_size_bytes(this->secret_key_encrypted);
}
