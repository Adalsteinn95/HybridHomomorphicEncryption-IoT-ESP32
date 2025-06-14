declare -A expected_commits=(
  ["HElib"]="d7be6f0"
  ["SEAL"]="265d77e"
  ["m4ri"]="b9897d5"
  ["tfhe"]="a085efe"
)

for submodule in "${!expected_commits[@]}"; do
  actual=$(cd "$submodule" && git rev-parse --short HEAD)
  expected="${expected_commits[$submodule]}"
  if [[ "$actual" == "$expected" ]]; then
    echo "[OK] $submodule is at $actual"
  else
    echo "[MISMATCH] $submodule is at $actual (expected $expected)"
  fi
done
