#include "HybridNostrNative.hpp"
#include "nostr_native.h"

#include <stdexcept>

namespace margelo::nitro::nostrnative {

bool HybridNostrNative::verifySerialized(
    const std::shared_ptr<ArrayBuffer>& serializedUtf8,
    const std::shared_ptr<ArrayBuffer>& id,
    const std::shared_ptr<ArrayBuffer>& pubkey,
    const std::shared_ptr<ArrayBuffer>& sig) {
  if (id->size() != 32 || pubkey->size() != 32 || sig->size() != 64) {
    return false;
  }
  return qntx_nostr_verify_serialized(serializedUtf8->data(), serializedUtf8->size(),
                                     id->data(), pubkey->data(), sig->data()) != 0;
}

std::shared_ptr<ArrayBuffer> HybridNostrNative::publicKey(
    const std::shared_ptr<ArrayBuffer>& secretKey) {
  if (secretKey->size() != 32) {
    throw std::invalid_argument("secretKey must be 32 bytes");
  }
  auto out = ArrayBuffer::allocate(32);
  if (!qntx_nostr_public_key(secretKey->data(), out->data())) {
    throw std::invalid_argument("invalid secret key");
  }
  return out;
}

std::shared_ptr<ArrayBuffer> HybridNostrNative::sign(
    const std::shared_ptr<ArrayBuffer>& id,
    const std::shared_ptr<ArrayBuffer>& secretKey,
    const std::shared_ptr<ArrayBuffer>& auxRand) {
  if (id->size() != 32) {
    throw std::invalid_argument("id must be 32 bytes");
  }
  if (secretKey->size() != 32) {
    throw std::invalid_argument("secretKey must be 32 bytes");
  }
  if (auxRand->size() != 32) {
    throw std::invalid_argument("auxRand must be 32 bytes");
  }
  auto out = ArrayBuffer::allocate(64);
  if (!qntx_nostr_sign(id->data(), secretKey->data(), auxRand->data(), out->data())) {
    throw std::invalid_argument("invalid secret key");
  }
  return out;
}

} // namespace margelo::nitro::nostrnative
