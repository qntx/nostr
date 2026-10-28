#pragma once

#include "HybridNostrNativeSpec.hpp"

namespace margelo::nitro::nostrnative {

class HybridNostrNative final : public HybridNostrNativeSpec {
public:
  // HybridObject is a virtual base, so the most-derived class must pass TAG itself.
  HybridNostrNative() : HybridObject(TAG) {}

  bool verifySerialized(const std::shared_ptr<ArrayBuffer>& serializedUtf8,
                        const std::shared_ptr<ArrayBuffer>& id,
                        const std::shared_ptr<ArrayBuffer>& pubkey,
                        const std::shared_ptr<ArrayBuffer>& sig) override;
  std::shared_ptr<ArrayBuffer> publicKey(const std::shared_ptr<ArrayBuffer>& secretKey) override;
  std::shared_ptr<ArrayBuffer> sign(const std::shared_ptr<ArrayBuffer>& id,
                                    const std::shared_ptr<ArrayBuffer>& secretKey,
                                    const std::shared_ptr<ArrayBuffer>& auxRand) override;
  std::shared_ptr<ArrayBuffer> ecdhX(const std::shared_ptr<ArrayBuffer>& secretKey,
                                     const std::shared_ptr<ArrayBuffer>& publicKeyX) override;
};

} // namespace margelo::nitro::nostrnative
