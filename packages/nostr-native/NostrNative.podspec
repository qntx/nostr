require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "NostrNative"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported, :visionos => 1.0 }
  s.source       = { :git => "https://github.com/qntx/nostr.git", :tag => "v#{s.version}" }

  s.source_files = [
    # Implementation (C core + C++ HybridObject)
    "cpp/**/*.{h,hpp,c,cpp}",
    # Vendored libsecp256k1: headers plus the two precomputed-table TUs. secp256k1.c is
    # intentionally not here — cpp/nostr_native.c includes it as a single translation unit.
    "vendor/secp256k1/include/**/*.h",
    "vendor/secp256k1/src/**/*.h",
    "vendor/secp256k1/src/precomputed_ecmult.c",
    "vendor/secp256k1/src/precomputed_ecmult_gen.c",
  ]

  s.pod_target_xcconfig = {
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) ENABLE_MODULE_EXTRAKEYS=1 ENABLE_MODULE_SCHNORRSIG=1",
  }

  load 'nitrogen/generated/ios/NostrNative+autolinking.rb'
  add_nitrogen_files(s)

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'
  install_modules_dependencies(s)
end
