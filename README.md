# CryptoSuite

<p>
   <a href="https://developer.apple.com/swift/">
      <img src="https://img.shields.io/badge/Swift-6.0-orange.svg?style=flat" alt="Swift 6.0">
   <a href="https://github.com/apple/swift-package-manager">
      <img src="https://img.shields.io/badge/Swift%20Package%20Manager-compatible-brightgreen.svg" alt="SPM">
   </a>
</p>


CryptoSuite is your all-in-one Swift library for integrating elliptic curve cryptography into your apps with ease. It provides a simple yet robust API that seamlessly combines cryptographic operations, secure key persistence via keychain and biometric protection, all built on top of Apple's CryptoKit.

## Features

CryptoSuite is written entirely in Swift 6, leveraging structured concurrency and the latest Swift APIs. It provides your project with a comprehensive and secure solution for EC-based cryptographic operations, including key persistence and message integrity checks using MAC:

### Cryptographic Operations

- **Elliptic Curve Cryptography (ECC)**: Support for key agreement (ECDH) and digital signature (ECDSA) operations using the following elliptic curves:
  - NIST P-256 (+ Secure Enclave managed P-256)
  - NIST P-384
  - NIST P-521
- **Message Authentication Code (MAC)**: Generation and verification using HMAC.

### Secure Key Management

- **Keychain Integration**: Secure key persistence leveraging Apple's keychain through the [Keyrmes](https://github.com/bpluta/Keyrmes) library.
- **Biometric Protection**: Optional biometry authentication for key access and key usage (the later available only for Secure Enclave keys only).

### Biometry

- **Biometric State Awareness**: Monitoring device biometric state changes (for example when new fingerprint / face / eye has been registered)
- **Authentication Context Workflows**: Manage biometric authentication contexts, including initialization, preauthentication, and invalidation workflows

## Compatibility

CryptoSuite supports the following platforms and OS versions:

- **iOS**: 16.0 and later
- **macOS**: 13.0 and later
- **watchOS**: 9.0 and later
- **tvOS**: 16.0 and later
- **visionOS**: 1.0 and later

## Installation

### Adding CryptoSuite as Swift Package Manager dependency

To integrate using Apple's [Swift Package Manager](https://swift.org/package-manager/), add the following line to the dependencies in your `Package.swift` file:

```swift
.package(url: "https://github.com/bpluta/CryptoSuite.git", from: "1.0.0")
```

Then include `CryptoSuite` as a dependency for your target:

```swift
.target(name: "<YOUR_TARGET_NAME>", dependencies: [
    .product(name: "CryptoSuite", package: "CryptoSuite"),
]),
```

Finally, add `import CryptoSuite` to your source code.

## Usage

CryptoSuite offers a clear and easy-to-use API for performing common cryptographic tasks. Below are examples demonstrating essential features:

### Key generation
#### Setup
```swift
let keyGenerator = SecureKeyGenerator()
```
#### EC key pair generation
```swift
// Generates standard NIST P-256 EC Private Key
let privateKey: P256.KeyAgreement.PrivateKey? = try keyGenerator.generateKey(with: nil)
// Obtaining public key
let publicKey = privateKey?.publicKey
```

### Key persistence
#### Setup
```swift
// Defining enum with keychain entity identifier
enum KeychainIdentifiers: String, KeychainIdentifiable {
    case agreementKey

    var keychainLabel: String { rawValue }
}

// Setting up keychain-backed secure storage
let keychainStore = KeychainStore()
let keyStorage = SecureKeyStorage(keychainStore: keychainStore, accessibility: .whenUnlockedThisDeviceOnly)
```
#### Store key in keychain
```swift
// Storing given private key under agreementKey identifier
try await keyStorage.storeKey(
    privateKey,
    identifier: KeychainIdentifiers.agreementKey,
    isAuthenticationRequired: false
)
```
#### Read key from keychain
```swift
// Reading P256.KeyAgreement.PrivateKey under agreementKey identifier from keychain
let privateKey: P256.KeyAgreement.PrivateKey? = try await keyStorage.readKey(
    identifier: KeychainIdentifiers.agreementKey,
    authenticationContext: nil
)
```
#### Delete key from keychain
```swift
// Deleting key of agreementKey from keychain
try await keyStorage.deleteKey(identifier: KeychainIdentifiers.agreementKey)
```

### Cryptographic operations
#### ECDSA signature generation
```swift
// Generating ECDSA signature of given message using provided private key 
let signature = try signatureManager.sign(data: messageData, with: privateKey)
```
#### ECDSA signature verification
```swift
// Verifying if ECDSA signature of given message is correct and has been produced by the owner of the public key 
let isValid = signatureManager.verify(signature: signature, of: messageData, for: publicKey)
```
#### MAC authentication code generation
```swift
// Initializing CryptoKit.SymmetricKey instance from raw key data
let symmetricKey = SymmetricKey(data: keyData)
// Generating HMAC-SHA256 authentication code of given data using provided symmetric key
let authenticationCode = signatureManager.create(HMAC<SHA256>.self, from: data, with: symmetricKey)
```
#### MAC authentication code verification
```swift
// Initializing CryptoKit.SymmetricKey instance from raw key data
let symmetricKey = SymmetricKey(data: keyData)
// Validating if provided HMAC-SHA256 authentication code is correct for given data and symmetric key
let isValid = signatureManager.verify(HMAC<SHA256>.self, authenticationCode: authenticationCode, authenticating: data, using: symmetricKey)
```


### Biometry
#### Setup
> [!IMPORTANT]
> In order to provide biometry into your app you need to first include the `NSFaceIDUsageDescription` key into your `Info.plist` file in your project
```swift
// Defining enum with keychain entity identifiers
enum KeychainIdentifiers: String, KeychainIdentifiable {
    case biometryDomainState

    var keychainLabel: String { rawValue }
}

// Setting up BiometryProvider instance
let keychainStore = KeychainStore()
let biometryProvider = BiometryProvider(
    keychainStore: keychainStore,
    domainStateKey: KeychainIdentifiers.biometryDomainState,
    accessibility: .whenUnlockedThisDeviceOnly
)
// Initializing authentication context with custom prompt message
let biometryContext = biometryProvider.initializeContext(prompt: "Biometry prompt message")
```
#### Biometry state verification
```swift
// Verifying if biometry can be evaluated and its state has not been changed
// (for example new face has been enrolled to FaceID)
try await biometryProvider.biometryState.verify(biometryContext, with: .biometry)
```
#### Context pre-authentication
```swift
// Evaluating a biometry authentication on given context
try await biometryProvider.preauthBiometry(context: biometryContext, policy: .biometry)
```
#### Context invalidation
```swift
// Stopping pending evaluation and preventing the context from being used again
await biometryProvider.invalidate(context: biometryContext)
```
#### Reseting biometry state
```swift
// Deleting biometry state domain from keychain
try await biometryProvider.biometryState.reset()
```

### Migration from your current implementation
#### Custom LAContext configuration
You can use your custom [LAContext]('https://developer.apple.com/documentation/localauthentication/lacontext') setup with CryptoSuite by using the following initializer:
```swift
let biometryContext = BiometryContext(context: laContext)
```
#### Migrating SecKey instances into CryptoKit keys
CryptoSuite provides an easy way to migrate [SecKey]('https://developer.apple.com/documentation/security/seckey') instances from `Security.framework` to supported `CryptoKit` key types that can be used in CryptoSuite. Here are few examples:
```swift
// NIST P-256
let p256AgreementKey = try P256.KeyAgreement.PrivateKey(secKey: secKey)
let p256SigningKey = try P256.Signing.PrivateKey(secKey: secKey)

// NIST P-384
let p384AgreementKey = try P384.KeyAgreement.PrivateKey(secKey: secKey)
let p384SigningKey = try P384.Signing.PrivateKey(secKey: secKey)

// NIST P-521
let p521AgreementKey = try P521.KeyAgreement.PrivateKey(secKey: secKey)
let p521SigningKey = try P521.Signing.PrivateKey(secKey: secKey)

// Secure Enclave NIST P-256
let p256SecureEnclaveAgreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(secKey: secKey, authenticationContext: laContext)
let p256SecureEnclaveSigningKey = try SecureEnclave.P256.Signing.PrivateKey(secKey: secKey, authenticationContext: laContext)
```

### Swift concurrency

CryptoSuite has been designed to work with Swift Concurrency providng safe and easy to use way to integrate it to your project using async / await API.  
> [!NOTE]
> While CryptoSuite has been built with Swift concurrency support in mind, it is based upon Apple’s CryptoKit types that are not necessarily marked as `Sendable`. Therefore if you choose to use strict Swift Concurrency settings in your project you will likely run into concurrency warning issues when handling CryptoKit types. If you wish to silence these kind of warnings you can override an implicit import of CryptoKit that is provided by the library by adding an explicit import of CryptoKit marked with `@preconcurrency` attribute.

## Contributing

Contributions are very welcome 🙌

## License

CryptoSuite is available under the [Zero-Clause BSD](https://opensource.org/license/0bsd) license. See [LICENSE.txt](./LICENSE.txt) for details.

