//
//  SecureKeyStorageTests.swift
//  CryptoSuiteExample
//
//  Created by Bartłomiej Pluta
//

import Testing
@testable import CryptoSuite

struct SecureKeyStorageTests {
    let storage: SecureKeyStorage
    let keychain: KeychainStore
    let keyGenerator: SecureKeyGenerator
    
    typealias DefaultKeyType = P256.KeyAgreement.PrivateKey
    
#if targetEnvironment(simulator)
    private static let isRunningOnSimulator = true
#else
    private static let isRunningOnSimulator = false
#endif
    
    init() async throws {
        let keychain = KeychainStore()
        self.keychain = keychain
        self.storage = SecureKeyStorage(keychainStore: keychain, accessibility: .whenUnlocked, shouldSkipAuthenticationUI: false)
        self.keyGenerator = SecureKeyGenerator()
        try await keychain.wipeOutStorage()
    }
    
    @Test("Storing P256 key agreement key")
    func testStoreP256KeyAgreementKey() async throws {
        let expectedKey: P256.KeyAgreement.PrivateKey = try keyGenerator.generateKey(with: nil)
        try await storage.storeKey(expectedKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        let storedEntry = try fetchFromKeychain(key: TestIdentifiers.someKey.keychainLabel)
        let storedKey: SecKey = try storedEntry.get(key: kSecValueRef)
        #expect(expectedKey.x963Representation == storedKey.privateKeyExternalRepresentation)
        #expect(expectedKey.publicKey.x963Representation == storedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Storing P256 signing key")
    func testStoreP256SigningKey() async throws {
        let expectedKey: P256.Signing.PrivateKey = try keyGenerator.generateKey(with: nil)
        try await storage.storeKey(expectedKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        let storedEntry = try fetchFromKeychain(key: TestIdentifiers.someKey.keychainLabel)
        let storedKey: SecKey = try storedEntry.get(key: kSecValueRef)
        #expect(expectedKey.x963Representation == storedKey.privateKeyExternalRepresentation)
        #expect(expectedKey.publicKey.x963Representation == storedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Storing secure enclave P256 key agreement key")
    func testStoreSecureEnclaveP256KeyAgreementKey() async throws {
        let expectedKey: SecureEnclave.P256.KeyAgreement.PrivateKey = try keyGenerator.generateKey(with: nil)
        try await storage.storeKey(expectedKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        let storedEntry = try fetchFromKeychain(key: TestIdentifiers.someKey.keychainLabel)
        let storedKey: SecKey = try storedEntry.get(key: kSecValueRef)
        #expect(expectedKey.dataRepresentation == storedKey.privateKeyTokenRepresentation)
        #expect(expectedKey.publicKey.x963Representation == storedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Storing secure enclave P256 signing key")
    func testStoreSecureEnclaveP256SigningKey() async throws {
        let expectedKey: SecureEnclave.P256.Signing.PrivateKey = try keyGenerator.generateKey(with: nil)
        try await storage.storeKey(expectedKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        let storedEntry = try fetchFromKeychain(key: TestIdentifiers.someKey.keychainLabel)
        let storedKey: SecKey = try storedEntry.get(key: kSecValueRef)
        #expect(expectedKey.dataRepresentation == storedKey.privateKeyTokenRepresentation)
        #expect(expectedKey.publicKey.x963Representation == storedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Different key accessibility settings", arguments: [
        (storedAccessiblity: .whenUnlocked, expectedAccessibility: kSecAttrAccessibleWhenUnlocked),
        (storedAccessiblity: .whenUnlockedThisDeviceOnly, expectedAccessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        (storedAccessiblity: .afterFirstUnlock, expectedAccessibility: kSecAttrAccessibleAfterFirstUnlock),
        (storedAccessiblity: .afterFirstUnlockThisDeviceOnly, expectedAccessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
        (storedAccessiblity: .whenPasscodeSetThisDeviceOnly, expectedAccessibility: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
    ] as [(KeychainQueryKey.Accessibility, CFString)])
    func testStoreAccessiblity(storedAccessibility: KeychainQueryKey.Accessibility, expectedAccessibility: CFString) async throws {
        let storage = SecureKeyStorage(
            keychainStore: keychain,
            accessibility: storedAccessibility
        )
        let expectedKey: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        try await storage.storeKey(expectedKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        let storedEntry = try fetchFromKeychain(key: TestIdentifiers.someKey.keychainLabel)
        let accessibility: CFString = try storedEntry.get(key: kSecAttrAccessible)
        #expect(accessibility == expectedAccessibility)
    }
    
    @Test("Reading P256 key agreement key")
    func testReadP256AgreementKey() async throws {
        let expectedKey = SecKey.newP256()
        try writeToKeychain(key: TestIdentifiers.someKey.keychainLabel, value: expectedKey, accessibility: kSecAttrAccessibleWhenUnlocked)
        let storedKey: P256.KeyAgreement.PrivateKey? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey?.x963Representation == expectedKey.privateKeyExternalRepresentation)
        #expect(storedKey?.publicKey.x963Representation == expectedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Reading P256 signing key")
    func testReadP256SigningKey() async throws {
        let expectedKey = SecKey.newP256()
        try writeToKeychain(key: TestIdentifiers.someKey.keychainLabel, value: expectedKey, accessibility: kSecAttrAccessibleWhenUnlocked)
        let storedKey: P256.Signing.PrivateKey? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey?.x963Representation == expectedKey.privateKeyExternalRepresentation)
        #expect(storedKey?.publicKey.x963Representation == expectedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Reading secure enclave P256 key agreement key")
    func testReadSecureEnclaveP256AgreementKey() async throws {
        let expectedKey = SecKey.newSecureEnclaveP256(biometryProtected: false)
        try writeToKeychain(key: TestIdentifiers.someKey.keychainLabel, value: expectedKey, accessibility: kSecAttrAccessibleWhenUnlocked)
        let storedKey: SecureEnclave.P256.KeyAgreement.PrivateKey? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey?.dataRepresentation == expectedKey.privateKeyTokenRepresentation)
        #expect(storedKey?.publicKey.x963Representation == expectedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Reading secure enclave P256 signing key")
    func testReadSecureEnclaveP256SigningKey() async throws {
        let expectedKey = SecKey.newSecureEnclaveP256(biometryProtected: false)
        try writeToKeychain(key: TestIdentifiers.someKey.keychainLabel, value: expectedKey, accessibility: kSecAttrAccessibleWhenUnlocked)
        let storedKey: SecureEnclave.P256.Signing.PrivateKey? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey?.dataRepresentation == expectedKey.privateKeyTokenRepresentation)
        #expect(storedKey?.publicKey.x963Representation == expectedKey.publicKeyExternalRepresentation)
    }
    
    @Test("Storing generated key and reading it back")
    func testReadAndStoreKey() async throws {
        let expectedKey: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        try await storage.storeKey(expectedKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        let storedKey: DefaultKeyType? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey?.dataRepresentation == expectedKey.dataRepresentation)
    }
    
    @Test("Reading non existing key - should return nil")
    func testMissingKey() async throws {
        let storedKey: DefaultKeyType? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey == nil)
    }
    
    @Test("Deleting key - should remove it from keychain")
    func testKeyDeletion() async throws {
        let key: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        try await storage.storeKey(key, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        try await storage.deleteKey(identifier: TestIdentifiers.someKey)
        let storedKey: DefaultKeyType? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey == nil)
    }
    
    @Test("Storing the same key twice - should overwrite")
    func testDoubleStore() async throws {
        let firstKey: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        let secondKey: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        #expect(firstKey.dataRepresentation != secondKey.dataRepresentation)
        
        try await storage.storeKey(firstKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        try await storage.storeKey(secondKey, identifier: TestIdentifiers.someKey, isAuthenticationRequired: false)
        
        let storedKey: DefaultKeyType? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKey?.dataRepresentation == secondKey.dataRepresentation)
    }
    
    @Test("Protected key storage - should return nil when no authentication context provided and set to skip authentication UI", .disabled(if: isRunningOnSimulator, "This is intended to be tested on a physical device - keychain on simulator always returns stored entry even if there was no authentication context provided"))
    func testAuthenticationRequirementNoContext() async throws {
        /// Disabling auto triggering authentication prompt
        let storage = SecureKeyStorage(keychainStore: keychain, accessibility: .whenUnlocked, shouldSkipAuthenticationUI: true)
        let key: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        
        /// Requiring authentication
        try await storage.storeKey(key, identifier: TestIdentifiers.someKey, isAuthenticationRequired: true)
        
        /// No authentication context provided (should not find the key)
        let storedKeyWithoutAuthentication: DefaultKeyType? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKeyWithoutAuthentication == nil)
    }
    
    @Test("Protected key storage - should return the key when passed successfully authenticated context", .disabled(if: isRunningOnSimulator, "This is intended to be tested on a physical device - keychain on simulator always returns stored entry regardless of authentication context provided"))
    func testAuthenticationRequirementWithContext() async throws {
        /// Disabling auto triggering authentication prompt
        let storage = SecureKeyStorage(keychainStore: keychain, accessibility: .whenUnlocked, shouldSkipAuthenticationUI: true)
        let key: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        
        /// Requiring authentication
        try await storage.storeKey(key, identifier: TestIdentifiers.someKey, isAuthenticationRequired: true)
        
        /// Creating and preauthing biometry context
        let biometryProvider = await BiometryProvider(keychainStore: storage.keychain, domainStateKey: TestIdentifiers.someDomain)
        let context = biometryProvider.initializeContext(prompt: "Some prompt")
        try await context.evaluate(policy: .biometry)
        
        /// Providing authentication context (should read key without any additional authentication)
        let storedKeyWithAuthentication: DefaultKeyType? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: context)
        #expect(storedKeyWithAuthentication?.dataRepresentation == key.dataRepresentation)
    }
    
    @Test("Protected key storage - should automatically trigger authentication prompt", .disabled(if: isRunningOnSimulator, "This is intended to be tested on a physical device - keychain on simulator always returns stored entry regardless of authentication context provided"))
    func testAuthenticationRequirementAutoContext() async throws {
        /// Enabling auto triggering authentication prompt
        let storage = SecureKeyStorage(keychainStore: keychain, accessibility: .whenUnlocked, shouldSkipAuthenticationUI: false)
        let key: DefaultKeyType = try keyGenerator.generateKey(with: nil)
        
        /// Requiring authentication
        try await storage.storeKey(key, identifier: TestIdentifiers.someKey, isAuthenticationRequired: true)
        
        /// No authentication context provided (should automatically trigger authentication prompt)
        let storedKeyWithAutoAuthentication: DefaultKeyType? = try await storage.readKey(identifier: TestIdentifiers.someKey, authenticationContext: nil)
        #expect(storedKeyWithAutoAuthentication?.dataRepresentation == key.dataRepresentation)
    }
    
    @Test("Protected key usage - should automatically trigger authentication prompt when using key to sign data", .disabled(if: isRunningOnSimulator, "This is intended to be tested on a physical device - authentication protected keys do not work on simulator"))
    func testAuthenticationProtectedKey() async throws {
        let biometryProvider = await BiometryProvider(keychainStore: storage.keychain, domainStateKey: TestIdentifiers.someDomain)
        let context = biometryProvider.initializeContext(prompt: "Some prompt")
        
        let key: SecureEnclave.P256.Signing.PrivateKey = try keyGenerator.generateKey(with: context)
        
        let dataToSign = "Lorem ipsum dolor sit amet".data(using: .utf8)!
        let signatureManager = SignatureManager()
        let signatrue = try signatureManager.sign(data: dataToSign, with: key)
        #expect(signatrue.rawRepresentation.count == 64)
    }
}

extension SecureKeyStorageTests {
    enum TestIdentifiers: String, KeychainIdentifiable {
        case someKey
        case someDomain
        
        var keychainLabel: String { rawValue }
    }
}

fileprivate extension SecKey {
    var privateKeyTokenRepresentation: Data? {
        (SecKeyCopyAttributes(self) as? [String: Any])?["toid"] as? Data
    }
    
    var privateKeyExternalRepresentation: Data {
        let externalRepresentation = SecKeyCopyExternalRepresentation(self, nil) as Data?
        return externalRepresentation!
    }
    
    var publicKeyExternalRepresentation: Data {
        let publicKey = SecKeyCopyPublicKey(self)!
        let externalRepresentation = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        return externalRepresentation!
    }
    
    static func newP256() -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String: false
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as NSDictionary, &error) else {
            fatalError((error!.takeRetainedValue() as Error).localizedDescription)
        }
        return privateKey
    }
    
    static func newSecureEnclaveP256(biometryProtected: Bool) -> SecKey {
        let flags: SecAccessControlCreateFlags = biometryProtected ? [.biometryCurrentSet, .privateKeyUsage] : [.privateKeyUsage]
        let allocator = kCFAllocatorDefault
        let accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let access = SecAccessControlCreateWithFlags(allocator, accessibility, flags, nil)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as NSDictionary, &error) else {
            fatalError((error!.takeRetainedValue() as Error).localizedDescription)
        }
        return privateKey
    }
}

extension SecureKeyStorageTests {
    enum KeychainError: Error, Equatable {
        case couldNotExtractResponse
        case couldNotExtractValue
        case couldNotCastValueType
        case notFound
        case unknownError(OSStatus)
    }
    
    func writeToKeychain(key: String, value: SecKey, accessibility: CFString) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: value,
            kSecAttrAccessible as String: accessibility,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationLabel as String: key
        ]
        let status = SecItemAdd(query as NSDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unknownError(status)
        }
    }
    
    func fetchFromKeychain(key: String, itemClass: CFString = kSecClassKey) throws -> [String: Any] {
        let query: [String: Any] = [
            kSecClass as String: itemClass,//kSecClassKey,
            kSecAttrApplicationLabel as String: key,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true
        ]
        var item: AnyObject?
        let status = SecItemCopyMatching(query as NSDictionary, &item)
        guard status != errSecItemNotFound else {
            throw KeychainError.notFound
        }
        guard status == errSecSuccess else {
            throw KeychainError.unknownError(status)
        }
        guard let keychainResponseDictionary = item as? [String: Any] else {
            throw KeychainError.couldNotExtractResponse
        }
        return keychainResponseDictionary
    }
}

fileprivate extension Dictionary where Key == String, Value == Any {
    @discardableResult
    func get<T>(key: CFString) throws -> T {
        guard let someValue = self[key as String] else {
            throw SecureKeyStorageTests.KeychainError.couldNotExtractValue
        }
        guard let value = someValue as? T else {
            throw SecureKeyStorageTests.KeychainError.couldNotCastValueType
        }
        return value
    }
}
