//
//  SecureKeyStorage.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import Keyrmes
import LocalAuthentication

/// A protocol defining an actor-based interface for secure cryptographic key storage.
public protocol KeyStorage: Actor {
    
    /// Stores a cryptographic key into secure storage.
    ///
    /// - Parameters:
    ///   - key: A cryptographic key conforming to `SecureKeyConvertible` that will be stored.
    ///   - identifier: A unique keychain identifier used to reference the key.
    /// - Throws: An error if storing the key fails.
    ///
    func storeKey<KeyType: SecureKeyConvertible>(_ key: KeyType, identifier: KeychainIdentifiable, isAuthenticationRequired: Bool) async throws
    
    /// Reads a cryptographic key from secure storage.
    ///
    /// - Parameters:
    ///   - identifier: A unique keychain identifier used to reference the key.
    ///   - authenticationContext: An optional biometry context used to authenticate key retrieval.
    /// - Returns: The cryptographic key of definied type conforming to `SecureKeyConvertible`protocol  if found, otherwise `nil`.
    /// - Throws: An error if reading or decoding the key fails.
    ///
    func readKey<KeyType: SecureKeyConvertible>(identifier: KeychainIdentifiable, authenticationContext: BiometryContext?) async throws -> KeyType?
    
    /// Deletes a cryptographic key from secure storage.
    ///
    /// - Parameter identifier: A unique keychain identifier used to reference the key.
    /// - Throws: An error if deletion fails.
    ///
    func deleteKey(identifier: KeychainIdentifiable) async throws
}

/// Default implementation of `KeyStorage` backed by keychain storage for secure persistence of sensitive keys.
public actor SecureKeyStorage: KeyStorage {
    
    /// The underlying keychain storage used for persistance of stored keys
    let keychain: KeychainStore
    
    /// The keychain accessibility level to apply when storing keys.
    let accessibility: KeychainQueryKey.Accessibility
    
    /// This determines wheatherf keychain should prevent initializing an user authentication proces when
    /// accessed keychain entry is biometricaly protected and there is no evaluated context provided. Such retrieval
    /// would fail automatically if set to true, otherwise it falls back for user authentication.
    let shouldSkipAuthenticationUI: Bool
    
    /// Initializes a new instance of `SecureKeyStorage` with an existing `KeychainStore` and specified accessibility.
    ///
    /// - Parameters:
    ///   - keychainStore: The underlying keychain storage used for key operations.
    ///   - accessibility: The keychain accessibility level to apply when storing keys.
    ///   - shouldSkipAuthenticationUI: A flag that defines if system should fallback for authentication if  there is no evaluated authentication context provided when accessing a biometry provided entry. Defaults to false.
    ///
    public init(keychainStore: KeychainStore, accessibility: KeychainQueryKey.Accessibility, shouldSkipAuthenticationUI: Bool = false) {
        self.keychain = keychainStore
        self.accessibility = accessibility
        self.shouldSkipAuthenticationUI = shouldSkipAuthenticationUI
    }
    
    /// Initializes a new instance of `SecureKeyStorage` by creating a new `KeychainStore` with the given parameters.
    ///
    /// - Parameters:
    ///   - accessGroup: An optional access group for sharing keychain items.
    ///   - attributeService: An optional service attribute to group keychain items.
    ///   - serializer: A `KeychainSerializer` defining a serialization strategy for keychain stored types
    ///   - accessibility: The keychain accessibility level to apply when storing keys.
    ///   - shouldSkipAuthenticationUI: A flag that defines if system should fallback for authentication if  there is no evaluated authentication context provided when accessing a biometry provided entry.Defaults to false.
    ///
    public init(
        accessGroup: String? = nil,
        attributeService: String? = nil,
        serializer: KeychainSerializer = KeyrmesKeychainSerializer(),
        accessibility: KeychainQueryKey.Accessibility,
        shouldSkipAuthenticationUI: Bool = false
    ) {
        self.keychain = KeychainStore(
            accessGroup: accessGroup,
            attributeService: attributeService,
            serializer: serializer
        )
        self.accessibility = accessibility
        self.shouldSkipAuthenticationUI = shouldSkipAuthenticationUI
    }
    
    /// Stores a cryptographic key into kecychain storage.
    ///
    /// The method extracts the underlying `SecKey` from the provided key, constructs a keychain query,
    /// and attempts to store the key.
    ///
    /// - Note: In case of a duplicate key, the existing key is deleted and the
    /// store operation is retried.
    ///
    /// - Parameters:
    ///   - key: A cryptographic key conforming to `SecureKeyConvertible` to be stored.
    ///   - identifier: A unique keychain identifier for referencing the key.
    ///   - isAuthenticationRequired: A flag that determines if keychain should require biometry authentication when accessing the stored key.
    ///
    /// - Throws: A `SecureKeyStorageError` if the store operation fails.
    ///
    public func storeKey<KeyType>(_ key: KeyType, identifier: KeychainIdentifiable, isAuthenticationRequired: Bool) async throws(SecureKeyStorageError) where KeyType : SecureKeyConvertible {
        let secKey = try extractSecKey(from: key)
        let accessControl = try getAccessControl(isAuthenticationRequired: isAuthenticationRequired)
        do {
            let query = getSetQuery(identifier: identifier, secKey: secKey, accessControl: accessControl)
            try await set(query: query)
        } catch .keychainAccessFailure(.storeOperationFailed(let status)) where status == errSecDuplicateItem {
            try await deleteKey(identifier: identifier)
            let query = getSetQuery(identifier: identifier, secKey: secKey, accessControl: accessControl)
            try await set(query: query)
        }
    }
    
    /// Reads a cryptographic key from keychain.
    ///
    /// The method constructs a keychain read query and attempts to retrieve the underlying `SecKey` from the keychain.
    /// It then initializes a new key instance using the `SecureKeyConvertible` initializer, optionally utilizing
    /// a biometric authentication context.
    ///
    /// - Note: In the scenario of not providing `authenticationContext` to an authentication protected entry
    /// with `shouldSkipAuthenticationUI` set to `true`, the keychain behaves like the queried element is missing
    /// even if it actually is not. Since the keychain does not mark any reason for the failure instead of reporting the
    /// value as missing, this function would return `nil` in the described scenario which may be wrongly interpreted.
    /// Please keep it mind when dealing with authentication protected entries.
    ///
    /// - Parameters:
    ///   - identifier: A unique keychain identifier for the key.
    ///   - authenticationContext: An optional biometry context used to authenticate key retrieval.
    /// - Returns: An instance of the cryptographic key if found, otherwise `nil`.
    /// - Throws: A `SecureKeyStorageError` if reading or decoding the key fails.
    /// 
    public func readKey<KeyType>(identifier: KeychainIdentifiable, authenticationContext: BiometryContext?) async throws(SecureKeyStorageError) -> KeyType? where KeyType : SecureKeyConvertible {
        let query = getReadQuery(identifier: identifier, context: authenticationContext)
        guard let response = try await read(query: query) else { return nil }
        let secKey = try extractSecKey(from: response)
        let key: KeyType = try initializeKey(from: secKey, with: authenticationContext)
        return key
    }
    
    /// Deletes a cryptographic key from secure storage.
    ///
    /// The method constructs a keychain deletion query using the provided identifier and attempts to remove
    /// the associated key from the keychain.
    ///
    /// - Parameter identifier: A unique keychain identifier for the key.
    /// - Throws: A `SecureKeyStorageError` if the deletion fails.
    ///
    public func deleteKey(identifier: KeychainIdentifiable) async throws(SecureKeyStorageError) {
        let query = getDeleteQuery(identifier: identifier)
        try await delete(query: query)
    }
}

// MARK: - Operations
extension SecureKeyStorage {
    private func read<Query>(query: consuming Query) async throws(SecureKeyStorageError) -> RawKeychainOutput? where Query: QueryBuildable, Query: ~Copyable, Query: Sendable {
        do {
            let response = try await keychain.read(query: query)
            return response
        } catch { throw .keychainAccessFailure(error) }
    }
    
    private func set<Query>(query: consuming Query) async throws(SecureKeyStorageError) where Query: QueryBuildable, Query: ~Copyable, Query: Sendable {
        do {
            try await keychain.set(query: query)
        } catch { throw .keychainAccessFailure(error) }
    }
    
    private func delete<Query>(query: consuming Query) async throws(SecureKeyStorageError) where Query: QueryBuildable, Query: ~Copyable, Query: Sendable {
        do {
            try await keychain.delete(query: query)
        } catch { throw .keychainAccessFailure(error) }
    }
    
    private func initializeKey<KeyType>(from secKeyRepresentation: SecKey, with authenticationContext: BiometryContext?) throws(SecureKeyStorageError) -> KeyType where KeyType : SecureKeyConvertible {
        #if targetEnvironment(simulator)
        let context: LAContext? = nil
        #else
        let context: LAContext? = authenticationContext?.context
        #endif
        do {
            let key = try KeyType(secKey: secKeyRepresentation, authenticationContext: context)
            return key
        } catch {
            throw .failedToCreateKeyInstance(error)
        }
    }
}

// MARK: - Keychain queries
extension SecureKeyStorage {
    private func getReadQuery(identifier: KeychainIdentifiable, context: BiometryContext?) -> KeychainQueryBuilder {
        KeychainQueryBuilder.emptyQuery()
            .set(class: .key)
            .set(useAuthenticationContext: context?.context)
            .set(useAuthenticationUI: shouldSkipAuthenticationUI ? .skip : nil)
            .set(attributeApplicationLabel: identifier.keychainLabel)
            .set(useDataProtectionKeychain: true)
            .set(returnReference: true)
    }
    
    private func getSetQuery(identifier: KeychainIdentifiable, secKey: SecKey, accessControl: SecAccessControl) -> KeychainQueryBuilder {
        KeychainQueryBuilder.emptyQuery()
            .set(class: .key)
            .set(valueReference: .key(secKey))
            .set(attributeAccessControl: accessControl)
            .set(useDataProtectionKeychain: true)
            .set(attributeApplicationLabel: identifier.keychainLabel)
    }
    
    private func getDeleteQuery(identifier: KeychainIdentifiable) -> KeychainQueryBuilder {
        KeychainQueryBuilder.emptyQuery()
            .set(class: .key)
            .set(useDataProtectionKeychain: true)
            .set(attributeApplicationLabel: identifier.keychainLabel)
    }
}

// MARK: - Helpers
extension SecureKeyStorage {
    private func extractSecKey(from keychainResponse: RawKeychainOutput) throws(SecureKeyStorageError) -> SecKey {
        guard CFGetTypeID(keychainResponse.object) == SecKeyGetTypeID() else {
            throw .unableToCreateSecKeyRepresentation(.keychainOutputTypeMismatch)
        }
        guard let secKey = keychainResponse.object as! SecKey? else {
            throw .unableToCreateSecKeyRepresentation(.keychainOutputTypeCastFailure)
        }
        return secKey
    }
    
    private func extractSecKey<KeyType>(from key: KeyType) throws(SecureKeyStorageError) -> SecKey where KeyType : SecureKeyConvertible {
        do {
            let key = try key.secKey
            return key
        } catch { throw .unableToCreateSecKeyRepresentation(.secureKeyConvertibleExtractionFailure(error)) }
    }
    
    private func getAccessControl(authenticationContext: BiometryContext?) throws(SecureKeyStorageError) -> SecAccessControl {
        let isAuthenticationRequired = authenticationContext != nil
        return try getAccessControl(isAuthenticationRequired: isAuthenticationRequired)
    }
    
    private func getAccessControl(isAuthenticationRequired: Bool) throws(SecureKeyStorageError) -> SecAccessControl {
        let accessMode = accessibility.keychainValue as CFString
        let flags = getAccessControlFlags(isAuthenticationRequired: isAuthenticationRequired)
        guard let accessControl = SecAccessControlCreateWithFlags(nil, accessMode, flags, nil) else {
            throw .couldNotInitializeAccessControlObject
        }
        return accessControl
    }
    
    private func getAccessControlFlags(isAuthenticationRequired: Bool) -> SecAccessControlCreateFlags {
        if isAuthenticationRequired {
            return [.biometryCurrentSet]
        } else {
            return []
        }
    }
}

extension SecureKeyConvertible {
    var classDataRepresentation: CFData {
        dataRepresentation as CFData
    }
}

public enum SecureKeyStorageError: Error, CustomDebugStringConvertible {
    case unableToCreateSecKeyRepresentation(SecKeyConversionError)
    case keychainAccessFailure(KeychainStoreError)
    case failedToCreateKeyInstance(KeyConversionError)
    case couldNotInitializeAccessControlObject
    
    public enum SecKeyConversionError: Sendable, CustomDebugStringConvertible {
        case keychainOutputTypeMismatch
        case keychainOutputTypeCastFailure
        case secureKeyConvertibleExtractionFailure(KeyConversionError)
        
        public var debugDescription: String {
            switch self {
            case .keychainOutputTypeMismatch:
                "Type mismatch of keychain extracted object"
            case .keychainOutputTypeCastFailure:
                "Failed to cast keychain extracted object"
            case .secureKeyConvertibleExtractionFailure(let error):
                "Failed to extract SecKey from SecureKeyConvertible object: (\(error))"
            }
        }
    }
    
    public var debugDescription: String {
        switch self {
        case .unableToCreateSecKeyRepresentation(let error):
            "Failed to create SecKey representation: (\(error))"
        case .keychainAccessFailure(let error):
            "Keychain access failure: (\(error))"
        case .failedToCreateKeyInstance(let error):
            "Failed to create key instance: (\(error))"
        case .couldNotInitializeAccessControlObject:
            "Failed to initialize SecAccessControl object"
        }
    }
}
