//
//  SecureKeyGenerator.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import Keyrmes
import LocalAuthentication

/// A protocol for generating secure cryptographic keys.
public protocol SecureKeyFactory {
    
    /// Generates a secure cryptographic key.
    ///
    /// - Parameter context: An optional biometry context for integration of biometric authentication when accessing or using the generated key.
    /// - Returns: A key of type `KeyType` that conforms to `SecureKeyConvertible`.
    /// - Throws: An error if key generation fails.
    ///
    func generateKey<KeyType: SecureKeyConvertible>(with context: BiometryContext?) throws -> KeyType
}

/// An implementation of `SecureKeyFactory` that generates secure keys using CryptoKit and LocalAuthentication.
///
/// `SecureKeyGenerator` leverages keychain access control and biometric authentication to generate and protect
/// cryptographic keys. It creates a `SecAccessControl` object and initializes a secure key using that access control.
public struct SecureKeyGenerator: SecureKeyFactory, Sendable {
    
    /// The accessibility level that gets applied to generated keys.
    let accessibility: KeychainQueryKey.Accessibility
    
    /// Initializes a new instance of `SecureKeyGenerator` with specified accessibility settings.
    ///
    /// - Parameter accessibility: A key accessiblity setting; defautling to `.whenUnlockedThisDeviceOnly`
    ///
    public init(accessibility: KeychainQueryKey.Accessibility = .whenUnlockedThisDeviceOnly) {
        self.accessibility = accessibility
    }
    
    /// Generates a secure key of given `SecureKeyConvertible` conforming type..
    ///
    /// This method attempts to create a secure key instance with an access control policies defined by
    /// generators's accessiblity settings. Optonally, the generated key can be bound to given biometry context
    /// (if provided) to ensure that only authorized users can perform cryptographic operations with the key.
    ///
    /// - Note: Biometry context is ignored when running on simulator as CryptoKit do not support biomtery
    /// bound keys on simulator environment. This ensures that your code won't fail on simulator without adjusting
    /// it explicitly for simulator as an exception.
    ///
    /// - Parameter authenticationContext: An optional biometry context for integration of biometric authentication when accessing or using the generated key.
    /// - Returns: A secure cryptographic key of defined type concorming to `SecureKeyConvertible` protocol.
    /// - Throws: A `KeyGeneratorError` if key generation fails.
    ///
    public func generateKey<KeyType: SecureKeyConvertible>(with authenticationContext: BiometryContext?) throws(KeyGeneratorError) -> KeyType {
        let accessControl = try getAccessControl(context: authenticationContext)
        let privateKey: KeyType = try initializeKey(accessControl: accessControl, context: authenticationContext)
        return privateKey
    }
}

extension SecureKeyGenerator {
    private func initializeKey<KeyType>(accessControl: SecAccessControl, context authenticationContext: BiometryContext?) throws(KeyGeneratorError) -> KeyType where KeyType: SecureKeyConvertible {
        #if targetEnvironment(simulator)
        let context: LAContext? = nil
        #else
        let context: LAContext? = authenticationContext?.context
        #endif
        do {
            let key = try KeyType(compactRepresentable: true, accessControl: accessControl, authenticationContext: context)
            return key
        } catch {
            throw .failedToCreateSecureKeyInstance(error)
        }
    }
    
    private func getAccessControl(context authenticationContext: BiometryContext?) throws(KeyGeneratorError) -> SecAccessControl {
        let allocator = kCFAllocatorDefault
        let accessibility: KeychainQueryKey.Accessibility = .whenUnlockedThisDeviceOnly
        let accessMode = accessibility.keychainValue as CFString
        let flags = getAccessControlFlags(for: authenticationContext)
        guard let accessControl = SecAccessControlCreateWithFlags(allocator, accessMode, flags, nil) else {
            throw .couldNotInitializeAccessControlObject
        }
        return accessControl
    }
    
    private func getAccessControlFlags(for context: BiometryContext?) -> SecAccessControlCreateFlags {
        if let _ = context {
            return [.biometryCurrentSet, .privateKeyUsage]
        } else {
            return [.privateKeyUsage]
        }
    }
}

public enum KeyGeneratorError: Error, CustomDebugStringConvertible, Sendable {
    case couldNotInitializeAccessControlObject
    case failedToCreateSecureKeyInstance(Error)
    
    public var debugDescription: String {
        switch self {
        case .couldNotInitializeAccessControlObject:
            "Failed to initialize SecAccessControl object"
        case .failedToCreateSecureKeyInstance(let error):
            "Failed to create a secure key instance: (\(error.localizedDescription))"
        }
    }
}
