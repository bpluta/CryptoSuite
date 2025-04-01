//
//  SignatureManager.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

/// A protocol that defines operations for generating and verifying digital signatures.
///
/// Conforming types can sign data using a private key and verify signatures using a corresponding public key.
/// The generic constraints ensure that the signature type produced by the signing operation matches the expected type.
public protocol SignatureWorker {
    
    /// Generates a digital signature for the given data using the specified private key.
    ///
    /// - Parameters:
    ///   - data: The data to be signed.
    ///   - key: A private key conforming to `SecureKeyItem` used to generate the signature.
    /// - Returns: A digital signature of type `SignatureType`.
    /// - Throws: An error if signature generation fails.
    ///
    func sign<SignatureType: SecureKeySignature, PrivateKeyType: SecureKeyItem>(
        data: Data,
        with key: PrivateKeyType
    ) throws -> SignatureType where PrivateKeyType.SignatureType == SignatureType
    
    /// Verifies the digital signature of the given data using the specified public key.
    ///
    /// - Parameters:
    ///   - signature: The digital signature to verify.
    ///   - data: The original data that was signed.
    ///   - publicKey: A public key conforming to `PublicKeyItem` used for verification.
    /// - Returns: A Boolean value indicating whether the signature is valid.
    ///
    func verify<SignatureType: SecureKeySignature, PublicKeyType: PublicKeyItem>(
        signature: SignatureType,
        of data: Data,
        for publicKey: PublicKeyType
    ) -> Bool where PublicKeyType.SignatureType == SignatureType
}

/// A protocol that defines operations for creating and verifying authentication codes (MACs).
///
/// Conforming types can generate a hashed authentication code for a given data using a symmetric key,
/// and verify an authentication code against the data and key.
public protocol AuthenticationCodeWorker {
    
    /// Creates an authentication code (MAC) for the given data using the specified symmetric key.
    ///
    /// - Parameters:
    ///   - codeType: The type of authentication code algorithm to use.
    ///   - data: The data for which the authentication code is generated.
    ///   - key: A symmetric key conforming to `SymmetricKeyItem` used for code generation.
    /// - Returns: A hashed code of type `HashedCodeType`.
    ///
    func create<AlgorithmType: AuthenticationCode, KeyType: SymmetricKeyItem, HashedCodeType: HashedCode>(
        _ codeType: AlgorithmType.Type,
        from data: Data,
        with key: KeyType
    ) -> HashedCodeType where AlgorithmType.KeyType == KeyType, AlgorithmType.CodeType == HashedCodeType
    
    
    /// Verifies the given authentication code for the data using the specified symmetric key.
    ///
    /// - Parameters:
    ///   - codeType: The type of authentication code algorithm to use.
    ///   - authenticationCode: The authentication code to verify.
    ///   - data: The data to authenticate.
    ///   - key: A symmetric key conforming to `SymmetricKeyItem` used for verification.
    /// - Returns: A Boolean value indicating whether the authentication code is valid.
    ///
    func verify<AlgorithmType: AuthenticationCode, KeyType: SymmetricKeyItem, HashedCodeType: HashedCode>(
        _ codeType: AlgorithmType.Type,
        authenticationCode: HashedCodeType,
        authenticating data: Data,
        using key: KeyType
    ) -> Bool where AlgorithmType.KeyType == KeyType, AlgorithmType.CodeType == HashedCodeType
}

/// A manager that implements both digital signature and authentication code operations.
///
/// `SignatureManager` provides implementations for signing data, verifying signatures,
/// creating authentication codes, and verifying authentication codes. It leverages underlying key
/// operations provided by keys conforming to `SecureKeyItem` and `PublicKeyItem`, as well as authentication
/// code algorithms conforming to `AuthenticationCode`.
public struct SignatureManager: SignatureWorker, AuthenticationCodeWorker, Sendable {
    
    public init() { }
    
    /// Signs the given data using the specified private key.
    ///
    /// - Parameters:
    ///   - data: The data to be signed.
    ///   - key: A private key conforming to `SecureKeyItem` used for signing.
    /// - Returns: A digital signature of type `SignatureType`.
    /// - Throws: A `SignatureManagerError` if the signature cannot be generated.
    ///
    public func sign<SignatureType, PrivateKeyType>(
        data: Data,
        with key: PrivateKeyType
    ) throws(SignatureManagerError) -> SignatureType where SignatureType == PrivateKeyType.SignatureType, PrivateKeyType : SecureKeyItem {
        do {
            return try key.signature(for: data)
        } catch { throw .failedToGenerateSignature(error) }
    }
    
    /// Verifies the digital signature of the provided data using the specified public key.
    ///
    /// - Parameters:
    ///   - signature: The digital signature to verify.
    ///   - data: The original data that was signed.
    ///   - publicKey: A public key conforming to `PublicKeyItem` used for verification.
    /// - Returns: A Boolean value indicating whether the signature is valid.
    /// 
    public func verify<SignatureType, PublicKeyType>(
        signature: SignatureType,
        of data: Data,
        for publicKey: PublicKeyType
    ) -> Bool where SignatureType == PublicKeyType.SignatureType, PublicKeyType : PublicKeyItem {
        publicKey.isValidSignature(signature, for: data)
    }
    
    /// Creates an authentication code (MAC) for the given data using the specified symmetric key.
    ///
    /// - Parameters:
    ///   - codeType: The authentication code algorithm type.
    ///   - data: The data for which the authentication code is generated.
    ///   - key: A symmetric key conforming to `SymmetricKeyItem` used for code generation.
    /// - Returns: A hashed code of type `HashedCodeType`.
    ///
    public func create<AlgorithmType, KeyType, HashedCodeType>(
        _ codeType: AlgorithmType.Type,
        from data: Data,
        with key: KeyType
    ) -> HashedCodeType where AlgorithmType : AuthenticationCode, KeyType == AlgorithmType.KeyType, HashedCodeType == AlgorithmType.CodeType {
        codeType.authenticationCode(for: data, using: key)
    }
    
    /// Verifies the authentication code for the provided data using the specified symmetric key.
    ///
    /// - Parameters:
    ///   - codeType: The authentication code algorithm type.
    ///   - authenticationCode: The authentication code to verify.
    ///   - data: The data to authenticate.
    ///   - key: A symmetric key conforming to `SymmetricKeyItem` used for verification.
    /// - Returns: A Boolean value indicating whether the authentication code is valid.
    ///
    public func verify<AlgorithmType, KeyType, HashedCodeType>(
        _ codeType: AlgorithmType.Type,
        authenticationCode: HashedCodeType,
        authenticating data: Data,
        using key: KeyType
    ) -> Bool where AlgorithmType : AuthenticationCode, KeyType == AlgorithmType.KeyType, HashedCodeType == AlgorithmType.CodeType {
        codeType.isValidAuthenticationCode(authenticationCode, authenticating: data, using: key)
    }
}

public enum SignatureManagerError: Error, CustomDebugStringConvertible {
    case failedToGenerateSignature(Error)
    
    public var debugDescription: String {
        switch self {
        case .failedToGenerateSignature(let error):
            "Failed to generate signature: (\(error))"
        }
    }
}
