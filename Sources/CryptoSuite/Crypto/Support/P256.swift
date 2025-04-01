//
//  P256.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Keyrmes
import CryptoKit

extension CryptoKit.P256.Signing.PublicKey: PublicKeyItem { }

extension CryptoKit.P256.Signing.ECDSASignature: SecureKeySignature { }

extension CryptoKit.P256.KeyAgreement.PrivateKey: SecureKeyConvertible {
    public init(secKey: SecKey, authenticationContext: LAContext? = nil) throws(KeyConversionError) {
        guard let data = SecKeyCopyExternalRepresentation(secKey, nil) as Data? else {
            throw .unableToExtractKeyAttributes
        }
        do {
            try self.init(dataRepresentation: data, authenticationContext: authenticationContext)
        } catch { throw .failedToRetrieveSecureKeyInstanceFromRawRepresentation(error) }
    }
    
    public init(dataRepresentation: Data, authenticationContext: LAContext?) throws {
        try self.init(x963Representation: dataRepresentation)
    }
    
    public init(compactRepresentable: Bool, accessControl: SecAccessControl, authenticationContext: LAContext?) throws {
        self.init(compactRepresentable: compactRepresentable)
    }
    
    public var dataRepresentation: Data {
        x963Representation
    }
    
    public static var secKeyQueryKeyType: KeychainQueryKey.KeyType {
        .ECSECPrimeRandom
    }
}

extension CryptoKit.P256.Signing.PrivateKey: SecureKeyItem {
    public init(secKey: SecKey, authenticationContext: LAContext? = nil) throws(KeyConversionError) {
        guard let data = SecKeyCopyExternalRepresentation(secKey, nil) as Data? else {
            throw .unableToExtractKeyAttributes
        }
        do {
            try self.init(dataRepresentation: data, authenticationContext: authenticationContext)
        } catch { throw .failedToRetrieveSecureKeyInstanceFromRawRepresentation(error) }
    }
    
    public init(dataRepresentation: Data, authenticationContext: LAContext?) throws {
        try self.init(x963Representation: dataRepresentation)
    }
    
    public init(compactRepresentable: Bool, accessControl: SecAccessControl, authenticationContext: LAContext?) throws {
        self.init(compactRepresentable: compactRepresentable)
    }
    
    public var dataRepresentation: Data {
        x963Representation
    }
    
    public static var secKeyQueryKeyType: KeychainQueryKey.KeyType {
        .ECSECPrimeRandom
    }
}
