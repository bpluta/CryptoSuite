//
//  P256+SecureEnclave.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Keyrmes
import CryptoKit

extension CryptoKit.SecureEnclave.P256.Signing.PrivateKey: SecureKeyItem {
    public init(secKey: SecKey, authenticationContext: LAContext? = nil) throws(KeyConversionError) {
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any] else {
            throw .unableToExtractKeyAttributes
        }
        guard let tokenData = attributes["toid"] as? Data else {
            throw .missingKeyTokenIdentifier
        }
        do {
            try self.init(dataRepresentation: tokenData, authenticationContext: authenticationContext)
        } catch { throw .failedToRetrieveSecureKeyInstanceFromRawRepresentation(error) }
    }
    
    public var secKeyCreateQuery: NSDictionary {
        CryptoKit.SecureEnclave.P256.privateKeyQuery(
            token: dataRepresentation,
            keyType: Self.secKeyQueryKeyType
        )
    }
    
    public static var secKeyQueryKeyType: Keyrmes.KeychainQueryKey.KeyType {
        .ECSECPrimeRandom
    }
}

extension CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey: SecureKeyConvertible {
    public init(secKey: SecKey, authenticationContext: LAContext? = nil) throws(KeyConversionError) {
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any] else {
            throw .unableToExtractKeyAttributes
        }
        guard let tokenData = attributes["toid"] as? Data else {
            throw .missingKeyTokenIdentifier
        }
        do {
            try self.init(dataRepresentation: tokenData, authenticationContext: authenticationContext)
        } catch { throw .failedToRetrieveSecureKeyInstanceFromRawRepresentation(error) }
    }
    
    public var secKeyCreateQuery: NSDictionary {
        CryptoKit.SecureEnclave.P256.privateKeyQuery(
            token: dataRepresentation,
            keyType: Self.secKeyQueryKeyType
        )
    }
    
    public static var secKeyQueryKeyType: Keyrmes.KeychainQueryKey.KeyType {
        .ECSECPrimeRandom
    }
}

fileprivate extension CryptoKit.SecureEnclave.P256 {
    static func privateKeyQuery(token tokenRepresentation: Data, keyType: Keyrmes.KeychainQueryKey.KeyType) -> NSDictionary {
        KeychainQueryBuilder()
            .set(attributeKeyType: .ECSECPrimeRandom)
            .set(attributeKeyClass: .private)
            .set(attributeTokenID: .secureEnclave)
            .set(tokenId: tokenRepresentation)
            .buildQuery()
    }
}
