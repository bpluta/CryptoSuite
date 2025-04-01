//
//  SecureKeyConvertible+SecKey.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

public extension SecureKeyConvertible {
    var secKey: SecKey { get throws(KeyConversionError) {
        var error: Unmanaged<CFError>?
        let query = secKeyCreateQuery
        let data = dataRepresentation as NSData
        guard let secKey = SecKeyCreateWithData(data, query, &error) else {
            throw .unableToCreateKeyFromUnderlyingData
        }
        return secKey
    }}
    
    var secKeyCreateQuery: NSDictionary {
        KeychainQueryBuilder()
            .set(attributeKeyType: Self.secKeyQueryKeyType)
            .set(attributeKeyClass: .private)
            .buildQuery()
    }
}
