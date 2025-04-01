//
//  SecureKeyConvertible.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

public protocol SecureKeyConvertible {
    
    init(secKey: SecKey, authenticationContext: LAContext?) throws(KeyConversionError)
    
    init(dataRepresentation: Data, authenticationContext: LAContext?) throws
    
    init(compactRepresentable: Bool, accessControl: SecAccessControl, authenticationContext: LAContext?) throws
    
    var dataRepresentation: Data { get }
    
    var secKey: SecKey { get throws(KeyConversionError) }
    
    var secKeyCreateQuery: NSDictionary { get }
    
    static var secKeyQueryKeyType: KeychainQueryKey.KeyType { get }
}
