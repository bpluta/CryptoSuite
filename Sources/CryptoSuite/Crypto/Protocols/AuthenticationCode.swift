//
//  AuthenticationCode.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

public protocol AuthenticationCode {
    
    associatedtype H: HashFunction
    
    associatedtype CodeType: HashedCode
    
    associatedtype KeyType: SymmetricKeyItem
    
    static func authenticationCode<D>(for data: D, using key: KeyType) -> CodeType where D : DataProtocol
    
    static func isValidAuthenticationCode<D>(_ authenticationCode: CodeType, authenticating authenticatedData: D, using key: KeyType) -> Bool where D : DataProtocol
}
