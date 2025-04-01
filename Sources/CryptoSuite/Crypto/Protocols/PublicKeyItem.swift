//
//  PublicKeyItem.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

public protocol PublicKeyItem {
    
    associatedtype SignatureType: SecureKeySignature
    
    var x963Representation: Data { get }
    
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    
    func isValidSignature<D>(_ signature: SignatureType, for data: D) -> Bool where D : DataProtocol
}
