//
//  SecureKeySignable.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

public protocol SecureKeySignable {
    
    associatedtype SignatureType: SecureKeySignature
    
    func signature<D>(for digest: D) throws -> SignatureType where D : DataProtocol
}
