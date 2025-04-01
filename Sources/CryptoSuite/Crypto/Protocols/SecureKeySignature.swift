//
//  SecureKeySignature.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

public protocol SecureKeySignature {
    
    var rawRepresentation: Data { get }
    
    init<D>(rawRepresentation: D) throws where D : DataProtocol
}
