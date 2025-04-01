//
//  HashedAuthenticationCode.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import CryptoKit

extension CryptoKit.HashedAuthenticationCode: HashedCode {
    public var data: Data {
        Data(self)
    }
}
