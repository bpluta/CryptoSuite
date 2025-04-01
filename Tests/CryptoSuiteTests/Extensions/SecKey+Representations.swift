//
//  SecKey+Representations.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import Security

extension SecKey {
    var privateKeyTokenRepresentation: Data? {
        (SecKeyCopyAttributes(self) as? [String: Any])?["toid"] as? Data
    }
    
    var privateKeyExternalRepresentation: Data {
        var error: Unmanaged<CFError>?
        let externalRepresentation = SecKeyCopyExternalRepresentation(self, &error) as Data?
        return externalRepresentation!
    }
    
    var publicKeyExternalRepresentation: Data {
        let publicKey = SecKeyCopyPublicKey(self)!
        var error: Unmanaged<CFError>?
        let externalRepresentation = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
        return externalRepresentation!
    }
}
