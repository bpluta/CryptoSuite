//
//  SecKey+NewKey.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import Security

extension SecKey {
    static func newKey(bits: Int) -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: bits,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String: false
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as NSDictionary, &error) else {
            fatalError((error!.takeRetainedValue() as Error).localizedDescription)
        }
        return privateKey
    }
    
    static func newSecureEnclaveKey(bits: Int, biometryProtected: Bool) -> SecKey {
        let flags: SecAccessControlCreateFlags = biometryProtected ? [.biometryCurrentSet, .privateKeyUsage] : [.privateKeyUsage]
        let allocator = kCFAllocatorDefault
        let accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let access = SecAccessControlCreateWithFlags(allocator, accessibility, flags, nil)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: bits,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as NSDictionary, &error) else {
            fatalError((error!.takeRetainedValue() as Error).localizedDescription)
        }
        return privateKey
    }
}
