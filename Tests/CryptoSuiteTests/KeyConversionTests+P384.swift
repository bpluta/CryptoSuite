//
//  KeyConversionTests+P384.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Testing
@testable import CryptoSuite

@Suite("P384 key conversion and interoperability")
struct KeyConversionTestsP384 {
    
    // MARK: - P384 Key Agreement Keys
    @Test
    func testP384KeyAgreementSecKeyBackwardConversion() throws {
        typealias KeyType = P384.KeyAgreement.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyExternalRepresentation == somePrivateKey.x963Representation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testP384KeyAgreementSecKeyForwardConversion() throws {
        typealias KeyType = P384.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 384)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyExternalRepresentation == newKey.x963Representation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }
    
    @Test
    func testP384KeyAgreementBackwardAndForwardConversion() throws {
        typealias KeyType = P384.KeyAgreement.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP384KeyAgreementBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = P384.KeyAgreement.PrivateKey
        typealias OuptutKeyType = P384.Signing.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP384KeyAgreementBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = P384.KeyAgreement.PrivateKey
        typealias OuptutKeyType = P256.Signing.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        try #require(performing: {
            try OuptutKeyType(secKey: secKey)
        }, throws: { error in
            guard case .failedToRetrieveSecureKeyInstanceFromRawRepresentation(_) = error as? KeyConversionError else { return false }
            return true
        })
    }
    
    @Test
    func testP384KeyAgreementForwardAndBackwardConversion() throws {
        typealias KeyType = P384.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 384)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyExternalRepresentation == restoredKey.privateKeyExternalRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
    
    // MARK: - P384 Signing Keys
    @Test
    func testP384SigningSecKeyBackwardConversion() throws {
        typealias KeyType = P384.Signing.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyExternalRepresentation == somePrivateKey.x963Representation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testP384SigningSecKeyForwardConversion() throws {
        typealias KeyType = P384.Signing.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 384)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyExternalRepresentation == newKey.x963Representation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }

    @Test
    func testP384SigningBackwardAndForwardConversion() throws {
        typealias KeyType = P384.Signing.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP384SigningBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = P384.Signing.PrivateKey
        typealias OuptutKeyType = P384.KeyAgreement.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP384SigningBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = P384.Signing.PrivateKey
        typealias OuptutKeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        try #require(performing: {
            try OuptutKeyType(secKey: secKey)
        }, throws: { error in
            guard case .failedToRetrieveSecureKeyInstanceFromRawRepresentation(_) = error as? KeyConversionError else { return false }
            return true
        })
    }

    @Test
    func testP384SigningForwardAndBackwardConversion() throws {
        typealias KeyType = P384.Signing.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 384)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyExternalRepresentation == restoredKey.privateKeyExternalRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
}
