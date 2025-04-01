//
//  KeyConversionTests+P521.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Testing
@testable import CryptoSuite

@Suite("P521 key conversion and interoperability")
struct KeyConversionTestsP521 {
    
    // MARK: - P521 Key Agreement Keys
    @Test
    func testP521KeyAgreementSecKeyBackwardConversion() throws {
        typealias KeyType = P521.KeyAgreement.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyExternalRepresentation == somePrivateKey.x963Representation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testP521KeyAgreementSecKeyForwardConversion() throws {
        typealias KeyType = P521.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 521)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyExternalRepresentation == newKey.x963Representation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }
    
    @Test
    func testP521KeyAgreementBackwardAndForwardConversion() throws {
        typealias KeyType = P521.KeyAgreement.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP521KeyAgreementBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = P521.KeyAgreement.PrivateKey
        typealias OuptutKeyType = P521.Signing.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP521KeyAgreementBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = P521.KeyAgreement.PrivateKey
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
    func testP521KeyAgreementForwardAndBackwardConversion() throws {
        typealias KeyType = P521.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 521)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyExternalRepresentation == restoredKey.privateKeyExternalRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
    
    // MARK: - P521 Signing Keys
    @Test
    func testP521SigningSecKeyBackwardConversion() throws {
        typealias KeyType = P521.Signing.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyExternalRepresentation == somePrivateKey.x963Representation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testP521SigningSecKeyForwardConversion() throws {
        typealias KeyType = P521.Signing.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 521)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyExternalRepresentation == newKey.x963Representation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }

    @Test
    func testP521SigningBackwardAndForwardConversion() throws {
        typealias KeyType = P521.Signing.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP521SigningBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = P521.Signing.PrivateKey
        typealias OuptutKeyType = P521.KeyAgreement.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP521SigningBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = P521.Signing.PrivateKey
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
    func testP521SigningForwardAndBackwardConversion() throws {
        typealias KeyType = P521.Signing.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 521)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyExternalRepresentation == restoredKey.privateKeyExternalRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
}
