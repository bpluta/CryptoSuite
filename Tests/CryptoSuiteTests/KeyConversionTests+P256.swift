//
//  KeyConversionTests+P256.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Testing
@testable import CryptoSuite

@Suite("P256 key conversion and interoperability")
struct KeyConversionTestsP256 {
    
    // MARK: - Secure enclave P256 Key Agreement Keys
    @Test
    func testSecureEnclaveP256KeyAgreementSecKeyBackwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        let somePrivateKey = try KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyTokenRepresentation == somePrivateKey.dataRepresentation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testSecureEnclaveP256KeyAgreementSecKeyForwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newSecureEnclaveKey(bits: 256, biometryProtected: false)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyTokenRepresentation == newKey.dataRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }
    
    @Test
    func testSecureEnclaveP256KeyAgreementBackwardAndForwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        let somePrivateKey = try KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.dataRepresentation == restoredKey.dataRepresentation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testSecureEnclaveP256KeyAgreementBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        typealias OuptutKeyType = SecureEnclave.P256.Signing.PrivateKey
        let somePrivateKey = try InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.dataRepresentation == restoredKey.dataRepresentation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testSecureEnclaveP256KeyAgreementBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        typealias OuptutKeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = try InitialKeyType()
        let secKey = try somePrivateKey.secKey
        try #require(performing: {
            try OuptutKeyType(secKey: secKey)
        }, throws: { error in
            guard case .unableToExtractKeyAttributes = error as? KeyConversionError else { return false }
            return true
        })
    }
    
    @Test
    func testSecureEnclaveP256KeyAgreementForwardAndBackwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newSecureEnclaveKey(bits: 256, biometryProtected: false)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyTokenRepresentation == restoredKey.privateKeyTokenRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
    
    // MARK: - Secure enclave P256 Signing Keys
    @Test
    func testSecureEnclaveP256SigningSecKeyBackwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.Signing.PrivateKey
        let somePrivateKey = try KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyTokenRepresentation == somePrivateKey.dataRepresentation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testSecureEnclaveP256SigningSecKeyForwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.Signing.PrivateKey
        let somePrivateKey = SecKey.newSecureEnclaveKey(bits: 256, biometryProtected: false)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyTokenRepresentation == newKey.dataRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }

    @Test
    func testSecureEnclaveP256SigningBackwardAndForwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.Signing.PrivateKey
        let somePrivateKey = try KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.dataRepresentation == restoredKey.dataRepresentation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testSecureEnclaveP256SigningBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = SecureEnclave.P256.Signing.PrivateKey
        typealias OuptutKeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        let somePrivateKey = try InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.dataRepresentation == restoredKey.dataRepresentation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testSecureEnclaveP256SigningBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = SecureEnclave.P256.Signing.PrivateKey
        typealias OuptutKeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = try InitialKeyType()
        let secKey = try somePrivateKey.secKey
        try #require(performing: {
            try OuptutKeyType(secKey: secKey)
        }, throws: { error in
            guard case .unableToExtractKeyAttributes = error as? KeyConversionError else { return false }
            return true
        })
    }
    
    @Test
    func testSecureEnclaveP256SigningForwardAndBackwardConversion() throws {
        typealias KeyType = SecureEnclave.P256.Signing.PrivateKey
        let somePrivateKey = SecKey.newSecureEnclaveKey(bits: 256, biometryProtected: false)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyTokenRepresentation == restoredKey.privateKeyTokenRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
    
    // MARK: - Plain P256 Key Agreement Keys
    @Test
    func testP256KeyAgreementSecKeyBackwardConversion() throws {
        typealias KeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyExternalRepresentation == somePrivateKey.x963Representation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testP256KeyAgreementSecKeyForwardConversion() throws {
        typealias KeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 256)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyExternalRepresentation == newKey.x963Representation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }
    
    @Test
    func testP256KeyAgreementBackwardAndForwardConversion() throws {
        typealias KeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP256KeyAgreementBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = P256.KeyAgreement.PrivateKey
        typealias OuptutKeyType = P256.Signing.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP256KeyAgreementBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = P256.KeyAgreement.PrivateKey
        typealias OuptutKeyType = SecureEnclave.P256.Signing.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        try #require(performing: {
            try OuptutKeyType(secKey: secKey)
        }, throws: { error in
            guard case .missingKeyTokenIdentifier = error as? KeyConversionError else { return false }
            return true
        })
    }
    
    @Test
    func testP256KeyAgreementForwardAndBackwardConversion() throws {
        typealias KeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 256)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyExternalRepresentation == restoredKey.privateKeyExternalRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
    
    // MARK: - Plain P256 Signing Keys
    @Test
    func testP256SigningSecKeyBackwardConversion() throws {
        typealias KeyType = P256.Signing.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        #expect(secKey.privateKeyExternalRepresentation == somePrivateKey.x963Representation)
        #expect(secKey.publicKeyExternalRepresentation == somePrivateKey.publicKey.x963Representation)
    }
    
    @Test
    func testP256SigningSecKeyForwardConversion() throws {
        typealias KeyType = P256.Signing.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 256)
        let newKey = try KeyType(secKey: somePrivateKey)
        #expect(somePrivateKey.privateKeyExternalRepresentation == newKey.x963Representation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == newKey.publicKey.x963Representation)
    }

    @Test
    func testP256SigningBackwardAndForwardConversion() throws {
        typealias KeyType = P256.Signing.PrivateKey
        let somePrivateKey = KeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try KeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP256SigningBackwardAndForwardWithOtherCompatibleTypeConversion() throws {
        typealias InitialKeyType = P256.Signing.PrivateKey
        typealias OuptutKeyType = P256.KeyAgreement.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        let restoredKey = try OuptutKeyType(secKey: secKey)
        #expect(somePrivateKey.x963Representation == restoredKey.x963Representation)
        #expect(somePrivateKey.publicKey.x963Representation == restoredKey.publicKey.x963Representation)
    }
    
    @Test
    func testP256SigningBackwardAndForwardWithOtherNonCompatibleTypeConversion() throws {
        typealias InitialKeyType = P256.Signing.PrivateKey
        typealias OuptutKeyType = SecureEnclave.P256.KeyAgreement.PrivateKey
        let somePrivateKey = InitialKeyType()
        let secKey = try somePrivateKey.secKey
        try #require(performing: {
            try OuptutKeyType(secKey: secKey)
        }, throws: { error in
            guard case .missingKeyTokenIdentifier = error as? KeyConversionError else { return false }
            return true
        })
    }

    @Test
    func testP256SigningForwardAndBackwardConversion() throws {
        typealias KeyType = P256.Signing.PrivateKey
        let somePrivateKey = SecKey.newKey(bits: 256)
        let newKey = try KeyType(secKey: somePrivateKey)
        let restoredKey = try newKey.secKey
        #expect(somePrivateKey.privateKeyExternalRepresentation == restoredKey.privateKeyExternalRepresentation)
        #expect(somePrivateKey.publicKeyExternalRepresentation == restoredKey.publicKeyExternalRepresentation)
    }
}
