//
//  KeyTests.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Testing
@testable import CryptoSuite

@Suite("Key tests")
struct KeyTests {
    var keyFactory: SecureKeyFactory = SecureKeyGenerator()
    var signatureWorker: SignatureWorker = SignatureManager()
    
#if targetEnvironment(simulator)
    private static let isRunningOnSimulator = true
#else
    private static let isRunningOnSimulator = false
#endif
    
    @Test("Key without authentication context")
    func testKeyGeneration() async throws {
        let key: MockKeyItem = try keyFactory.generateKey(with: nil)
        #expect(!key.isWithAuthenticationContext)
    }
    
    @Test("Key with authentication context", .disabled(if: isRunningOnSimulator, "Key generation with authentication context does not work on simulator"))
    func testContextKeyGeneration() throws {
        let key: MockKeyItem = try keyFactory.generateKey(with: BiometryContext(context: LAContext()))
        #expect(key.isWithAuthenticationContext)
    }
    
    @Test("Externally generated signature verification", arguments: [
        (
            signatureOfAlice: "MEYCIQC+3+TYDWQvHDeOoAi0UxW7CWFplnrgjrc5xJEbU8aRCgIhANX4ZkuwLSb9w0+2Wa38gZ7iFIEjThHvOtdj2HnG/Zc+",
            signatureOfBob: "MEQCIAKSnPqtwqBJFfrU/bXTMXKvz2ptk6Xufnaf6p1gH9SdAiAtoKZEJLNTdQDw0GeWnbnfUaaHnNtJMtLVMbHwcf8vmg=="
        ), (
            signatureOfAlice: "MEYCIQDSDfa68f8aEzSqhLdB4ALTz8FMglAL03kSgulU+ZpdYQIhAJZKmwlZ8m8bgv/8puK6eRcVUh9MNwOyxY8EARCf1V/5",
            signatureOfBob: "MEYCIQCG3Km8K2U0vhye8frpq2xnEx6PAgwKMZWSnWB2XxJVvAIhAPyjVl2/ugoJ6KosGHHV0lHYkz7c/PxYpDPpISEgm2Zf"
        ), (
            signatureOfAlice: "MEYCIQCDQd3TEJ/RE+sxiWlekgUoSTFdz49jxvBiMgDQlyZV7gIhANcNv5nHjaWtjy2NUlpsSUp/CQuDXTMYrDCmU2WbYRO2",
            signatureOfBob: "MEQCICDT2njVYvN62J2Yah/39TB4az+2IzzSwhQY/PDTCbXQAiBF872YwZqlkqcaY/QzbN/QsFmURu9VEFP/0WpvaPdVvQ=="
        ),(
            signatureOfAlice: "MEUCIQDpbEVsbrxHe9hRTJbBfnesQNKYWdOmT+OcZTIaUFt4KgIgJrTS9GCGhJ9Yt/bodYWrf/Au712oTVbc2HH9QwyVACg=",
            signatureOfBob: "MEQCIEMSSqdK0ss+1KlBhKan2RPL77Q+s2OxdVt3aDT8C4VDAiBpo+Zfua5CFcQPMcNNM8Uk9a8/pstXLL0uYoOpQxslHQ=="
        ),(
            signatureOfAlice: "MEYCIQC82S4thS9SXMh3sx4cB3NbznOUlll2wAmrE0apVWFl3gIhAP8k4mP4mEsbHnhCFKfYWFzTy6YPH/a2iTFawXVK2yh/",
            signatureOfBob: "MEUCIQDRtcZiG4bx/QdmvA6RVGz4OnArv//oAQqCsiJ1Nwew1gIgURAuqc7SghLxTBgPEaDRuLNoGqVBJCPv/bXH8ioNsAc="
        )
    ])
    func testExternalSignatureValidation(singatureOfAlice: String, signatureOfBob: String) {
        #expect(singatureOfAlice != signatureOfBob)
        
        func isValid(signature: String, of data: Data, for publicKey: String) -> Bool {
            let derSignatureRepresentation = Data(base64Encoded: signature.data(using: .utf8)!)!
            let signature = try! P256.Signing.ECDSASignature(derRepresentation: derSignatureRepresentation)
            
            let pemPublicKeyRepresentation = String(data: Data(base64Encoded: publicKey.data(using: .utf8)!)!, encoding: .utf8)!
            let publicKey = try! P256.Signing.PublicKey(pemRepresentation: pemPublicKeyRepresentation)
            
            let isSignatureValid = signatureWorker.verify(signature: signature, of: data, for: publicKey)
            
            return isSignatureValid
        }
        
        let isSignatureOfAliceValidForHerPublicKey = isValid(signature: singatureOfAlice, of: data, for: aliceEncodedPublicKey)
        let isSignatureOfAliceValidForBobsPublicKey = isValid(signature: singatureOfAlice, of: data, for: bobEncodedPublicKey)
        
        #expect(isSignatureOfAliceValidForHerPublicKey, "Signature of Alice: \"\(singatureOfAlice)\" should pass validation for a public key of Alice")
        #expect(!isSignatureOfAliceValidForBobsPublicKey, "Signature of Alice: \"\(singatureOfAlice)\" should not pass validation for a public key of Bob")
        
        let isSignatureOfBobValidForHisPublicKey = isValid(signature: singatureOfAlice, of: data, for: aliceEncodedPublicKey)
        let isSignatureOfBobValidForAlicesPublicKey = isValid(signature: singatureOfAlice, of: data, for: bobEncodedPublicKey)
        
        #expect(isSignatureOfBobValidForHisPublicKey, "Signature of Bob: \"\(signatureOfBob)\" should pass validation for a public key of Bob")
        #expect(!isSignatureOfBobValidForAlicesPublicKey, "Signature of Bob: \"\(signatureOfBob)\" should not pass validation for a public key of Alice")
    }
    
    @Test("Internally generated signature validation")
    mutating func testInternalSignatureValidation() throws {
        keyFactory = SecureKeyGenerator()
        let signatureManager = SignatureManager()
        let privateKey: P256.Signing.PrivateKey = try keyFactory.generateKey(with: nil)
        let publicKey = privateKey.publicKey
        
        let properMessageData = data
        let wrongMessageData = String("Lorem ipsum dolor sit amet".reversed()).data(using: .utf8)!
        
        let properSignature = try signatureManager.sign(data: properMessageData, with: privateKey)
        let wrongSignature = try signatureManager.sign(data: wrongMessageData, with: privateKey)
        let isProperSignatureValid = signatureManager.verify(signature: properSignature, of: properMessageData, for: publicKey)
        let isWrongSignatureValid = signatureManager.verify(signature: wrongSignature, of: properMessageData, for: publicKey)
        
        #expect(properSignature.rawRepresentation.count == 64)
        #expect(isProperSignatureValid)
        #expect(!isWrongSignatureValid)
    }
    
    @Test("Signature uniqueness")
    mutating func testSignatureUniqueness() throws {
        keyFactory = SecureKeyGenerator()
        let signatureManager = SignatureManager()
        
        let privateKey: P256.Signing.PrivateKey = try keyFactory.generateKey(with: nil)
        
        let signature1 = try signatureManager.sign(data: data, with: privateKey)
        let signature2 = try signatureManager.sign(data: data, with: privateKey)
        
        #expect(signature1.rawRepresentation.count == 64)
        #expect(signature1.rawRepresentation != signature2.rawRepresentation, "Signatures should be unique")
    }
    
    @Test("HMAC validation")
    func testHMACValidation() {
        let signatureManager = SignatureManager()
        let remoteKey = symmetricKey
        let hashAlgorithm = HMAC<SHA256>.self
        
        let signature = signatureManager.create(hashAlgorithm, from: data, with: remoteKey)
        let isValid = signatureManager.verify(hashAlgorithm, authenticationCode: signature, authenticating: data, using: remoteKey)
        
        #expect(remoteKey.bitCount == 256)
        #expect(signature.data.count == 32)
        #expect(isValid)
    }
    
    @Test("HMAC uniqueness")
    func testHMACUniqueness() {
        let signatureManager = SignatureManager()
        let remoteKey = symmetricKey
        let hashAlgorithm = HMAC<SHA256>.self
        
        let signature1 = signatureManager.create(hashAlgorithm, from: data, with: remoteKey)
        let signature2 = signatureManager.create(hashAlgorithm, from: data, with: remoteKey)
        
        #expect(remoteKey.bitCount == 256)
        #expect(signature1.data.count == 32)
        #expect(signature1.data == signature2.data, "Signatures should be unique")
    }
}

// MARK: - Initial setup data
extension KeyTests {
    /// This property represents an example data to be processed by crypto operations
    private var data: Data { "Lorem ipsum dolor sit amet".data(using: .utf8)! }
    
    private var aliceEncodedPrivateKey: String { "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1dEdjBLUGlCRFEvSTNLbzMKQ1NsQ2VkcXI5V0p3RWw1RE1oNDZJKzVoMTh5aFJBTkNBQVN4dTVySzFxNTk4NzFKc2dFV2k1eEQ5L1pDSnhieApBUFN6emJXdE9kZy81d2puWkNWclNkUVBLNWUvT0ZPa1FwcWZ5R2d2dGNSa0NWb2doaUNnM3l4UwotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
    }
    private var aliceEncodedPublicKey: String { "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFc2J1YXl0YXVmZk85U2JJQkZvdWNRL2YyUWljVwo4UUQwczgyMXJUbllQK2NJNTJRbGEwblVEeXVYdnpoVHBFS2FuOGhvTDdYRVpBbGFJSVlnb044c1VnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
    }
    
    private var bobEncodedPrivateKey: String { "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1I1emU0QUthM3hock1ycmwKZldERklEc3RFNG9vT2ZrWU1Pc3EwMUZ1ZW1taFJBTkNBQVJGanN5YkpvTzRHTksxN2Z2YzNtWWVONHRsYUVmbAp6SnZjTnpCT1pXWjlRWHBVUXpjUjROR2NWYVJQU3ZuUXJ5RzArRitjcWpLNVFlQmJ0VVVJd2xQRgotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
    }
    private var bobEncodedPublicKey: String { "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFUlk3TW15YUR1QmpTdGUzNzNONW1IamVMWldoSAo1Y3liM0Rjd1RtVm1mVUY2VkVNM0VlRFJuRldrVDByNTBLOGh0UGhmbktveXVVSGdXN1ZGQ01KVHhRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
    }
    
    private var symmetricKeyString: String { "LLhO9ekwoHAJ5FDRHBl7BmYwHqPoeyuo677kl6WuisU=" }
    private var symmetricKey: SymmetricKey {
        SymmetricKey(data: Data(base64Encoded: symmetricKeyString.data(using: .utf8)!)!)
    }
}

// MARK: - Mock implementations
actor MockKeyStorage: KeyStorage {
    
    var storage: [String:Data] = [:]
    
    var hasStored = false
    var hasRead = false
    var hasDeleted = false
    
    func storeKey<KeyType>(_ key: KeyType, identifier: any Keyrmes.KeychainIdentifiable, isAuthenticationRequired: Bool) async throws where KeyType : SecureKeyConvertible {
        hasStored = true
    }
    
    func readKey<T>(identifier: KeychainIdentifiable, authenticationContext: BiometryContext?) throws -> T? where T : SecureKeyConvertible {
        guard let data = storage[identifier.keychainLabel] else { return nil }
        hasRead = true
        return try T(dataRepresentation: data, authenticationContext: authenticationContext?.context)
    }
    
    func deleteKey(identifier: KeychainIdentifiable) throws {
        storage.removeValue(forKey: identifier.keychainLabel)
        hasDeleted = true
    }
    
}

struct MockSignature: SecureKeySignature {
    var rawRepresentation: Data
    
    init<D>(rawRepresentation: D) throws where D : DataProtocol {
        self.rawRepresentation = rawRepresentation as! Data
    }
}

class MockKeyItem: SecureKeyItem {
    
    var dataHasBeenSigned = false
    var isWithAuthenticationContext: Bool
    var dataRepresentation: Data
    
    static var secKeyQueryKeyType: Keyrmes.KeychainQueryKey.KeyType { .ECSECPrimeRandom }
    
    required init(secKey: SecKey, authenticationContext: LAContext?) throws(CryptoSuite.KeyConversionError) {
        fatalError("not supported")
    }
    
    required init(dataRepresentation: Data, authenticationContext: LAContext?) throws {
        self.dataRepresentation = dataRepresentation
        self.isWithAuthenticationContext = authenticationContext != nil
    }
    
    required init(compactRepresentable: Bool, accessControl: SecAccessControl, authenticationContext: LAContext?) throws {
        self.dataRepresentation = Data()
        self.isWithAuthenticationContext = authenticationContext != nil
    }
    
    func signature<D>(for digest: D) throws -> MockSignature where D : DataProtocol {
        let signature = try MockSignature(rawRepresentation: digest)
        dataHasBeenSigned = true
        return signature
    }
}
