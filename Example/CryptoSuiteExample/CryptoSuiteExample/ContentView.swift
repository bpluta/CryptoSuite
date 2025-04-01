//
//  ContentView.swift
//  CryptoSuiteExample
//
//  Created by Bartłomiej Pluta
//

import SwiftUI
import CryptoSuite
@preconcurrency import CryptoKit

struct KeyManager: Sendable {
    let keyStorage: SecureKeyStorage
    let keyGenerator: SecureKeyGenerator
    let signatureManager: SignatureManager
    
    typealias KeyType = P256
    
    init(keychainStore: KeychainStore) {
        self.keyStorage = SecureKeyStorage(
            keychainStore: keychainStore,
            accessibility: .whenUnlocked
        )
        self.keyGenerator = SecureKeyGenerator()
        self.signatureManager = SignatureManager()
    }
    
    func generateKey(context: BiometryContext) async throws {
        let key: KeyType.KeyAgreement.PrivateKey = try keyGenerator.generateKey(with: context)
        try await keyStorage.storeKey(key, identifier: KeychainItem.privateKey, isAuthenticationRequired: true)
    }
    
    func signMessageWithPrivateKey(context: BiometryContext?) async throws -> KeyType.Signing.PrivateKey.SignatureType {
        guard let privateKey: KeyType.Signing.PrivateKey = try await keyStorage.readKey(
            identifier: KeychainItem.privateKey,
            authenticationContext: context
        ) else { throw KeyError.missingKey }
        
        let messageToSign = "My message".data(using: .utf8)!
        let signature = try signatureManager.sign(data: messageToSign, with: privateKey)
        return signature
    }
    
    func verify(signature: KeyType.Signing.PrivateKey.SignatureType, context: BiometryContext) async throws -> Bool {
        guard let privateKey: KeyType.Signing.PrivateKey = try await keyStorage.readKey(
            identifier: KeychainItem.privateKey,
            authenticationContext: context
        ) else { throw KeyError.missingKey }
        
        let messageToSign = "My message".data(using: .utf8)!
        let isValid = signatureManager.verify(signature: signature, of: messageToSign, for: privateKey.publicKey)
        return isValid
    }
    
    enum KeyError: Error {
        case missingKey
    }
}

struct BiometryManager {
    let biometryProvider: BiometryProvider
    
    init(keychainStore: KeychainStore) {
        self.biometryProvider = BiometryProvider(
            keychainStore: keychainStore,
            domainStateKey: KeychainItem.biometryDomainState,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
    }
    
    func initializeContext() -> BiometryContext {
        biometryProvider.initializeContext(prompt: "Here is my prompt message")
    }
    
    func invalidate(context: BiometryContext) async {
        await biometryProvider.invalidate(context: context)
    }
    
    func preauth(context: BiometryContext) async throws {
        try await biometryProvider.preauthBiometry(context: context)
    }
}

enum KeychainItem: String, KeychainIdentifiable {
    case biometryDomainState
    case privateKey
    
    var keychainLabel: String { rawValue }
}

struct ContentView: View {
    @StateObject private var viewModel = ViewModel()
    
    var body: some View {
        VStack(spacing: 40) {
            Button(action: {
                Task { await initializeContext() }
            }) {
                Text("Initialize biometry context")
            }
            Button(action: {
                Task { await preauthContext() }
            }){
                Text("Preauth biometry context")
            }
            Button(action: {
                Task { await invalidateContext() }
            }) {
                Text("Invalidate biometry context")
            }
            Button(action: {
                Task { await generateNewKey() }
            }) {
                Text("Generate new key")
            }
            Button(action: {
                Task { await signMessage() }
            }) {
                Text("Sign message")
            }
            Button(action: {
                Task { await wipeoutKeychain() }
            }) {
                Text("Wipe out keychain")
            }
        }
        .padding()
    }
    
    func initializeContext() async {
        viewModel.biometryContext = viewModel.biometry.initializeContext()
    }
    
    func preauthContext() async {
        guard let biometryContext = getBiometryContext() else { return }
        do {
            try await viewModel.biometry.preauth(context: biometryContext)
        } catch let error {
            print("Biomery preauth failed: \(error)")
        }
    }
    
    func invalidateContext() async {
        guard let biometryContext = getBiometryContext() else { return }
        await viewModel.biometry.invalidate(context: biometryContext)
        viewModel.biometryContext = nil
    }
    
    func generateNewKey() async {
        guard let biometryContext = getBiometryContext() else { return }
        do {
            try await viewModel.biometry.preauth(context: biometryContext)
        } catch let error {
            print("Biomery preauth failed: \(error)")
        }
        do {
            try await viewModel.keyManager.generateKey(context: biometryContext)
        } catch let error {
            print("Key generation failed: \(error)")
        }
    }
    
    func signMessage() async {
        let biometryContext = getBiometryContext()
        do {
            let signature = try await viewModel.keyManager.signMessageWithPrivateKey(context: biometryContext)
            print("Base64 signature: \(signature.derRepresentation.base64EncodedString())")
        } catch let error {
            print("Singature generation failed: \(error)")
        }
    }
    
    func wipeoutKeychain() async {
        do {
            try await viewModel.keychainStore.wipeOutStorage()
        } catch let error {
            print("Keychain wipeout failed: \(error)")
        }
    }
    
    func getBiometryContext() -> BiometryContext? {
        guard let biometryContext = viewModel.biometryContext else {
            print("Missing biometry context")
            return nil
        }
        return biometryContext
    }
}

extension ContentView {
    class ViewModel: ObservableObject {
        @Published var biometryContext: BiometryContext?
        
        let keychainStore: KeychainStore
        let biometry: BiometryManager
        let keyManager: KeyManager
        
        init() {
            let keychainStore = KeychainStore()
            self.biometry = BiometryManager(keychainStore: keychainStore)
            self.keyManager = KeyManager(keychainStore: keychainStore)
            self.keychainStore = keychainStore
        }
    }
}

#Preview {
    ContentView()
}
