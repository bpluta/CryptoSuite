//
//  BiometryState.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import Keyrmes
import LocalAuthentication

/// An actor that manages the biometric domain state by interfacing with a keychain store.
public actor BiometryState {
    
    let keychainStore: KeychainStore
    let domainStateKey: any KeychainIdentifiable
    let accessibility: KeychainQueryKey.Accessibility
    
    /// Initializes a new `BiometryState` instance.
    ///
    /// - Parameters:
    ///   - keychainStore: The keychain store used to persist and retrieve the biometric domain state.
    ///   - domainStateKey: A unique keychain identifier used as the key for storing the biometric state.
    ///   - accessibility: The keychain accessibility attribute to use when storing the biometric state.
    ///
    public init(keychainStore: KeychainStore, domainStateKey: any KeychainIdentifiable, accessibility: KeychainQueryKey.Accessibility) {
        self.keychainStore = keychainStore
        self.domainStateKey = domainStateKey
        self.accessibility = accessibility
    }
    
    /// Verifies that the current biometric domain state matches the stored state.
    ///
    /// This method checks whether the provided `BiometryContext` can evaluate the specified biometric policy,
    /// then compares its current domain state with the state stored in the keychain. If no state is stored, it saves the current state.
    /// If the states do not match, it updates the stored state and throws an error indicating the biometric state has changed.
    ///
    /// - Parameters:
    ///   - biometryContext: The context providing the current biometric domain state.
    ///   - policy: The biometric policy to be evaluated.
    /// - Throws: A `BiometricOperationError` if evaluation fails or if the biometric state has changed.
    ///
    public func verify(_ biometryContext: BiometryContext, with policy: BiometryPolicy) async throws(BiometricOperationError) {
        try await biometryContext.canEvaluate(policy: policy)
        let currentBiometryDomain = try await biometryContext.evaluatedBiometryDomainState
        guard let storedBiometryDomainState = try await getCurrentBiometryDomainState() else {
            try await setCurrentBiometryDomain(to: currentBiometryDomain)
            return
        }
        guard currentBiometryDomain == storedBiometryDomainState else {
            try await setCurrentBiometryDomain(to: currentBiometryDomain)
            throw BiometricOperationError.biometryStateHasChanged
        }
        return
    }
    
    /// Resets the stored biometric domain state.
    ///
    /// This method clears the stored biometric state in the keychain by deleting the associated key.
    ///
    /// - Throws: A `BiometricOperationError` if resetting the state fails.
    ///
    public func reset() async throws(BiometricOperationError) {
        try await setCurrentBiometryDomain(to: nil)
    }
}

extension BiometryState {
    private func setCurrentBiometryDomain(to newValue: Data?) async throws(BiometricOperationError) {
        do {
            if let newValue {
                try await keychainStore.set(identifier: domainStateKey, to: newValue, accessibility: accessibility)
            } else {
                try await keychainStore.delete(identifier: domainStateKey)
            }
        } catch { throw .couldNotSetBiometryDomainState(error: error) }
    }
    
    private func getCurrentBiometryDomainState() async throws(BiometricOperationError) -> Data? {
        do {
            let currentDomainState: Data? = try await keychainStore.read(identifier: domainStateKey)
            return currentDomainState
        } catch { throw .couldNotRetrieveCurrentBiometryDomainState(error: error) }
    }
}
