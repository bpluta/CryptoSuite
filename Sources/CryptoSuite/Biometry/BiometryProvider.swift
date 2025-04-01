//
//  BiometryProvider.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import Keyrmes
import LocalAuthentication

/// A provider for handling biometric operations such as initializing a biometric context,
/// pre-authenticating, and invalidating biometric sessions.
///
/// `BiometryProvider` leverages a keychain-backed `BiometryState` to monitor and verify changes
/// in the biometric domain state. It offers helper methods to create and manage a `BiometryContext`
/// for evaluating biometric policies.
public struct BiometryProvider: Sendable {
    
    /// The current biometric state used to verify the evaluated biometric domain.
    public let biometryState: BiometryState
    
    /// Initializes a new `BiometryProvider` with the specified keychain store, domain state key,
    /// and accessibility option.
    ///
    /// - Parameters:
    ///   - keychainStore: A `KeychainStore` instance for accessing keychain data.
    ///   - domainStateKey: A keychain identifier used to store and retrieve the biometric domain state.
    ///   - accessibility: The keychain accessibility level, defaulting to `.whenUnlockedThisDeviceOnly`.
    ///
    public init(keychainStore: KeychainStore, domainStateKey: any KeychainIdentifiable, accessibility: KeychainQueryKey.Accessibility = .whenUnlockedThisDeviceOnly) {
        self.biometryState = BiometryState(
            keychainStore: keychainStore,
            domainStateKey: domainStateKey,
            accessibility: accessibility
        )
    }
    
    /// Creates and configures a new biometric context for authentication.
    ///
    /// This method initializes an `LAContext`, sets its localized prompt messages, and wraps it
    /// into a `BiometryContext` for further biometric operations.
    ///
    /// - Parameters:
    ///   - prompt: The message presented to the user during biometric authentication.
    ///   - cancelTitle: An optional title for the cancel button.
    ///   - fallbackTitle: The fallback title for button that lets user to fallback biometry authentication into passcode or password authentication
    /// - Returns: A configured `BiometryContext` ready to be used for evaluating biometric policies.
    ///
    public func initializeContext(prompt: String, cancelTitle: String? = nil, fallbackTitle: BiometryContext.Fallback = .default) -> BiometryContext {
        let laContext = LAContext()
        laContext.localizedReason = prompt
        laContext.localizedFallbackTitle = fallbackTitle.contextFallbackTitle
        laContext.localizedCancelTitle = cancelTitle
        let context = BiometryContext(context: laContext)
        return context
    }
    
    /// Invalidates the provided biometric context and dismisses its pending policy evaluation.
    ///
    /// This method ensures that the given `BiometryContext` is no longer valid for further operations.
    ///
    /// - Parameter context: The `BiometryContext` to be invalidated.
    ///
    public func invalidate(context: BiometryContext) async {
        await context.invalidate()
    }
    
    /// Performs pre-authentication for biometric operations.
    ///
    /// This method first verifies the current biometric state using `biometryState.verify(...)`,
    /// and then prompts the user for biometric authentication by evaluating the specified policy
    /// using the provided `BiometryContext`.
    ///
    /// - Parameters:
    ///   - context: The `BiometryContext` to be used for policy evaluation.
    ///   - policy: The biometric policy to evaluate, defaulting to `.biometry`.
    /// - Throws: A `BiometricOperationError` if verification or policy evaluation fails.
    ///
    public func preauthBiometry(context: BiometryContext, policy: BiometryPolicy = .biometry) async throws(BiometricOperationError) {
        try await biometryState.verify(context, with: policy)
        try await context.evaluate(policy: policy)
    }
}
