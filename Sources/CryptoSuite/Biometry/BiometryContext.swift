//
//  BiometryContext.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import LocalAuthentication

/// An actor that wraps a LocalAuthentication context to provide a simplified interface for biometric operations.
public actor BiometryContext {
    nonisolated let context: LAContext
    
    /// Creates a new BiometryContext with the given LocalAuthentication context.
    ///
    /// - Parameter context: An instance of LAContext to be wrapped.
    ///
    public init(context: LAContext) {
        self.context = context
    }
    
    /// Returns the current evaluated biometric domain state as Data.
    ///
    /// This property fetches the `evaluatedPolicyDomainState` from the underlying LAContext,
    /// which reflects changes in biometric enrollments. If the domain state is unavailable,
    /// a `BiometricOperationError.noEvaluatedDomainState` error is thrown.
    ///
    public var evaluatedBiometryDomainState: Data? {
        get throws(BiometricOperationError) {
            guard let currentDomainState = context.evaluatedPolicyDomainState else {
                throw .noEvaluatedDomainState
            }
            return currentDomainState
        }
    }
    
    /// Invalidates the underlying LAContext and dismisses pending evaluation.
    ///
    /// Call this method when the biometric context is no longer needed to ensure that it cannot be used further.
    ///
    public func invalidate() {
        context.invalidate()
    }
    
    /// Evaluates the specified biometric policy.
    ///
    /// This method uses the underlying LAContext to prompt the user for biometric authentication
    /// based on the provided policy. If the evaluation fails, a `BiometricOperationError.policyEvaluationFailure` is thrown.
    ///
    /// - Parameter policy: The biometric policy to evaluate. Defaults to `.biometry`.
    /// - Throws: A `BiometricOperationError` if policy evaluation fails.
    ///
    public func evaluate(policy: BiometryPolicy = .biometry) async throws(BiometricOperationError) {
        do {
            try await context.evaluatePolicy(policy.policyType, localizedReason: context.localizedReason)
        } catch {
            let error = BiometryError(from: error as NSError)
            throw .policyEvaluationFailure(error: error)
        }
    }
    
    /// Determines whether the specified biometric policy can be evaluated.
    ///
    /// This method checks if the underlying LAContext is capable of evaluating the given policy.
    /// If the policy cannot be evaluated, a `BiometricOperationError.cannotEvaluate` error is thrown.
    ///
    /// - Parameter policy: The biometric policy to check. Defaults to `.biometry`.
    /// - Returns: `true` if the policy can be evaluated.
    /// - Throws: A `BiometricOperationError` if the biometric policy cannot be evaluated.
    ///
    @discardableResult
    public func canEvaluate(policy: BiometryPolicy = .biometry) throws(BiometricOperationError) -> Bool {
        var error: NSError?
        let canEvaluatePolicy = context.canEvaluatePolicy(policy.policyType, error: &error)
        guard canEvaluatePolicy else {
            let error = BiometryError(from: error)
            throw .cannotEvaluate(policy: policy, error: error)
        }
        return canEvaluatePolicy
    }
}

extension BiometryContext {
    /// This enum defines fallback button presentation settings
    public enum Fallback {
        /// This options elimintates the fallback behavior meaning that it hides fallback option from the user interace
        case none
        /// This option sets default - system provided titles for fallback button
        case `default`
        /// This option sets a custom title to fallback button
        case custom(String)
        
        var contextFallbackTitle: String? {
            switch self {
            case .none:
                return ""
            case .default:
                return nil
            case .custom(let fallback):
                return fallback
            }
        }
    }
}

extension LAContext: @unchecked @retroactive Sendable { }
