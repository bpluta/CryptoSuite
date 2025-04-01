//
//  BiometryError.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import Keyrmes
import LocalAuthentication

/// This type maps known LAError biometry related errors into an enum
public enum BiometryError: Error, CustomDebugStringConvertible, Sendable {
    case invalidCredentials
    case cancelledByUser
    case userDidFallbackToPassword
    case cancelledBySystem
    case passcodeNotSet
    case biometryNotAvailable
    case biometryNotEnrolled
    case biometryLockout
    case canceledByApplication
    case invalidContext
    case interactionNotAllowed
    #if os(macOS)
    case noWatchAvailable
    case biometryHasNotBeenPaired
    case biometryHasBeenDisconnected
    case invalidDimensions
    #endif
    case unknown(_ code: Int)
    case unknownError
    
    public var debugDescription: String {
        switch self {
        case .invalidCredentials:
            "User has denied to provide correct credentials"
        case .cancelledByUser:
            "Authentication has been cancelled by user"
        case .userDidFallbackToPassword:
            "User has tapped the fallback to password button"
        case .cancelledBySystem:
            "Authentication has been cancelled by system"
        case .passcodeNotSet:
            "Passcode is not set on the device"
        case .biometryNotAvailable:
            "Biometry is not available on the device"
        case .biometryNotEnrolled:
            "Biometry has no enrolled identities"
        case .biometryLockout:
            "Too many failed biometry attempts"
        case .canceledByApplication:
            "Authentication has been canceled by application"
        case .invalidContext:
            "Biometry context has been previously invalidated"
        case .interactionNotAllowed:
            "Interaction has been forbidden"
        #if os(macOS)
        case .noWatchAvailable:
            "No paired watch nearby"
        case .biometryHasNotBeenPaired:
            "No biometry accessory has been paired"
        case .biometryHasBeenDisconnected:
            "Paired biometry accessory is not connected"
        case .invalidDimensions:
            "Dimensions of embeded UI are invalid"
        #endif
        case .unknown(let errorCode):
            "Unknown error code: (\(errorCode))"
        case .unknownError:
            "Unknown error"
        }
    }
    
    init(from nsError: NSError?) {
        guard let nsError else {
            self = .unknownError
            return
        }
        switch nsError {
        case LAError.authenticationFailed:
            self = .invalidCredentials
        case LAError.userCancel:
            self = .cancelledByUser
        case LAError.userFallback:
            self = .userDidFallbackToPassword
        case LAError.systemCancel:
            self = .cancelledBySystem
        case LAError.passcodeNotSet:
            self = .passcodeNotSet
        case LAError.biometryNotAvailable:
            self = .biometryNotAvailable
        case LAError.biometryNotEnrolled:
            self = .biometryNotEnrolled
        case LAError.biometryLockout:
            self = .biometryLockout
        case LAError.appCancel:
            self = .canceledByApplication
        case LAError.invalidContext:
            self = .invalidContext
        case LAError.notInteractive:
            self = .interactionNotAllowed
        #if os(macOS)
        case LAError.watchNotAvailable:
            self = .noWatchAvailable
        case LAError.biometryNotPaired:
            self = .biometryHasNotBeenPaired
        case LAError.biometryDisconnected:
            self = .biometryHasBeenDisconnected
        case LAError.invalidDimensions:
            self = .invalidDimensions
        #endif
        default:
            self = .unknown(nsError.code)
        }
    }
}

public enum BiometricOperationError: Error, CustomDebugStringConvertible, Sendable {
    case couldNotSetBiometryDomainState(error: KeychainStoreError)
    case couldNotRetrieveCurrentBiometryDomainState(error: KeychainStoreError)
    case cannotEvaluate(policy: BiometryPolicy, error: BiometryError)
    case noEvaluatedDomainState
    case biometryStateHasChanged
    case policyEvaluationFailure(error: BiometryError)
    
    public var debugDescription: String {
        switch self {
        case .couldNotSetBiometryDomainState(let error):
            return "Could not update biometry domain state: (\(error))"
        case .couldNotRetrieveCurrentBiometryDomainState(let error):
            return "Could not retrieve current biometry domain state: (\(error))"
        case .cannotEvaluate(let policy, let error):
            return "Cannot evaluate policy \"\(policy)\": (\(error))"
        case .noEvaluatedDomainState:
            return "Biometry context coes not contain any registered domain state"
        case .biometryStateHasChanged:
            return "Biometry domain state has changed and does not match the processed one"
        case .policyEvaluationFailure(let error):
            return "Policy evaluation failed: (\(error))"
        }
    }
}
