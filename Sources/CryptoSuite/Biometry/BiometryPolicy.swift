//
//  BiometryPolicy.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation
import LocalAuthentication

public enum BiometryPolicy: String, Sendable {
    case passwordOrBiometry
    case biometry
    #if os(macOS)
    case appleWatch
    case biometryOrAppleWatch
    #endif
    
    var policyType: LAPolicy {
        switch self {
        case .passwordOrBiometry:
            return .deviceOwnerAuthentication
        case .biometry:
            return .deviceOwnerAuthenticationWithBiometrics
        #if os(macOS)
        case .appleWatch:
            return .deviceOwnerAuthenticationWithWatch
        case .biometryOrAppleWatch:
            return .deviceOwnerAuthenticationWithBiometricsOrWatch
        #endif
        }
    }
}

extension BiometryPolicy: CustomStringConvertible {
    public var description: String { rawValue }
}
