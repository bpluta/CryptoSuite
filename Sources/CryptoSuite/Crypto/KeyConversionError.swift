//
//  KeyConversionError.swift
//  CryptoSuite
//
//  Created by Bartłomiej Pluta
//

import Foundation

public enum KeyConversionError: Error, CustomDebugStringConvertible, Sendable {
    case unableToExtractKeyAttributes
    case missingKeyTokenIdentifier
    case unableToCreateKeyFromUnderlyingData
    case failedToRetrieveSecureKeyInstanceFromRawRepresentation(Error)
    
    public var debugDescription: String {
        switch self {
        case .unableToExtractKeyAttributes:
            "Unable to extract key attributes of SecKey instance"
        case .missingKeyTokenIdentifier:
            "Missing key token identifier"
        case .unableToCreateKeyFromUnderlyingData:
            "Unable to create SecKey representation from underlying data"
        case .failedToRetrieveSecureKeyInstanceFromRawRepresentation(let error):
            "Failed to retrieve a secure key instance of type from its raw representation: (\(error.localizedDescription))"
        }
    }
}
