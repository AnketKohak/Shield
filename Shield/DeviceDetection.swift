//
//  DeviceDetection.swift
//  Shield
//
//  Created by Protectt_intern on 06/03/25.
//

import Foundation
import UIKit
import Darwin

struct DeviceDetector {
    private static let deviceMapping: [String: String] = [
        // MARK: - iPhones
        "iPhone1,1": "iPhone",
        "iPhone1,2": "iPhone 3G",
        "iPhone2,1": "iPhone 3GS",
        "iPhone3,1": "iPhone 4", "iPhone3,2": "iPhone 4", "iPhone3,3": "iPhone 4",
        "iPhone4,1": "iPhone 4s",
        "iPhone5,1": "iPhone 5 (GSM)", "iPhone5,2": "iPhone 5 (CDMA)",
        "iPhone5,3": "iPhone 5c (GSM)", "iPhone5,4": "iPhone 5c (Global)",
        "iPhone6,1": "iPhone 5s (GSM)", "iPhone6,2": "iPhone 5s (Global)",
        "iPhone7,1": "iPhone 6 Plus", "iPhone7,2": "iPhone 6",
        "iPhone8,1": "iPhone 6s", "iPhone8,2": "iPhone 6s Plus",
        "iPhone8,4": "iPhone SE (1st gen)",
        "iPhone9,1": "iPhone 7 (CDMA)", "iPhone9,3": "iPhone 7 (GSM)",
        "iPhone9,2": "iPhone 7 Plus (CDMA)", "iPhone9,4": "iPhone 7 Plus (GSM)",
        "iPhone10,1": "iPhone 8 (CDMA)", "iPhone10,4": "iPhone 8 (GSM)",
        "iPhone10,2": "iPhone 8 Plus (CDMA)", "iPhone10,5": "iPhone 8 Plus (GSM)",
        "iPhone10,3": "iPhone X (CDMA)", "iPhone10,6": "iPhone X (GSM)",
        "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max", "iPhone11,6": "iPhone XS Max (China)",
        "iPhone11,8": "iPhone XR",
        "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro", "iPhone12,5": "iPhone 11 Pro Max",
        "iPhone12,8": "iPhone SE (2nd gen)",
        "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
        "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
        "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
        "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
        "iPhone14,6": "iPhone SE (3rd gen)",
        "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
        "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
        "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
        "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
        
        // MARK: - iPads
        "iPad1,1": "iPad (1st gen)",
        "iPad2,1": "iPad 2 (Wi-Fi)", "iPad2,2": "iPad 2 (GSM)", "iPad2,3": "iPad 2 (CDMA)", "iPad2,4": "iPad 2 (Mid 2012)",
        "iPad3,1": "iPad (3rd gen)", "iPad3,2": "iPad (3rd gen)", "iPad3,3": "iPad (3rd gen)",
        "iPad3,4": "iPad (4th gen)", "iPad3,5": "iPad (4th gen)", "iPad3,6": "iPad (4th gen)",
        "iPad4,1": "iPad Air (Wi-Fi)", "iPad4,2": "iPad Air (Cellular)", "iPad4,3": "iPad Air (China)",
        "iPad5,3": "iPad Air 2 (Wi-Fi)", "iPad5,4": "iPad Air 2 (Cellular)",
        "iPad6,11": "iPad (5th gen)", "iPad6,12": "iPad (5th gen)",
        "iPad7,5": "iPad (6th gen)", "iPad7,6": "iPad (6th gen)",
        "iPad7,11": "iPad (7th gen)", "iPad7,12": "iPad (7th gen)",
        "iPad11,6": "iPad (8th gen)", "iPad11,7": "iPad (8th gen)",
        "iPad12,1": "iPad (9th gen)", "iPad12,2": "iPad (9th gen)",
        "iPad13,18": "iPad Air (5th gen)", "iPad13,19": "iPad Air (5th gen)",
        "iPad14,1": "iPad mini (6th gen)", "iPad14,2": "iPad mini (6th gen)",
        "iPad13,1": "iPad Pro 11\" (3rd gen)", "iPad13,2": "iPad Pro 11\" (3rd gen)",
        "iPad13,4": "iPad Pro 12.9\" (5th gen)", "iPad13,5": "iPad Pro 12.9\" (5th gen)",
        
        // MARK: - iPod Touches
        "iPod1,1": "iPod touch (1st gen)",
        "iPod2,1": "iPod touch (2nd gen)",
        "iPod3,1": "iPod touch (3rd gen)",
        "iPod4,1": "iPod touch (4th gen)",
        "iPod5,1": "iPod touch (5th gen)",
        "iPod7,1": "iPod touch (6th gen)",
        "iPod9,1": "iPod touch (7th gen)",
        
        // MARK: - Simulators
        "x86_64": "Simulator", "arm64": "Simulator"
    ]
    
    static func getDeviceModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        let identifier = machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        
        // Handle simulator detection
        if identifier == "x86_64" || identifier == "arm64" {
            if let simIdentifier = ProcessInfo().environment["SIMULATOR_MODEL_IDENTIFIER"] {
                return deviceMapping[simIdentifier] ?? "Unknown Simulator Device"
            }
        }
        
        return deviceMapping[identifier] ?? "Unknown Device"
    }
}

//// Usage example:
//let deviceName = DeviceDetector.getDeviceModel()
//print("Current device: \(deviceName)")
