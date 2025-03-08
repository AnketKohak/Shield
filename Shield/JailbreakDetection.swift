import UIKit
import Darwin
import Foundation
import Security


struct JailbreakDetector {
    
    static func isDeviceCompromised() -> Bool {
        return checkSuspiciousFiles() ||
        checkJailbreakSchemes() ||
        checkUnrestrictedWriteAccess() ||
        checkSymbolicLinkAnomalies() ||
        checkSuspiciousDynamicLibraries() ||
        checkSandboxIntegrity() ||
        checkJailbreakEnvironment()
    }
    
    // MARK: - File System Checks
    private static func checkSuspiciousFiles() -> Bool {
        let jailbreakFiles = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/usr/sbin/sshd",
            "/bin/bash",
            "/etc/apt",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/var/log/syslog",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/stash"
        ]
        
        return jailbreakFiles.contains { path in
            FileManager.default.fileExists(atPath: path)
        }
    }
    
    // MARK: - URL Scheme Checks
    private static func checkJailbreakSchemes() -> Bool {
        let jailbreakSchemes = [
            "cydia://",
            "sileo://",
            "zbra://",
            "undecimus://"
        ]
        
        return jailbreakSchemes.contains { scheme in
            guard let url = URL(string: scheme) else { return false }
            return UIApplication.shared.canOpenURL(url)
        }
    }
    
    // MARK: - Write Permission Check
    private static func checkUnrestrictedWriteAccess() -> Bool {
        let testPath = "/private/" + UUID().uuidString
        do {
            try "test_write".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
    
    // MARK: - Symbolic Link Analysis
    private static func checkSymbolicLinkAnomalies() -> Bool {
        let systemPaths = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/include"
        ]
        
        return systemPaths.contains { path in
            do {
                let destination = try FileManager.default.destinationOfSymbolicLink(atPath: path)
                return !destination.hasPrefix("/var/stash")
            } catch {
                return false
            }
        }
    }
    
    // MARK: - Dynamic Library Inspection
    private static func checkSuspiciousDynamicLibraries() -> Bool {
        let suspiciousDylibs = [
            "SubstrateLoader",
            "libhooker",
            "CydiaSubstrate",
            "cynject",
            "Electra",
            "FridaGadget",
            "LibertyLite"
        ]
        
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let libraryName = String(cString: imageName).lowercased()
            
            for dylib in suspiciousDylibs {
                if libraryName.contains(dylib.lowercased()) {
                    return true
                }
            }
        }
        return false
    }
    
    // MARK: - Sandbox Integrity Check
    private static func checkSandboxIntegrity() -> Bool {
        let sandboxTestFile = "/private/" + UUID().uuidString
        let testContent = "sandbox_test".data(using: .utf8)
        
        if FileManager.default.createFile(atPath: sandboxTestFile, contents: testContent) {
            do {
                try FileManager.default.removeItem(atPath: sandboxTestFile)
                return true
            } catch {
                return false
            }
        }
        return false
    }
    
    // MARK: - Environment Check
    private static func checkJailbreakEnvironment() -> Bool {
        let envIndicators = [
            "DYLD_INSERT_LIBRARIES",
            "CYDIA",
            "SSLSPILL",
            "SubstrateLoader"
        ]
        
        return envIndicators.contains { indicator in
            getenv(indicator) != nil
        }
    }
}

// MARK: - Usage Example
extension JailbreakDetector {
    static func performSecurityCheck() {
        DispatchQueue.global().async {
            if isDeviceCompromised() {
                DispatchQueue.main.async {
                    handleSecurityBreach()
                }
            }
        }
    }
    
    private static func handleSecurityBreach() {
        // Implement your security response
        let alert = UIAlertController(
            title: "Security Alert",
            message: "This device is compromised",
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(
            title: "OK",
            style: .destructive,
            handler: { _ in
                // Consider graceful degradation instead of exit
                UIApplication.shared.perform(#selector(NSXPCConnection.suspend))
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    exit(EXIT_FAILURE)
                }
            }
        ))
        
        if let rootVC = UIApplication.shared.keyWindow?.rootViewController {
            rootVC.present(alert, animated: true)
        }
    }
}
