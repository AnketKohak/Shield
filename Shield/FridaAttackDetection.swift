//
//  FridaAttackDetection.swift
//  Shield
//
//  Created by Anket Kohak on 09/03/25.
//

import Foundation
import Darwin
import UIKit
import ObjectiveC
import QuartzCore

final class FridaDetector {
    
    // MARK: - Detection Methods
    
    static func isFridaInstalled() -> Bool {
        let paths = [
            "/usr/sbin/frida-server",
            "/usr/lib/frida/frida-agent.dylib",
            "/Library/LaunchDaemons/re.frida.server.plist",
            "/tmp/frida.socket"
        ]
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }
    
    static func isFridaPortOpen() -> Bool {
        let ports: [in_port_t] = [27042, 27043, 63521]
        for port in ports {
            var sockaddr = sockaddr_in()
            sockaddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sockaddr.sin_family = sa_family_t(AF_INET)
            sockaddr.sin_port = UInt16(port).bigEndian
            sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1")
            
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            guard sock >= 0 else { continue }
            
            let result = withUnsafePointer(to: &sockaddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            
            if result == 0 {
                close(sock)
                return true
            }
            close(sock)
        }
        return false
    }
    
    static func isFridaProcessRunning() -> Bool {
        let processes = [
            "frida-server",
            "frida-helper",
            "frida"
        ]
        let bufferSize = Int(MAXPATHLEN)
        let nameBuffer = UnsafeMutablePointer<CChar>.allocate(capacity: bufferSize)
        defer { nameBuffer.deallocate() }
        
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var procSize = 0
        sysctl(&mib, UInt32(mib.count), nil, &procSize, nil, 0)
        
        let procCount = procSize / MemoryLayout<kinfo_proc>.size
        guard procCount > 0 else { return false }
        
        let procList = UnsafeMutablePointer<kinfo_proc>.allocate(capacity: procCount)
        defer { procList.deallocate() }
        
        sysctl(&mib, UInt32(mib.count), procList, &procSize, nil, 0)
        
        for i in 0..<procCount {
            let proc = procList[Int(i)]
            var pid = proc.kp_proc.p_pid
            if pid == 0 { continue }
            
            memset(nameBuffer, 0, bufferSize)
            procname(pid, nameBuffer, bufferSize)
            let processName = String(cString: nameBuffer)
            
            if processes.contains(processName) {
                return true
            }
        }
        return false
    }
    
    static func isFridaDbusPresent() -> Bool {
        let message = "AUTH\r\n".data(using: .utf8)!
        let ports: [in_port_t] = [27042, 27043]
        
        for port in ports {
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            guard sock >= 0 else { continue }
            
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = UInt16(port).bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            
            let connectResult = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard connectResult == 0 else { continue }
            
            _ = message.withUnsafeBytes { send(sock, $0.baseAddress, message.count, 0) }
            
            var response = [UInt8](repeating: 0, count: 1024)
            let bytesRead = recv(sock, &response, response.count, 0)
            close(sock)
            
            if bytesRead > 0, String(bytes: response, encoding: .utf8)?.contains("REJECTED") == true {
                return true
            }
        }
        return false
    }
    
    static func isFridaEnvPresent() -> Bool {
        guard let env = getenv("FRIDA_") else { return false }
        return String(cString: env).contains("FRIDA")
    }
    
    static func isFridaNamedPipePresent() -> Bool {
        let dir = opendir("/tmp")
        defer { closedir(dir) }
        
        while let entry = readdir(dir) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                String(cString: UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self))
            }
            if name.hasPrefix("frida-") { return true }
        }
        return false
    }
    
    static func denyDebugger() {
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        sysctl(&mib, 4, &info, &size, nil, 0)
        
        if (info.kp_proc.p_flag & P_TRACED) != 0 {
            exit(0)
        }
        
        let ptracePtr = dlsym(dlopen(nil, RTLD_NOW), "ptrace")
        typealias PtraceType = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
        let ptrace = unsafeBitCast(ptracePtr, to: PtraceType.self)
        _ = ptrace(PT_DENY_ATTACH, 0, 0, 0)
    }
    
    static func isMethodSwizzled() -> Bool {
        guard let originalMethod = class_getInstanceMethod(
            UIViewController.self,
            #selector(UIViewController.viewDidLoad)
        ), let swappedMethod = class_getInstanceMethod(
            UIViewController.self,
            #selector(UIViewController.viewDidLoad)
        ) else { return false }
        
        return originalMethod != swappedMethod
    }
    
    static func detectTimingAttack() -> Bool {
        let startTime = CACurrentMediaTime()
        _ = (0...1000).map { $0 * $0 }
        return CACurrentMediaTime() - startTime > 0.001
    }
    
    // MARK: - Combined Detection
    
    static func performAdvancedDetection() -> Bool {
        let checks: [() -> Bool] = [
            isFridaInstalled,
            isFridaPortOpen,
            isFridaProcessRunning,
            isFridaDbusPresent,
            isFridaEnvPresent,
            isFridaNamedPipePresent,
            isMethodSwizzled,
            detectTimingAttack
        ]
        
        for check in checks.shuffled() {
            if check() {
                // Take action: exit, crash, or report
                exit(0)
                return true
            }
        }
        return false
    }
    
    // MARK: - Memory Scan (Requires Bridging Header)
    /*
     Add to Bridging Header:
     #import <mach-o/dyld.h>
     #import <string.h>
     
     Implement in C file:
     bool scanMemoryForFrida() {
         const char *fridaStrings[] = {"FridaGadget", "frida-agent", "gum-js-loop"};
         uint32_t count = _dyld_image_count();
         
         for (uint32_t i = 0; i < count; i++) {
             const struct mach_header *header = _dyld_get_image_header(i);
             const char *name = _dyld_get_image_name(i);
             intptr_t slide = _dyld_get_image_vmaddr_slide(i);
             
             // Mach-O parsing logic here
         }
         return false;
     }
     */
}

// MARK: - Usage
// Call early in application lifecycle
//FridaDetector.denyDebugger()
//_ = FridaDetector.performAdvancedDetection()
