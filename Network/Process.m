//
//  Process.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/9.
//
// Process.m
#import "Process.h"
#include <bsm/libbsm.h>
#include <libproc.h>
#include <CommonCrypto/CommonDigest.h>

@interface Process ()
//进程核心数据
@property (nonatomic) ProcessCoreData coreData;

@property (nonatomic, assign) BOOL pathResolved;
@property (nonatomic, assign) BOOL signatureComputed;
@property (nonatomic, assign) BOOL hashComputed;
@end

@implementation Process

- (instancetype)initWithFlowMetadata:(NSData *)metadata {
    if (self = [super init]) {
        // 1. 从 metadata 提取 audit token
        if (metadata.length != 32) {
            NSLog(@"Invalid audit token size");
            return self;
        }
        
        audit_token_t auditToken;
        memcpy(&auditToken, metadata.bytes, 32);
        _coreData.pid = audit_token_to_pid(auditToken);
        
        // 2. 获取基础信息（可能失败）
        proc_name(_coreData.pid, _coreData.name, sizeof(_coreData.name));
        proc_pidpath(_coreData.pid, _coreData.processPath, sizeof(_coreData.processPath));
        
        _sha256HashStr = [self sha256HashForFilePath:_coreData.processPath];
        
        NSString* str = [NSString stringWithUTF8String:_coreData.processPath];
        _infoPlist = [self codeSignatureInfoForExecutableAtPath:str];
        
        // 3. Bundle ID 需要从签名或系统接口获取，不能用 mainBundle！
        // （mainBundle 是你自己的 Extension，不是目标进程！）
        // 暂时留空，后续从签名中提取
    }
    //打印日志
    [self logAllProperties];
    return self;
}

#pragma mark -- 进程文件哈希值
- (NSString *)sha256HashForFilePath:(const char *)filePath {
    if (!filePath || strlen(filePath) == 0) {
        NSLog(@"file Path is null");
        return nil;
    }
    
    NSString *filePathStr = [NSString stringWithUTF8String:filePath];
    NSData *fileData = [NSData dataWithContentsOfFile:filePathStr];
    return [self sha256HashForData:fileData];
}

#pragma mark -- 计算NSData的哈希值
- (NSString *)sha256HashForData:(NSData *)data {
    if (!data) {
        return nil;
    }
    
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", hash[i]];
    }
    return [hex copy];
}
#pragma mark - 获取进程的apple签发数字签名
-(NSDictionary *)codeSignatureInfoForExecutableAtPath:(NSString *)exePath{
    if(!exePath || ![[NSFileManager defaultManager] fileExistsAtPath:exePath]){
        return nil;
    }
    //1.创建 SecStaticCode 对象
    SecStaticCodeRef staticCode = NULL;
    CFURLRef url = (__bridge CFURLRef)([NSURL fileURLWithPath:exePath]);
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    
    if(status != errSecSuccess){
        NSLog(@"SecStaticCodeCreateWithPath failed : %ld" , (long)status);
        return nil;
    }
    //2.获取签名信息
    CFDictionaryRef info = NULL;
    status = SecCodeCopySigningInformation(staticCode, kSecCSRequirementInformation | kSecCSSigningInformation ,&info );
    NSDictionary * result = nil;
    if(status == errSecSuccess && info){
        result = (__bridge_transfer NSDictionary*)info;
    }
    CFRelease(staticCode);
    return result;
}

#pragma mark -- 日志打印
- (void)logAllProperties {
    NSLog(@"=== Process Info ===");
    
    // 基础信息
    NSLog(@"Bundle Identifier: %@", self.bundleIdentifier ?: @"(null)");
    NSLog(@"Process ID (PID): %d", (int)self.coreData.pid);
    NSLog(@"Process Name: %s", self.coreData.name ? :"(null)");
    
    // 路径信息
    NSLog(@"Executable Path: %s", self.coreData.processPath ?: "(null)");
    
    // 安全属性
    NSLog(@"SHA-256 Hash: %@", self.sha256HashStr ?: @"(null)");
    NSLog(@"Code Signature Summary:");
    
    if (self.sha256HashStr) {
        NSLog(@"  - Raw Signature: %@", self.sha256HashStr);
    } else {
        NSLog(@"  - (No signature info)");
    }
    
    // Info.plist 内容（简略）
    if (self.infoPlist && [self.infoPlist count] > 0) {
        NSLog(@"Info.plist Keys: %@", [self.infoPlist allKeys]);
    } else {
        NSLog(@"Info.plist: (null or empty)");
    }
    
    NSLog(@"====================\n");
}
@end
