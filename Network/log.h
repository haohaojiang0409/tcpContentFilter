//
//  log.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/4.
//

#import <os/log.h>
#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN

@interface LogManager : NSObject

+ (os_log_t)firewallLog;

+ (void)info:(NSString *)message, ...;
+ (void)error:(NSString *)message, ...;
+ (void)debug:(NSString *)message, ...;

@end

NS_ASSUME_NONNULL_END

