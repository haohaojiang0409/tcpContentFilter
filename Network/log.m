//
//  log.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/4.
//

#import "log.h"

@implementation LogManager

static os_log_t _firewallLog;

+ (void)initialize {
    if (self == [LogManager class]) {
        _firewallLog = os_log_create("com.eagleyun.BorderControl",
                                     "Firewall");
    }
}

+ (os_log_t)firewallLog {
    return _firewallLog;
}

#pragma mark - Log APIs

+ (void)info:(NSString *)message, ... {
    va_list args;
    va_start(args, message);
    os_log_with_type(_firewallLog, OS_LOG_TYPE_DEFAULT, "%{public}@", [[NSString alloc] initWithFormat:message arguments:args]);
    va_end(args);
}

+ (void)error:(NSString *)message, ... {
    va_list args;
    va_start(args, message);
    os_log_with_type(_firewallLog, OS_LOG_TYPE_ERROR, "%{public}@", [[NSString alloc] initWithFormat:message arguments:args]);
    va_end(args);
}

+ (void)debug:(NSString *)message, ... {
    va_list args;
    va_start(args, message);
    os_log_with_type(_firewallLog, OS_LOG_TYPE_DEBUG, "%{public}@", [[NSString alloc] initWithFormat:message arguments:args]);
    va_end(args);
}

@end
