//
//  AppFilterProvider.h
//  Network
//
//  Created by azimgd on 13.06.2023.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "Rule.h"
#import "tools.h"
#import "XPCServer.h"
#import "log.h"
#import "DomainIPCache.h"
#import "RulePollingManager.h"
//@interface AppFilterProvider : NEFilterDataProvider
//
//+ (void)initialize;
//@end

static os_log_t _Nonnull firewallLog;

@interface AppFilterProvider : NEFilterDataProvider

@end
