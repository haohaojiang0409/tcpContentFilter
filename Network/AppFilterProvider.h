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
#import <os/log.h>
//@interface AppFilterProvider : NEFilterDataProvider
//
//+ (void)initialize;
//@end

static os_log_t _Nullable firewallLog;

@interface AppFilterProvider : NEFilterDataProvider
+ (void)handlePacketwithContext: (NEFilterPacketContext *_Nonnull) context
                    fromInterface: (nw_interface_t _Nonnull) interface
                        direction: (NETrafficDirection) direction
                     withRawBytes: (const void *_Nonnull) packetBytes
                        length: (const size_t) packetLength;
@end
