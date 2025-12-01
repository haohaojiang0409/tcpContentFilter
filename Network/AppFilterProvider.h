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

//@interface AppFilterProvider : NEFilterDataProvider
//
//+ (void)initialize;
//@end

@interface AppFilterProvider : NEFilterDataProvider
+ (void)handlePacketwithContext: (NEFilterPacketContext *_Nonnull) context
                    fromInterface: (nw_interface_t _Nonnull) interface
                        direction: (NETrafficDirection) direction
                     withRawBytes: (const void *_Nonnull) packetBytes
                        length: (const size_t) packetLength;
@end
