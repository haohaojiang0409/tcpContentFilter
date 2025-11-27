//
//  AppFilterProvider.h
//  Network
//
//  Created by azimgd on 13.06.2023.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "Rule.h"
static NSMutableDictionary<NSString *, NSString *> *gIPToHostnameMap;
static dispatch_once_t onceToken;

@interface AppFilterProvider : NEFilterDataProvider

+ (void)initialize;
@end
