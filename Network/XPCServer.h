//
//  XPCServer.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/1.
//

#ifndef XPCServer_H
#define XPCServer_H


#import <Foundation/Foundation.h>
#import "AppFilterProvider.h"
#import <os/log.h>


@protocol AppCommunication<NSObject>
// This method shows the information about a packet on the UI
- (void)showTextMessageWithMessage:(NSString *_Nonnull)message
                 completionHandler:(void (^_Nonnull)(bool success))reply;
@end

@protocol ProviderCommunication<NSObject>

-(void)registerWithCompletionHandler:(void (^_Nonnull)(bool success))completionHandler;

@end


@interface IPCConnection : NSObject<NSXPCListenerDelegate>
//保存监听器实例
@property (nonatomic , retain) NSXPCListener* _Nonnull listener;
//连接保存
@property (nonatomic , retain) NSXPCConnection* _Nullable connection;

@property(nonatomic, weak) NSObject<AppCommunication> *_Nullable delegate;

+(IPCConnection* _Nonnull)shared;

-(void)startListener;

/// This method is called by SimplePcap app to register with the IPC provider running in the system extension.
- (void)registerWithExtension:(NSBundle *_Nonnull)bundle
              withDelegate:(NSObject<AppCommunication> *_Nonnull)delegate
     withCompletionHandler:(void (^_Nonnull)(bool success))completionHandler;

- (BOOL)listener:(NSXPCListener *_Nonnull)listener
    shouldAcceptNewConnection:(NSXPCConnection *_Nonnull)newConnection;

- (void)registerWithCompletionHandler:(void (^_Nonnull)(bool success))completionHandler;

-(void)sendStr:(NSString*_Nonnull)str whthCompletionHandler:(void (^_Nonnull)(bool success))reply;
@end

#endif
