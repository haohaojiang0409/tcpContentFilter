//
//  const.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/12/11.
//

#pragma once

#pragma mark - Process

//存储进程路径的最大长度
#define PROC_PIDPATHINFO_MAXSIZE 1025

#pragma mark - Log

//日志文件最大字节数
#define LOG_FILE_MAXSIZE (10 * 1024 * 1024) //10MB

// 方向
typedef NS_ENUM(NSUInteger, FlowDirection) {
    FlowDirectionOutbound,
    FlowDirectionInbound
};

// 协议
typedef NS_ENUM(NSUInteger, TransportProtocol) {
    TransportProtocolTCP,
    TransportProtocolUDP,
    TransportProtocolICMP,
    TransportProtocolUnknown
};

