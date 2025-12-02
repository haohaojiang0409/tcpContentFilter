//
//  ViewController.h
//  BorderControl
//
//  Created by azimgd on 13.06.2023.
//

#import <Cocoa/Cocoa.h>
#import "../Network/XPCServer.h"

@interface ViewController : NSViewController <AppCommunication>

//文本编辑框
@property (weak) IBOutlet NSTextField *textField;

@end

