//
//  ESPubnubAccountViewController.h
//  PubnubAdiumPlugin
//
//  Created by Alexey Yesipenko on 5/9/13.
//  Copyright (c) 2013 Alexey Yesipenko. All rights reserved.
//

#import <Adium/AIAccountViewController.h>

@interface ESPubnubAccountViewController : AIAccountViewController
@property (weak) IBOutlet NSTextField *textField_publish;
@property (weak) IBOutlet NSTextField *textField_subscribe;
@property (weak) IBOutlet NSTextField *textField_history;
@property (weak) IBOutlet NSTextField *textField_origin;
@property (weak) IBOutlet NSTextField *textField_secret;
@property (weak) IBOutlet NSTextField *textField_cipher;

@end
