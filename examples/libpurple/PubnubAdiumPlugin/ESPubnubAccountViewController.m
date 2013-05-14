//
//  ESPubnubAccountViewController.m
//  PubnubAdiumPlugin
//
//  Created by Alexey Yesipenko on 5/9/13.
//  Copyright (c) 2013 Alexey Yesipenko. All rights reserved.
//

#import <Adium/AIAccount.h>
#import <AdiumLibpurple/SLPurpleCocoaAdapter.h>
#import "ESPubnubAccountViewController.h"
#include "pubnub_options.h"
#include <libpurple/account.h>

@implementation ESPubnubAccountViewController

-(NSString *)nibName
{
    return @"ESPubnubAccountView";
}

- (void)configureForAccount:(AIAccount *)inAccount
{
    [super configureForAccount:inAccount];
    
    NSString *publish = [account preferenceForKey:@OPTION_PUBLISH_KEY group:GROUP_ACCOUNT_STATUS] ?: @DEFAULT_PUBLISH_KEY;
    [_textField_publish setStringValue:publish];
    NSString *subscribe = [account preferenceForKey:@OPTION_SUBSCRIBE_KEY group:GROUP_ACCOUNT_STATUS] ?: @DEFAULT_SUBSCRIBE_KEY;
    [_textField_subscribe setStringValue:subscribe];
    NSString *history = [account preferenceForKey:@OPTION_HISTORY_N group:GROUP_ACCOUNT_STATUS];
    [_textField_history setIntegerValue:(history? [history intValue] :DEFAULT_HISTORY_N)];
    NSString *origin = [account preferenceForKey:@OPTION_ORIGIN_SERVER group:GROUP_ACCOUNT_STATUS] ?: @DEFAULT_ORIGIN_SERVER;
    [_textField_origin setStringValue:origin];
    NSString *secret = [account preferenceForKey:@OPTION_SECRET_KEY group:GROUP_ACCOUNT_STATUS] ?: @DEFAULT_SECRET_KEY;
    [_textField_secret setStringValue:secret];
    NSString *cipher = [account preferenceForKey:@OPTION_CIPHER_KEY group:GROUP_ACCOUNT_STATUS] ?: @DEFAULT_CIPHER_KEY;
    [_textField_cipher setStringValue:cipher];
    
}

- (void)saveConfiguration
{
    [super saveConfiguration];
    
    PurpleAccount *pAccount = accountLookupFromAdiumAccount((CBPurpleAccount*)account);
    NSString *publish = [_textField_publish stringValue];
    [account setPreference:publish forKey:@OPTION_PUBLISH_KEY group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(pAccount, OPTION_PUBLISH_KEY, [publish UTF8String]);
    NSString *subscribe = [_textField_subscribe stringValue];
    [account setPreference:subscribe forKey:@OPTION_SUBSCRIBE_KEY group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(pAccount, OPTION_SUBSCRIBE_KEY, [subscribe UTF8String]);
    NSNumber *history = [NSNumber numberWithInteger:[_textField_history integerValue]];
    [account setPreference:history forKey:@OPTION_HISTORY_N group:GROUP_ACCOUNT_STATUS];
    purple_account_set_int(pAccount, OPTION_HISTORY_N, [history intValue]);
    NSString *origin = [_textField_origin stringValue];
    [account setPreference:origin forKey:@OPTION_ORIGIN_SERVER group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(pAccount, OPTION_ORIGIN_SERVER, [origin UTF8String]);
    NSString *secret = [_textField_secret stringValue];
    [account setPreference:secret forKey:@OPTION_SECRET_KEY group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(pAccount, OPTION_SECRET_KEY, [secret UTF8String]);
    NSString *cipher = [_textField_cipher stringValue];
    [account setPreference:cipher forKey:@OPTION_CIPHER_KEY group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(pAccount, OPTION_CIPHER_KEY, [cipher UTF8String]);
}

- (NSView *)privacyView
{
    return nil;
}

@end
