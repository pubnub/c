//
//  ESPubnubService.m
//  PubnubAdiumPlugin
//
//  Created by Alexey Yesipenko on 5/2/13.
//  Copyright (c) 2013 Alexey Yesipenko. All rights reserved.
//

#import "ESPubnubService.h"
#import "ESPurplePubnubAccount.h"
#import "ESPubnubJoinChatViewController.h"
#import "ESPubnubAccountViewController.h"

#import <Adium/AISharedAdium.h>
#import <Adium/AIStatusControllerProtocol.h>
#import <AIUtilities/AIStringUtilities.h>
#import <AIUtilities/AIImageAdditions.h>

@implementation ESPubnubService

- (Class)accountClass {
	return [ESPurplePubnubAccount class];
}

//Service Description
- (NSString *)serviceCodeUniqueID {
	return @"libpurple-pubnub";
}
- (NSString *)serviceID{
	return @"Pubnub";
}
- (NSString *)serviceClass {
	return @"Pubnub";
}
- (NSString *)shortDescription {
	return @"Pubnub";
}
- (NSString *)longDescription {
	return @"Pubnub";
}

- (NSCharacterSet *)allowedCharacters {
    NSMutableCharacterSet *allowed = [NSMutableCharacterSet alphanumericCharacterSet];
    [allowed formUnionWithCharacterSet:[NSCharacterSet  punctuationCharacterSet]];
    return allowed;
}

- (NSUInteger)allowedLength {
	return 64;
}

- (BOOL)caseSensitive {
	return NO;
}

- (BOOL)supportsPassword {
	return NO;
}

- (AIServiceImportance)serviceImportance {
	return AIServicePrimary;
}

- (NSString *)userNameLabel {
    return AILocalizedString(@"User Name", nil); // Sign-in name
}

- (void)registerStatuses {
#define ADDSTATUS(name, type) \
[adium.statusController registerStatus:name \
withDescription:[adium.statusController localizedDescriptionForCoreStatusName:name] \
ofType:type forService:self]
    
    ADDSTATUS(STATUS_NAME_AVAILABLE, AIAvailableStatusType);
    ADDSTATUS(STATUS_NAME_OFFLINE, AIOfflineStatusType);
}

- (NSImage *)defaultServiceIconOfType:(AIServiceIconType)iconType
{
    if ((iconType == AIServiceIconSmall) || (iconType == AIServiceIconList)) {
        return [NSImage imageNamed:@"pubnub_small" forClass:[self class] loadLazily:YES];
    } else {
        return [NSImage imageNamed:@"pubnub" forClass:[self class] loadLazily:YES];
    }
}

- (NSString *)pathForDefaultServiceIconOfType:(AIServiceIconType)iconType
{
    if ((iconType == AIServiceIconSmall) || (iconType == AIServiceIconList)) {
		return [[NSBundle bundleForClass:[self class]] pathForImageResource:@"pubnub_small"];
	}
	return [[NSBundle bundleForClass:[self class]] pathForImageResource:@"pubnub"];
}

- (BOOL)canCreateGroupChats
{
    return YES;
}

- (DCJoinChatViewController *)joinChatView
{
	return [ESPubnubJoinChatViewController joinChatView];
}

-(AIAccountViewController *)accountViewController
{
    return [ESPubnubAccountViewController accountViewController];
}

@end
