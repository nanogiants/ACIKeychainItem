/*
-------------------------------------------------------------------------------
The MIT License (MIT)

Copyright (c) 2015 appcom interactive GmbH. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
-------------------------------------------------------------------------------
*/

#import "ACIKeychainItem.h"
#import <Security/Security.h>

@implementation ACIKeychainItem

- (id)initWithIdentifier:(NSString *)identifier accessGroup:(NSString *)accessGroup
{
    NSAssert(identifier != nil, @"identifier has to be set.");
    self = [super init];
    if (self) {
        _identifier = identifier;
        
#if !TARGET_IPHONE_SIMULATOR
        // Don't use access group on simulator.
        _accessGroup = accessGroup;
#endif
    }
    return self;
}

- (BOOL)insertData:(NSData *)data forSecType:(ACIKeychainItemSecType)type
{
    NSMutableDictionary *query = [self createQuery];
    
    CFTypeRef cftype = [ACIKeychainItem attrTypeForKeychainItemSecType:type];
    
    if (cftype == NULL) return NO;
    
    query[(__bridge id)cftype] = data;
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    
    return (errSecSuccess == status);
}

- (BOOL)updateData:(NSData *)data forSecType:(ACIKeychainItemSecType)type
{
    NSMutableDictionary *query = [self createQuery];
    NSMutableDictionary *update =[[NSMutableDictionary alloc] init];
    CFTypeRef cftype = [ACIKeychainItem attrTypeForKeychainItemSecType:type];
    
    if (cftype == NULL) return NO;
    
    update[(__bridge id)cftype] = data;
    
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    
    return (errSecSuccess == status);
}

- (BOOL)insertOrUpdateData:(NSData *)data forSecType:(ACIKeychainItemSecType)type
{
    NSMutableDictionary *query = [self createQuery];
    
    CFTypeRef cftype = [ACIKeychainItem attrTypeForKeychainItemSecType:type];
    
    if (cftype == NULL) return NO;
    
    query[(__bridge id)cftype] = data;
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    
    // if item already exists - try to update
    if (status == errSecDuplicateItem) {
        NSMutableDictionary *update =[[NSMutableDictionary alloc] init];
        update[(__bridge id)cftype] = data;
        
        status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    }
    
    return (errSecSuccess == status);
}

- (NSData *)dataForSecType:(ACIKeychainItemSecType)type
{
    NSMutableDictionary *query = [self createQuery];
    CFTypeRef cftype = [ACIKeychainItem attrTypeForKeychainItemSecType:type];
    
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    
    // we need to gather data differently than other values
    if (type == ACIKeychainItemSecTypeData) {
        query[(__bridge id)kSecReturnData] = (id)kCFBooleanTrue;
    } else {
        query[(__bridge id)kSecReturnAttributes] = (id)kCFBooleanTrue;
    }

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    
    // if we failed - just memory management and return
    if (status != errSecSuccess) {
        if (result != NULL) CFRelease(result);
        return nil;
    }
    
    // if we gathered data, get them and return
    if (type == ACIKeychainItemSecTypeData) {
        NSData *data = [(__bridge NSData *)result copy];
        CFRelease(result);
        return data;
    }
    
    // receive the data from the results
    id data = [(__bridge NSDictionary *)result objectForKey:(__bridge id)cftype];
    
    CFRelease(result);
    
    // convert any strings to data
    if ([data isKindOfClass:[NSString class]]) {
        return [data dataUsingEncoding:NSUTF8StringEncoding];
    }
    
    return data;
}

- (BOOL)remove
{
    NSMutableDictionary *query = [self createQuery];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    return (errSecSuccess == status);
}

// we create a bundleSeedID generic value to gather the bundleSeedID from keychain
+ (NSString *)bundleSeedID
{
    NSDictionary *query = @{
                            (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrGeneric : @"bundleSeedID",
                            (__bridge id)kSecAttrService : @"",
                            (__bridge id)kSecReturnAttributes : (id)kCFBooleanTrue
                            };
    
    CFDictionaryRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status == errSecItemNotFound)
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status != errSecSuccess)
        return nil;
    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge NSData *)kSecAttrGeneric];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [components firstObject];
    CFRelease(result);
    return bundleSeedID;
}

#pragma mark - Private

- (NSMutableDictionary *)createQuery
{
    NSData *identifier = [self.identifier dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrService] = identifier;
    
    if (self.accessGroup) query[(__bridge id)kSecAttrAccessGroup] = self.accessGroup;
    
    return query;
}

// returns corresponding cftype
+ (CFTypeRef)attrTypeForKeychainItemSecType:(ACIKeychainItemSecType)type
{
    switch (type)
    {
        case ACIKeychainItemSecTypeAccount:
            return kSecAttrAccount;
            break;
            
        case ACIKeychainItemSecTypeData:
            return kSecValueData;
            break;
            
        case ACIKeychainItemSecTypeLabel:
            return kSecAttrLabel;
            break;
            
        case ACIKeychainItemSecTypeDescription:
            return kSecAttrDescription;
            break;
            
        case ACIKeychainItemSecTypeGeneric:
            return kSecAttrGeneric;
            break;
            
        default: break;
    }
    
    return NULL;
}

@end
