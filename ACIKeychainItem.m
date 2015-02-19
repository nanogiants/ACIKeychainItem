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

// don't use init - we need the identifier at creation time
- (id)init
{
    NSAssert(NO, @"init don't satisfy requirements. Please Use initWithIdentifier:accessGroup: instead.");
    return [super init];
}

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

- (BOOL)insertAccount:(NSString *)account andPassword:(NSString *)password
{
    // create basic query
    NSMutableDictionary *query = [self createQuery];
    
    // add data to query
    query[(__bridge id)kSecAttrAccount] = account;
    query[(__bridge id)kSecValueData] = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    // add data to keychain
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    
    return (errSecSuccess == status);
}

- (BOOL)updateAccount:(NSString *)account andPassword:(NSString *)password
{
    // create basic query
    NSMutableDictionary *query = [self createQuery];
    
    // update data
    NSMutableDictionary *update =[[NSMutableDictionary alloc] init];
    update[(__bridge id)kSecAttrAccount] = account;
    update[(__bridge id)kSecValueData] = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    // update keychain item
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    
    return (errSecSuccess == status);
}

- (BOOL)insertOrUpdateAccount:(NSString *)account andPassword:(NSString *)password
{
    // try to insert
    BOOL success = [self insertAccount:account andPassword:password];
    
    // if couldn't insert - try to update
    if (!success) {
        success = [self updateAccount:account andPassword:password];
    }
    
    return success;
}

- (NSString *)account
{
    // receive the account from the results
    return [[self attrSearch] objectForKey:(__bridge id)kSecAttrAccount];
}

- (NSString *)password
{
    NSData *data = [self dataSearch];
    
    if (data) {
        // get password from data
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    
    return nil;
}

- (NSString *)label
{
    // receive the label from the keychain
    return [[self attrSearch] objectForKey:(__bridge id)kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self insertOrUpdateValue:label forAttr:kSecAttrLabel];
}

- (NSString *)desc
{
    // receive the description from the keychain
    return [[self attrSearch] objectForKey:(__bridge id)kSecAttrDescription];
}

- (void)setDesc:(NSString *)desc
{
    [self insertOrUpdateValue:desc forAttr:kSecAttrDescription];
}

// deletes this item from the keychain
- (BOOL)remove
{
    // create basic query
    NSMutableDictionary *query = [self createQuery];
    
    // delete item
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
                            (__bridge id)kSecReturnAttributes : (__bridge id)kCFBooleanTrue
                            };
    
    CFDictionaryRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status == errSecItemNotFound)
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status != errSecSuccess)
        return nil;
    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge NSString *)kSecAttrAccessGroup];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [components firstObject];
    CFRelease(result);
    return bundleSeedID;
}

#pragma mark - Private

// creates a basic query as starting point
- (NSMutableDictionary *)createQuery
{
    NSData *identifier = [self.identifier dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrService] = identifier;
    
    if (self.accessGroup) query[(__bridge id)kSecAttrAccessGroup] = self.accessGroup;
    
    return query;
}

- (BOOL)insertOrUpdateValue:(NSString *)value forAttr:(CFTypeRef)attr
{
    // create basic query
    NSMutableDictionary *query = [self createQuery];
    
    // add data to query
    query[(__bridge id)attr] = value;
    
    // add data to keychain
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    
    if (status == errSecDuplicateItem) {
        
        // update data
        NSMutableDictionary *update =[[NSMutableDictionary alloc] init];
        update[(__bridge id)attr] = value;
        
        // update keychain item
        status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    }
    
    return (errSecSuccess == status);
}

// returns the data on success and nil on failure
- (NSData *)dataSearch
{
    // create basic query
    NSMutableDictionary *query = [self createQuery];
    
    // search for first match
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    
    // get a dictionary from the keychain as result
    query[(__bridge id)kSecReturnData] = (id)kCFBooleanTrue;
    
    // search keychain
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    
    // if we failed - just memory management and return
    if (status != errSecSuccess) {
        if (result != NULL) CFRelease(result);
        return nil;
    }
    
    // get data from result
    NSData *data = [(__bridge NSData *)result copy];
    CFRelease(result);
    
    return data;
}


- (NSDictionary *)attrSearch
{
    // create basic query
    NSMutableDictionary *query = [self createQuery];
    
    // search for first match
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    
    // get a dictionary from the keychain as result
    query[(__bridge id)kSecReturnAttributes] = (id)kCFBooleanTrue;
    
    // search keychain
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    
    // if we failed - just memory management and return
    if (status != errSecSuccess) {
        if (result != NULL) CFRelease(result);
        return nil;
    }
    
    // get the dictionary from the results
    NSDictionary *dict = [(__bridge_transfer NSDictionary *)result copy];
    //CFRelease(result);
    
    return dict;
}

@end
