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

#import <Foundation/Foundation.h>

/**
 @brief Keychain Wrapper for iOS Keychain.
 @details Provides an easy interface for basic Keychain usage. An ACIKeychain
          represents a keychain item.
 */
@interface ACIKeychainItem : NSObject

///< Identifier of the keychain item - internally this is kSecAttrService
@property (nonatomic, strong, readonly) NSString *identifier;
///< The access group of this keychain item
@property (nonatomic, strong, readonly) NSString *accessGroup;

///< reads the account from the keychain item
@property (nonatomic, readonly) NSString *account;

///< reads the password from the keychain item
@property (nonatomic, readonly) NSString *password;

///< reads/writes the label from/to the keychain item
@property (nonatomic) NSString *label;

///< reads/writes the description from/to the keychain item
@property (nonatomic) NSString *desc;

/**
 @brief Creates a keychain item.
 @details
 @param identifier obvious identity of that item (uses kSecAttrService)
 @param accessGroup (optional) access group for sharing between apps.
 @sa ACIKeychainItem#bundleSeedID
 */
- (id)initWithIdentifier:(NSString *)identifier accessGroup:(NSString *)accessGroup;

/**
 @brief Inserts an account and password
 @details If the account or username already exists, this method will fail.
 @param account account or username
 @param password The password for the account / user
 @return YES on success and NO on failure.
 @sa updateAccount:andPassword: insertOrUpdateAccount:andPassword:
 */
- (BOOL)insertAccount:(NSString *)account andPassword:(NSString *)password;

/**
 @brief Updates an account and password
 @param account account or username
 @param password The password for the account / user
 @return YES on success and NO on failure.
 @sa insertAccount:andPassword: insertOrUpdateAccount:andPassword:
 */
- (BOOL)updateAccount:(NSString *)account andPassword:(NSString *)password;

/**
 @brief Inserts or updates an account and password
 @details First tries to inserts the username and password. If that fails it will try
          to update the entries.
 @param account Account or username
 @param password The password for the account / user
 @return YES on success and NO on failure.
 @sa insertAccount:andPassword: updateAccount:andPassword:
 */
- (BOOL)insertOrUpdateAccount:(NSString *)account andPassword:(NSString *)password;

/**
 @brief Deletes the item from the keychain.
 */
- (BOOL)remove;

/**
 @brief Function to get the Bundle Seed ID programmatically.
 @return Bundle Seed ID on success and nil on failure.
 */
+ (NSString *)bundleSeedID;

@end
