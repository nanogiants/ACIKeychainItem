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

typedef enum : NSUInteger {
    ACIKeychainItemSecTypeAccount,     /**< usage: account / username       */
    ACIKeychainItemSecTypeData,        /**< usage: password / data          */
    ACIKeychainItemSecTypeLabel,       /**< usage: user visible label       */
    ACIKeychainItemSecTypeDescription, /**< usage: user visible description */
    ACIKeychainItemSecTypeGeneric
} ACIKeychainItemSecType;

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

/**
 @brief Creates a keychain item.
 @details
 @param identifier obvious identity of that item (uses kSecAttrService)
 @param accessGroup (optional) access group for sharing between apps.
 @sa ACIKeychainItem#bundleSeedID
 */
- (id)initWithIdentifier:(NSString *)identifier accessGroup:(NSString *)accessGroup;

/**
 @brief Inserts data for the corresponding type.
 @details If there is already data for this type, this function will return false
          and you have to call updateData:forSecType: instead.
 @param data The data that will be added.
 @param type The type of the data.
 @return true on success and false on failure.
 @sa insertOrUpdateData:forSecType: updateData:accessGroup: dataForSecType:
 */
- (BOOL)insertData:(NSData *)data forSecType:(ACIKeychainItemSecType)type;

/**
 @brief Finds the data for the corresponding type.
 @param data The new data.
 @param type The type of the data.
 @return true on success and false on failure.
 @sa insertData:accessGroup: insertOrUpdateData:forSecType: dataForSecType:
 */
- (BOOL)updateData:(NSData *)data forSecType:(ACIKeychainItemSecType)type;

/**
 @brief Inserts or updates the given data for the corresponding type.
 @details First it tries to insert the data. If insertion failed due to already
          existing data, it will update the current data with the new one 
          instead.
 @param data The data that will be added or updated.
 @param type The type of the data.
 @return true on success and false on failure.
 @sa insertData:accessGroup: updateData:accessGroup: dataForSecType:
 */
- (BOOL)insertOrUpdateData:(NSData *)data forSecType:(ACIKeychainItemSecType)type;

/**
 @brief Finds the data for the corresponding type.
 @param type The type of the data to return.
 @return the data on success and nil on failure.
 @sa updateData:accessGroup: insertData:accessGroup: remove
 */
- (NSData *)dataForSecType:(ACIKeychainItemSecType)type;

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
