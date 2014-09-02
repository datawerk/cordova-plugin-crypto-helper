#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>


@interface CryptoHelper : CDVPlugin {
    
}

- (void)getRandomValue:(CDVInvokedUrlCommand*)command;
- (void)deriveKey:(CDVInvokedUrlCommand*)command;
- (void)validateKey:(CDVInvokedUrlCommand*)command;
- (void)generateKeyPair:(CDVInvokedUrlCommand*)command;
- (void)encrypt:(CDVInvokedUrlCommand*)command;
- (void)decrypt:(CDVInvokedUrlCommand*)command;
- (void)symmetricEncrypt:(CDVInvokedUrlCommand*)command;
- (void)symmetricDecrypt:(CDVInvokedUrlCommand*)command;
- (void)symmetricDecryptBatch:(CDVInvokedUrlCommand*)command;
+ (NSMutableData *)convertStringToData:(NSString *)hexString;
+ (NSString *)convertDataToString:(NSData *)data;
+ (NSString *)MD5String:(NSString *)data;
+ (NSString *)MD5StringFromData:(NSData *)data;
@end