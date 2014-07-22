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
@end