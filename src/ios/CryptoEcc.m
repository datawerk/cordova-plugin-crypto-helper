/*
 * JBoss, Home of Professional Open Source.
 * Copyright Red Hat, Inc., and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import "CryptoEcc.h"
#import "AGPBKDF2.h"
#import "AGCryptoBox.h"
#import "AGRandomGenerator.h"

@implementation CryptoEcc

- (void)getRandomValue:(CDVInvokedUrlCommand *)command {
    NSData * data = [AGRandomGenerator randomBytes];
    NSString *value = [self convertDataToString:data];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:value];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)deriveKey:(CDVInvokedUrlCommand *)command {
    NSMutableDictionary *options = [self parseParameters:command];
    NSString *password = [options objectForKey:@"password"];
    
    [self.commandDelegate runInBackground:^{
        AGPBKDF2 *agpbkdf2 = [[AGPBKDF2 alloc] init];
        NSData *rawPassword = [agpbkdf2 deriveKey:password];
        
        NSString *encodedPassword = [self convertDataToString:rawPassword];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:encodedPassword];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)generateKeyPair:(CDVInvokedUrlCommand *)command {
    
    [self.commandDelegate runInBackground:^{
        AGKeyPair *keyPair = [[AGKeyPair alloc] init];
        
        NSMutableDictionary *results = [NSMutableDictionary dictionary];
        [results setValue:[NSString [self convertDataToString:keyPair.privateKey]] forKey:@"privateKey"];
        [results setValue:[NSString [self convertDataToString:keyPair.publicKey]] forKey:@"publicKey"];
        
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:results];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)encrypt:(CDVInvokedUrlCommand *)command {
    NSMutableDictionary *options = [self parseParameters:command];
    NSString *publicKey = [options objectForKey:@"publicKey"];
    NSString *privateKey = [options objectForKey:@"privateKey"];
    NSString *nonce = [options objectForKey:@"nonce"];
    NSString *data = [options objectForKey:@"data"];
    
    AGCryptoBox *cryptoBox = [[AGCryptoBox alloc] initWithKey:[self convertStringToData:publicKey] privateKey:[self convertStringToData:privateKey]];
    [self.commandDelegate runInBackground:^{
        NSData *message = [data dataUsingEncoding:NSUTF8StringEncoding];
        
        NSData *result = [cryptoBox encrypt:message nonce:[self convertStringToData:nonce] error:nil];
        NSString *encodedResult = [self convertDataToString:result];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:encodedResult];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)decrypt:(CDVInvokedUrlCommand *)command {
    NSMutableDictionary *options = [self parseParameters:command];
    NSString *publicKey = [options objectForKey:@"publicKey"];
    NSString *privateKey = [options objectForKey:@"privateKey"];
    NSString *nonce = [options objectForKey:@"nonce"];
    NSString *data = [options objectForKey:@"data"];
    
    AGCryptoBox *cryptoBox = [[AGCryptoBox alloc] initWithKey:[self convertStringToData:publicKey] privateKey:[self convertStringToData:privateKey]];
    [self.commandDelegate runInBackground:^{
        NSData *message = [self convertStringToData:data];
        
        NSData *result = [cryptoBox decrypt:message nonce:[self convertStringToData:nonce] error:nil];
        NSString *encodedResult = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:encodedResult];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (NSMutableData *)convertStringToData:(NSString *)hexString {
    NSMutableData *commandToSend = [[NSMutableData alloc] init];
    long byte;
    char bytes[3] = {'\0', '\0', '\0'};
    int i;
    for (i = 0; i < [hexString length] / 2; i++) {
        bytes[0] = (char) [hexString characterAtIndex:i * 2];
        bytes[1] = (char) [hexString characterAtIndex:i * 2 + 1];
        byte = strtol(bytes, NULL, 16);
        [commandToSend appendBytes:&byte length:1];
    }
    return commandToSend;
}

- (NSString *)convertDataToString:(NSData *)data {
    const unsigned char *dataBuffer = (const unsigned char *) [data bytes];
    
    if (!dataBuffer) {
        return [NSString string];
    }
    
    NSUInteger dataLength = [data length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long) dataBuffer[i]]];
    }
    
    return [NSString stringWithString:hexString];
}

- (id)parseParameters:(CDVInvokedUrlCommand *)command {
    NSArray *data = [command arguments];
    if (data.count == 1) {
        return [data objectAtIndex:0];
    }
    return Nil;
}

@end