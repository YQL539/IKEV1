//
//  ViewController.m
//  tvpn
//
//  Created by zhang on 16/5/9.
//  Copyright © 2016年 tuzuu. All rights reserved.
//

#import "ViewController.h"
#import <NetworkExtension/NetworkExtension.h>

@interface ViewController ()

@property(nonatomic,strong) NEVPNManager * vpnManager;

@end

@implementation ViewController{
//    _vpnManager
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Do any additional setup after loading the view, typically from a nib.
}

-(IBAction) addVPN{
    // init VPN manager
    
    self.vpnManager = [NEVPNManager sharedManager];

    // load config from perference
    [_vpnManager loadFromPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
        
        if (error) {
            NSLog(@"Load config failed [%@]", error.localizedDescription);
            return;
        }
        
        NEVPNProtocolIPSec *p = (NEVPNProtocolIPSec *)_vpnManager.protocolConfiguration;
        
        if (p) {
            // Protocol exists.
            // If you don't want to edit it, just return here.
        } else {
            // create a new one.
            p = [[NEVPNProtocolIPSec alloc] init];
        }
        
        // config IPSec protocol
        p.username = @"a";
        p.serverAddress = @"119.28.44.232";;
        
        // Get password persistent reference from keychain
        // If password doesn't exist in keychain, should create it beforehand.
         [self createKeychainValue:@"666666" forIdentifier:@"VPN_PASSWORD"];
        p.passwordReference = [self searchKeychainCopyMatching:@"VPN_PASSWORD"];
        
        // PSK
        p.authenticationMethod = NEVPNIKEAuthenticationMethodSharedSecret;
         [self createKeychainValue:@"888888" forIdentifier:@"PSK"];
        p.sharedSecretReference = [self searchKeychainCopyMatching:@"PSK"];
        
        /*
         // certificate
         p.identityData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"client" ofType:@"p12"]];
         p.identityDataPassword = @"[Your certificate import password]";
         */
        
        p.localIdentifier = @"";
        p.remoteIdentifier =  @"119.28.44.232";
        
        p.useExtendedAuthentication = YES;
        p.disconnectOnSleep = NO;
        
        _vpnManager.protocolConfiguration = p;
        _vpnManager.localizedDescription = @"PSecvpnsd测试";
        
        [_vpnManager saveToPreferencesWithCompletionHandler:^(NSError *error) {
            if (error) {
                NSLog(@"Save config failed [%@]", error.localizedDescription);
            }
        }];
    }];

}

-(IBAction) startVPN{
    NSError *startError;
    [_vpnManager.connection startVPNTunnelAndReturnError:&startError];
    if (startError) {
        NSLog(@"Start VPN failed: [%@]", startError.localizedDescription);
    }

}

-(IBAction) stopVPN{

}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - KeyChain

static NSString * const serviceName = @"im.zorro.ipsec_demo.vpn_config";

- (NSMutableDictionary *)newSearchDictionary:(NSString *)identifier {
    NSMutableDictionary *searchDictionary = [[NSMutableDictionary alloc] init];
    
    [searchDictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    
    NSData *encodedIdentifier = [identifier dataUsingEncoding:NSUTF8StringEncoding];
    [searchDictionary setObject:encodedIdentifier forKey:(__bridge id)kSecAttrGeneric];
    [searchDictionary setObject:encodedIdentifier forKey:(__bridge id)kSecAttrAccount];
    [searchDictionary setObject:serviceName forKey:(__bridge id)kSecAttrService];
    
    return searchDictionary;
}

- (NSData *)searchKeychainCopyMatching:(NSString *)identifier {
    NSMutableDictionary *searchDictionary = [self newSearchDictionary:identifier];
    
    // Add search attributes
    [searchDictionary setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
    
    // Add search return types
    // Must be persistent ref !!!!
    [searchDictionary setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef result = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)searchDictionary, &result);
    
    return (__bridge_transfer NSData *)result;
}

- (BOOL)createKeychainValue:(NSString *)password forIdentifier:(NSString *)identifier {
    NSMutableDictionary *dictionary = [self newSearchDictionary:identifier];
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)dictionary);
    
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    [dictionary setObject:passwordData forKey:(__bridge id)kSecValueData];
    
    status = SecItemAdd((__bridge CFDictionaryRef)dictionary, NULL);
    
    if (status == errSecSuccess) {
        return YES;
    }
    return NO;
}

@end

