#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <Mobile/Mobile.h>
#import "ProfileStore.h"
#import <arpa/inet.h>
#import <net/if.h>
#import <netinet/in.h>
#import <ifaddrs.h>
#import <sys/socket.h>
#import <sys/file.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdatomic.h>
#import <string.h>
#import <stdbool.h>

static NSError *Failure(NSString *s){return [NSError errorWithDomain:@"NetworkEX.Tunnel" code:1 userInfo:@{NSLocalizedDescriptionKey:s}];}
static BOOL Parse4(NSString *s,struct in_addr *a){return [s isKindOfClass:NSString.class]&&inet_pton(AF_INET,s.UTF8String,a)==1;}
static BOOL Private4(NSString *s){struct in_addr a;if(!Parse4(s,&a))return NO;uint32_t x=ntohl(a.s_addr);return (x>>24)==10||(x>>20)==0xac1||(x>>16)==0xc0a8;}
static BOOL Conflicts(NSString *s){
 struct in_addr target;if(!Parse4(s,&target))return YES;
 struct ifaddrs *list=NULL;if(getifaddrs(&list)!=0)return YES;
 BOOL conflict=NO;
 for(struct ifaddrs *i=list;i;i=i->ifa_next){
  if(!i->ifa_addr||!i->ifa_netmask||i->ifa_addr->sa_family!=AF_INET||i->ifa_netmask->sa_family!=AF_INET||!(i->ifa_flags&IFF_UP)||(i->ifa_flags&IFF_LOOPBACK)||strncmp(i->ifa_name,"utun",4)==0)continue;
  uint32_t m=((struct sockaddr_in*)i->ifa_netmask)->sin_addr.s_addr,a=((struct sockaddr_in*)i->ifa_addr)->sin_addr.s_addr;
  if(m&&((a&m)==(target.s_addr&m))){conflict=YES;break;}
 }
 freeifaddrs(list);return conflict;
}

@interface PacketTunnelProvider : NEPacketTunnelProvider <MobileFlowPlatform> {
 dispatch_queue_t _control;
 dispatch_queue_t _worker;
 nw_path_monitor_t _monitor;
 dispatch_source_t _poll;
 MobileFlowSession *_session;
 NSURL *_root;
 int _lockfd;
 atomic_uint _underlay;
 int32_t _generation;
 BOOL _readPending,_stopping,_startingWorker,_settingsBusy,_finishedStop;
 void (^_startDone)(NSError *);
 void (^_stopDone)(void);
}
@end

@implementation PacketTunnelProvider
- (instancetype)init {
 if((self=[super init])){
  _control=dispatch_queue_create("networkex.ios.control",DISPATCH_QUEUE_SERIAL);
  _worker=dispatch_queue_create("networkex.ios.worker",DISPATCH_QUEUE_SERIAL);
  _lockfd=-1;atomic_init(&_underlay,0);
 }return self;
}
- (void)finishStart:(NSError *)error {
 void (^done)(NSError *)=_startDone;_startDone=nil;if(done)done(error);
}
- (void)fail:(NSString *)message {
 if(_stopping)return;
 NSError *e=Failure(message);[self finishStart:e];[self cancelTunnelWithError:e];[self stopInternal:nil];
}
- (void)startTunnelWithOptions:(NSDictionary<NSString *,NSObject *> *)options completionHandler:(void (^)(NSError *))completion {
 dispatch_async(_control,^{
  if(self->_session||self->_startingWorker||self->_startDone||self->_stopping){completion(Failure(@"VPN session already active"));return;}
  self->_startDone=[completion copy];
  self->_monitor=nw_path_monitor_create();
  __weak PacketTunnelProvider *weak=self;
  nw_path_monitor_set_update_handler(self->_monitor,^(nw_path_t path){
   PacketTunnelProvider *p=weak;if(!p||p->_stopping)return;
   __block unsigned int chosen=0;
   if(nw_path_get_status(path)==nw_path_status_satisfied){
    nw_path_enumerate_interfaces(path,^bool(nw_interface_t iface){
     nw_interface_type_t type=nw_interface_get_type(iface);
     if((type==nw_interface_type_wifi||type==nw_interface_type_cellular||type==nw_interface_type_wired)&&nw_path_uses_interface_type(path,type)){
      chosen=nw_interface_get_index(iface);return false;
     }return true;
    });
   }
   unsigned int old=atomic_exchange(&p->_underlay,chosen);
   if(old&&chosen!=old){[p fail:@"Physical network changed; reconnect VPN"];return;}
   if(chosen&&!p->_startingWorker&&!p->_session)[p launchCore];
  });
  nw_path_monitor_set_queue(self->_monitor,self->_control);nw_path_monitor_start(self->_monitor);
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW,25*NSEC_PER_SEC),self->_control,^{
   if(self->_startDone)[self fail:@"VPN not ready; check device approval, physical network and server"];
  });
 });
}
- (void)launchCore {
 _startingWorker=YES;
 dispatch_async(_worker,^{
  NSError *error=nil;NSData *credential=NEXLoadCredential(&error);
  NSURL *root=nil;int fd=-1;
  if(credential&&!error){
   // Lock outside the runtime tree, so a stale tree can be cleaned safely.
   NSURL *base=[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
   NSURL *parent=[base URLByAppendingPathComponent:@"NetworkEX" isDirectory:YES];
   NSDictionary *attrs=@{NSFilePosixPermissions:@0700,NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication};
   if([NSFileManager.defaultManager createDirectoryAtURL:parent withIntermediateDirectories:YES attributes:attrs error:&error]){
    NSString *path=[[parent URLByAppendingPathComponent:@".extension.lock"] path];
    fd=open(path.fileSystemRepresentation,O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0||flock(fd,LOCK_EX|LOCK_NB)!=0){if(fd>=0)close(fd);fd=-1;error=Failure(@"Another extension session is active");}
    else root=NEXPrivateRoot(@"runtime",&error);
   }
  }
  if(root&&!error && !MobileImportProfile(root.path,credential,&error)) { if(!error)error=Failure(@"Credential import failed"); }
  if(root&&!error && !NEXProtectTree(root,&error)){}
  MobileFlowSession *session=error||!root?nil:MobileNewFlowSession(self);
  __block BOOL accepted=NO;
  dispatch_sync(self->_control,^{
   self->_startingWorker=NO;
   if(!self->_stopping&&session&&atomic_load(&self->_underlay)!=0){
    self->_root=root;self->_lockfd=fd;self->_session=session;accepted=YES;[self startPoll];
   }
  });
  if(!accepted){if(root)[NSFileManager.defaultManager removeItemAtURL:root error:nil];if(fd>=0)close(fd);dispatch_async(self->_control,^{if(!self->_stopping)[self fail:error.localizedDescription?:@"Cannot load VPN identity"];});return;}
  NSError *startError=nil;
  if(![session start:root.path error:&startError]){
   dispatch_async(self->_control,^{[self fail:startError.localizedDescription?:@"Cannot start network core"];});
  }
  dispatch_sync(self->_control,^{if(self->_stopping)[session stop];});
 });
}
- (void)startPoll {
 if(_poll)return;
 _poll=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,_control);
 dispatch_source_set_timer(_poll,dispatch_time(DISPATCH_TIME_NOW,1*NSEC_PER_SEC),NSEC_PER_SEC,100*NSEC_PER_MSEC);
 __weak PacketTunnelProvider *weak=self;
 dispatch_source_set_event_handler(_poll,^{
  PacketTunnelProvider *p=weak;if(!p||p->_stopping||!p->_session)return;
  NSString *raw=[p->_session status];
  NSDictionary *s=[NSJSONSerialization JSONObjectWithData:[raw dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
  if([s[@"running"] boolValue]&&[s[@"tunnel"][@"state"] isEqual:@"running"]&&p->_generation>0){
   p.reasserting=NO;[p finishStart:nil];
  }else if(![s[@"running"] boolValue]){
   // Allow the worker to actually start the Go loop before treating false
   // as terminal. Startup also has a fixed 25-second deadline.
   if(!p->_startDone||[s[@"error"] length]>0)[p fail:s[@"error"]?:@"Network authorization ended"];
  }
 });
 dispatch_resume(_poll);
}
- (BOOL)bindSocket:(int32_t)fd {
 unsigned int idx=atomic_load(&_underlay);if(!idx||fd<0)return NO;
 // Bind each socket to a real selected physical interface. Never emulate
 // Android protect() by returning unconditional success.
 struct sockaddr_storage a={0};socklen_t len=sizeof(a);
 if(getsockname(fd,(struct sockaddr*)&a,&len)!=0)return NO;
 if(a.ss_family==AF_INET)return setsockopt(fd,IPPROTO_IP,IP_BOUND_IF,&idx,sizeof(idx))==0;
 if(a.ss_family==AF_INET6)return setsockopt(fd,IPPROTO_IPV6,IPV6_BOUND_IF,&idx,sizeof(idx))==0;
 return NO;
}
- (BOOL)applyTunnel:(NSString *)raw generation:(int32_t)gen {
 NSDictionary *s=raw?[NSJSONSerialization JSONObjectWithData:[raw dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil]:nil;
 if(![s isKindOfClass:NSDictionary.class]||![s[@"mtu"] isEqual:@1280]||!Private4(s[@"address"])||Conflicts(s[@"address"]))return NO;
 struct in_addr remote;if(!Parse4(s[@"remote_address"],&remote))return NO;
 NSArray *routes=s[@"routes"];if(![routes isKindOfClass:NSArray.class]||routes.count>64)return NO;
 NSMutableArray<NEIPv4Route *> *included=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
 for(NSString *r in routes){
  if(![r isKindOfClass:NSString.class]||![r hasSuffix:@"/32"])return NO;
  NSString *ip=[r substringToIndex:r.length-3];
  if(!Private4(ip)||Conflicts(ip)||[ip isEqual:s[@"remote_address"]]||[ip isEqual:s[@"address"]]||[seen containsObject:ip])return NO;
  [seen addObject:ip];[included addObject:[[NEIPv4Route alloc] initWithDestinationAddress:ip subnetMask:@"255.255.255.255"]];
 }
 NEPacketTunnelNetworkSettings *settings=[[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:s[@"remote_address"]];
 NEIPv4Settings *v4=[[NEIPv4Settings alloc] initWithAddresses:@[s[@"address"]] subnetMasks:@[@"255.255.255.255"]];
 v4.includedRoutes=included;settings.IPv4Settings=v4;settings.MTU=@1280;
 // No default route, DNS override, proxy or IPv6 tunnel configuration.
 dispatch_semaphore_t sem=dispatch_semaphore_create(0);__block BOOL success=NO;
 dispatch_async(_control,^{
  if(self->_stopping||self->_settingsBusy||self->_generation||!atomic_load(&self->_underlay)){dispatch_semaphore_signal(sem);return;}
  self->_settingsBusy=YES;
  [self setTunnelNetworkSettings:settings completionHandler:^(NSError *e){
   dispatch_async(self->_control,^{
    self->_settingsBusy=NO;
    if(!e&&!self->_stopping){self->_generation=gen;success=YES;[self pump];}
    else if(!self->_stopping)[self fail:e.localizedDescription?:@"VPN network settings rejected"];
    else if(!e)[self setTunnelNetworkSettings:nil completionHandler:nil];
    dispatch_semaphore_signal(sem);
   });
  }];
 });
 if(dispatch_semaphore_wait(sem,dispatch_time(DISPATCH_TIME_NOW,8*NSEC_PER_SEC))!=0){
  dispatch_async(_control,^{[self fail:@"VPN settings timed out"];});return NO;
 }return success;
}
- (void)pump {
 if(_readPending||_stopping||_generation==0||!_session)return;
 _readPending=YES;int32_t gen=_generation;
 __weak PacketTunnelProvider *weak=self;
 [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData*> *packets,NSArray<NSNumber*> *protocols){
  PacketTunnelProvider *p=weak;if(!p)return;
  dispatch_async(p->_control,^{
   p->_readPending=NO;
   if(!p->_stopping&&gen==p->_generation){
    NSUInteger count=MIN(MIN(packets.count,protocols.count),256);
    for(NSUInteger i=0;i<count;i++)if(protocols[i].intValue==AF_INET)[p->_session pushPacket:packets[i] generation:gen];
   }
   [p pump];
  });
 }];
}
- (BOOL)writePacket:(NSData *)packet generation:(int32_t)gen {
 if(!packet||packet.length<20||packet.length>1280)return NO;
 __block BOOL ok=NO;
 dispatch_sync(_control,^{if(!self->_stopping&&self->_generation==gen)ok=[self.packetFlow writePackets:@[packet] withProtocols:@[@(AF_INET)]];});
 return ok;
}
- (void)closeTunnel:(int32_t)gen {
 dispatch_semaphore_t sem=dispatch_semaphore_create(0);
 dispatch_async(_control,^{
  if(self->_generation!=gen){dispatch_semaphore_signal(sem);return;}
  self->_generation=0;self.reasserting=!self->_stopping;self->_settingsBusy=YES;
  [self setTunnelNetworkSettings:nil completionHandler:^(NSError *e){
   dispatch_async(self->_control,^{self->_settingsBusy=NO;if(e&&!self->_stopping)[self fail:@"Cannot clear VPN routes"];dispatch_semaphore_signal(sem);});
  }];
 });
 if(dispatch_semaphore_wait(sem,dispatch_time(DISPATCH_TIME_NOW,8*NSEC_PER_SEC))!=0)dispatch_async(_control,^{[self fail:@"VPN route cleanup timed out"];});
}
- (void)handleAppMessage:(NSData *)messageData completionHandler:(void (^)(NSData *))completion {
 if(!completion)return;
 dispatch_async(_control,^{
  if([messageData isEqualToData:[@"status" dataUsingEncoding:NSUTF8StringEncoding]]&&self->_session)
   completion([[self->_session status] dataUsingEncoding:NSUTF8StringEncoding]);
  else completion(nil);
 });
}
- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completion {
 dispatch_async(_control,^{[self stopInternal:completion];});
}
- (void)stopInternal:(void (^)(void))completion {
 if(_finishedStop){if(completion)completion();return;}
 if(_stopping){if(completion){if(_stopDone){void (^previous)(void)=_stopDone;_stopDone=^{previous();completion();};}else _stopDone=[completion copy];}return;}
 _stopping=YES;_stopDone=[completion copy];atomic_store(&_underlay,0);
 [self finishStart:Failure(@"VPN stopped")];
 if(_monitor){nw_path_monitor_cancel(_monitor);_monitor=nil;}
 if(_poll){dispatch_source_cancel(_poll);_poll=nil;}
 MobileFlowSession *session=_session;[session stop];
 dispatch_async(_worker,^{
  // The worker serializes setup and shutdown. Don't hold the control queue
  // while waiting: native callbacks may need it to close their generation.
  [session stop];BOOL stopped=!session||[session waitStopped:20000];
  dispatch_async(self->_control,^{
   self->_generation=0;self.reasserting=NO;
   if(stopped){self->_session=nil;if(self->_root)[NSFileManager.defaultManager removeItemAtURL:self->_root error:nil];self->_root=nil;if(self->_lockfd>=0){close(self->_lockfd);self->_lockfd=-1;}}
   self->_finishedStop=YES;void (^done)(void)=self->_stopDone;self->_stopDone=nil;if(done)done();
   if(!stopped)[self cancelTunnelWithError:Failure(@"Core shutdown timed out")];
  });
 });
}
@end
