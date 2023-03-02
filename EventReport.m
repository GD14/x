//
//  EventReport.m
//  Garden
//
//  Created by chenhanrong on 2022/11/29.
//
#import "SM2Util.h"
#import "EventReport.h"
#import "Utility.h"
#import "Log.h"
#import "YSHttpClient.h"
#import "YSApplication.h"
#import "YSConfig.h"
#import "NSData+Extend.h"
#import "NSArray+Extend.h"
#import "NSDictionary+Extend.h"
#import "EventDBThread.h"
#import "PBMonitor.h"
#import "EDLPScanner.h"
#import "HashCache.h"
#import "ScanCache.h"

static dispatch_queue_t sacnner_queue() {
    static dispatch_queue_t sacnnerQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sacnnerQueue = dispatch_queue_create("com.eaglyun.dlp.scanner", DISPATCH_QUEUE_SERIAL);
    });
    return sacnnerQueue;
}
static dispatch_queue_t snapshot_queue() {
    static dispatch_queue_t snapshotQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        snapshotQueue = dispatch_queue_create("com.eaglyun.dlp.snapshot", DISPATCH_QUEUE_SERIAL);
    });
    return snapshotQueue;
}

@implementation EventReport

+ (NSString*)syncGetSensitiveFileURL:(NSData* )data
                          fileSuffix:(NSString* )fileSuffix
                             fileMD5:(NSString* )fileMD5
                                type:(NSString* )type
{
    @autoreleasepool {
        NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
        params[@"file_hash"] = SafeString(fileMD5);
        params[@"file_suffix"] = SafeString(fileSuffix);
        params[@"file_type"] = SafeString(type);
        params[@"biz_type"] = @"dlp";
        NSString* sensitiveUrl = YSConfig.instance.fileUploadUrl;
        __block NSString *url = nil;
        __block bool upload = false;
        __block bool encrypt = false;
        __block NSString *encryptKey = nil;
        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
        [YSHttpClient getSensitiveFileURL:params url:sensitiveUrl complate:^(NSDictionary * infos){
//            DDLogInfo(@"[upload:]%@",infos);
            NSString *remoteURL = infos[@"url"];
            //获取加密的信息
//            NSString *encryptURL = infos[@"encrypted_url"];
//            encryptKey = infos[@"encrypt_key"];
//            //获取文件上传路径出错，文件读取不了/网络错误/后台错误
//            if(encryptKey.length > 0 && encryptURL.length>0){//当加密上传路径存在且加密密钥存在时使用加密
//                encrypt = true;
//                url = encryptURL;
//            }else{
//                url = remoteURL;
//            }
            url = remoteURL;
            upload = [infos[@"upload"] boolValue];
            dispatch_semaphore_signal(semaphore);
        }];
        dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        
        if(!upload){
            return url;
        }
        if(encrypt){
            data = [SM2Util getGMEncryptDataWithData:data key:encryptKey];
        }
        //上传文件到oss
        dispatch_semaphore_t sem2 = dispatch_semaphore_create(0);
        dispatch_semaphore_signal(sem2);
        [YSHttpClient uploadFileWithData:data remoteURL:url complate:^(NSError * error) {
            if(error != nil){
                url = nil;
            }
            dispatch_semaphore_signal(sem2);
        }];
        dispatch_semaphore_wait(sem2, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_SEC));
        return url;
    }
}

+ (void)reportDLPEvent:(EDLPREReportEvent*)reportEvent
{
    DDLogInfo(@"reportDLPEvent event %@",[reportEvent toJSONString]);
    NSMutableArray* array =  [[NSMutableArray alloc] init];
    NSDictionary* json = [reportEvent toDictionary];
    if(json){
        [array addObject:json];
    }
    NSData *data = [Utility toJsonData:array];
    NSString *auditLogReportUrl = YSConfig.instance.auditLogReportUrl;
    [YSHttpClient reportDLPEvent:data remoteURL:auditLogReportUrl complate:^(NSError *  error) {
        //如果出错，写入数据库
        if(error != nil){
            DDLogError(@"reportDLPEvent failed :%@",error);
            [EventDBThread.instance addDLPEvent:reportEvent];
        }else{
            DDLogInfo(@"reportDLPEvent succeed");
        }
    }];
}
+ (void)alertBlockEvent:(EDLPREReportEvent*)reportEvent
{

    NSDictionary *dic = [reportEvent toDictionary];

    [PBMonitor.instance handleBlockTip:dic];
}



+ (void)reportDLPEvent:(EDLPREReportEvent*)reportEvent
              isUpload:(BOOL)isUpload
            isSnapshot:(BOOL)isSnapshot
{
    
    NSTimeInterval nowTimestamp = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval timestamp = [reportEvent.time doubleValue];
    double second = 0.1;
    if(nowTimestamp - timestamp <1){
        second = 1.0;
    }
    dispatch_time_t delay_time = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(second * NSEC_PER_SEC));
    dispatch_after(delay_time,snapshot_queue(), ^{
            //获取截屏
            if(isSnapshot){
                reportEvent.snapshots = [PBMonitor.instance syncGetSnapshotsUrl:timestamp];
            }
            //上报文件
            reportEvent.file.md5Hash = [HashCache getMD5:reportEvent.file.path];
            reportEvent.uuid = [[NSUUID UUID] UUIDString];
            if(isUpload){
                NSData *fileData = [NSData dataWithContentsOfFile:reportEvent.file.path];
                reportEvent.fileURL = [EventReport syncGetSensitiveFileURL:fileData
                                        fileSuffix:[reportEvent.file.path pathExtension]
                                        fileMD5:reportEvent.file.md5Hash type:@"file"];
            }
            //扫描文件 & 上报事件
            dispatch_async(sacnner_queue(), ^{
                NSString *result = [ScanCache getScanResult:reportEvent.file.md5Hash path:reportEvent.file.path];
                reportEvent.engineResultStr = result;
                [EventReport reportDLPEvent:reportEvent];
            });
    });
}

+ (void)reportDLPBlockEvent:(EDLPREReportEvent*)reportEvent
                 isSnapshot:(BOOL)isSnapshot
{
    NSTimeInterval nowTimestamp = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval timestamp = [reportEvent.time doubleValue];
    double second = 0.1;
    if(nowTimestamp - timestamp <1){
        second = 1.0;
    }
    dispatch_time_t delay_time = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(second * NSEC_PER_SEC));
    dispatch_after(delay_time,snapshot_queue(), ^{
        //获取截屏
        if(isSnapshot){
            reportEvent.snapshots = [PBMonitor.instance syncGetSnapshotsUrl:timestamp];
        }
        if(reportEvent.file.md5Hash.length == 0){
            reportEvent.file.md5Hash = [HashCache getMD5:reportEvent.file.path];
        }
        if(reportEvent.uuid.length == 0){
            reportEvent.uuid = [[NSUUID UUID] UUIDString];
        }
        //扫描文件 & 上报事件
        dispatch_async(sacnner_queue(), ^{
            NSString *result = [ScanCache getScanResult:reportEvent.file.md5Hash path:reportEvent.file.path];
            reportEvent.engineResultStr = result;
            [EventReport reportDLPEvent:reportEvent];
            
            [EventReport alertBlockEvent:reportEvent];
        });
    });
}

+ (NSString*)queryBlockAction:(EDLPREReportEvent*)reportEvent{
    //扫描文件 & 上报事件
    dispatch_semaphore_t deadlineSema = dispatch_semaphore_create(0);
    __block NSDictionary* actionInfo = nil;
    dispatch_async(sacnner_queue(), ^{
        reportEvent.file.md5Hash = [HashCache getMD5:reportEvent.file.path];
        reportEvent.engineResultStr = [ScanCache getScanResult:reportEvent.file.md5Hash path:reportEvent.file.path];
        NSString *fileBlockUrl = YSConfig.instance.fileBlockUrl;
        NSDictionary* json = [reportEvent toDictionary];

        [YSHttpClient matchFileBlockAction:json remoteURL:fileBlockUrl
                                  complate:^(NSDictionary * dic, NSError *  error) {
            if(error){
                actionInfo = nil;
            }else{
                actionInfo = [dic objectForKey:@"data"];
            }
            DDLogInfo(@"query %@ %@",actionInfo,error);
            dispatch_semaphore_signal(deadlineSema);
        }];
    });
    dispatch_semaphore_wait(deadlineSema, dispatch_time(DISPATCH_TIME_NOW,90 * NSEC_PER_SEC));
    NSDictionary* resAction = actionInfo;
    NSString* action = [resAction objectForKey:@"action"];
    NSString* flowID = [resAction objectForKey:@"flow_id"];
    reportEvent.flowID = flowID;
    if([action isEqualToString:@"pending_submit_approval"]){
        reportEvent.policyID = [[resAction objectForKey:@"block_policy_id"] intValue];
        reportEvent.fileSecurityCode = [resAction objectForKey:@"file_security_code"];
        [EventReport alertBlockEvent:reportEvent];
    }
    return action;
}

#pragma mark -EDR
+ (void)reportEDREvent:(EDRReportEvent *)reportEvent
{
    NSMutableArray *array =  [[NSMutableArray alloc] init];
    int total = 0;
    for (EDRReportEventInfo *info in reportEvent.events) {
        NSDictionary *json = [info toDictionary];
        total += info.data.count;
        if(json){
            [array addObject:json];
        }
    }
    DDLogInfo(@"reportEDR event: %d",total);

    NSData *data = [Utility toJsonData:array];
    [YSHttpClient reportEDREvent:data remoteURL:@"" complate:^(NSError *error) {
        if(error != nil){
            DDLogError(@"reportEDREvent failed: %@",error);
            //如果出错，写入数据库,会进行定期重试上传
            [EventDBThread.instance addEDREvent:reportEvent];
        }else{
            DDLogInfo(@"reportEDREvent succeed");
        }
    }];
    
}
@end
