//
//  CheckTweakFrameworks.m
//  homework
//
//  Created by 曾宪杰 on 2020/3/2.
//  Copyright © 2020 test. All rights reserved.
//

#import "CheckTweakFrameworks.h"
#import "Define.h"

#include <stdlib.h>
#include <unistd.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h> //mach-o中LC加载命令
#include <mach-o/fat.h>   //mach-o中fat
#include <sys/stat.h>
#include <mach-o/stab.h> //desc

@implementation CheckTweakFrameworks

// 非越狱机中Frameworks是否有其他动态库
+ (NSArray *)searchInFrameworksByWiteList:(NSArray*)frameworks {
    // 排除hook工程里默认的文件
    NSArray *baseArr = @[@"RevealServer.framework",@"libcycript.cy",@"libcycript.db",
                         @"libcycript.dylib",@"libsubstrate.dylib"];
    [baseArr arrayByAddingObjectsFromArray:frameworks];
    LOGI(@"frameworks %@, base %@\n",frameworks,baseArr);
    
    NSString *path = [[NSBundle mainBundle] resourcePath];
    NSFileManager *manager = [NSFileManager defaultManager];
    
    NSString *url = [path stringByAppendingPathComponent:@"Frameworks"];
    LOGI(@"url = %@\n",url);
    
    if (![manager fileExistsAtPath:url]) {
        return NULL;
    }
    
    // 文件夹里的名字
    NSArray *tempArr = [manager contentsOfDirectoryAtPath:url error:nil];
    // 定义查找不在数组中的谓词语句
    NSPredicate *filepread = [NSPredicate predicateWithFormat:@"NOT (SELF IN %@)",baseArr];
    NSArray *filesArr = [tempArr filteredArrayUsingPredicate:filepread];
    
    LOGI(@"tempArr = %@ tweak = %@\n",tempArr,filesArr);
    
    return filesArr;

}

// 未越狱机从被hook函数的dlfname获取tweak动态库。
+ (NSString*)searchInFrameworkByName:(NSString *)dlfname {
    // 倒序搜索判断结尾是否是dylib
    NSRange endRangeStr = [dlfname rangeOfString:@"dylib" options:NSBackwardsSearch];
    if (endRangeStr.length == 0) {
        return NULL;
    }
    
    // Frameworks/libThoesHookDylib.dylib
    NSRange range = [dlfname rangeOfString:@"/" options:NSBackwardsSearch];
    
//    LOGI(@"rang.loc = %ld\n",range.location);
    NSUInteger len = dlfname.length - range.location -1;
    NSRange stringRange = NSMakeRange(dlfname.length - len, len);
    NSString *dylibgName = [dlfname substringWithRange:stringRange];
    LOGI(@"dylibgName = %@\n",dylibgName);
    
    return dylibgName;
    
}

// 未越狱机中MonkeyDev下载cycript文件和MDConfig文件路径
// /var/mobile/Containers/Data/Application/E8-4C/Documents/cycript/ms.cy
// /private/var/containers/Bundle/Application/E8-4C/ThoesHook.app/MDConfig.plist
+ (int)isInFrameworkHaveCycript {
    // config
    NSString *path = [[NSBundle mainBundle] pathForResource:@"MDConfig" ofType:@"plist"];
    LOGI(@"path %@\n",path);

    if (path) {
        LOGI(@"MDConfig NOT NULL \n");
        return 1;
    }
    
    // 路径下是否有 /Documents/cycript 有"hook.cy","md.cy","ms.cy","nslog.cy"
    NSString *documentsPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *cycriptPath = [documentsPath stringByAppendingPathComponent:@"cycript"];
    
    const char *cCycriptPath = [cycriptPath UTF8String];
    LOGI(@"cycriptPath %s\n",cCycriptPath);
    
    // 此处不用fileExistsAtPath
    int isHaveCycriptFile = access(cCycriptPath, F_OK);

    if (isHaveCycriptFile == 0) {
        return 1;
    }
    

    return 0;
    
}

uint64_t fileGetSize(char *file_path){
    // 复制文件状态
    struct stat bufer;
    if ( stat(file_path,&bufer) < 0 )
    {
        perror(file_path);
        return 0;
    }
    return bufer.st_size;
}

/*
1.如果是系统库返回 /System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore: No such file or directory  file isn't exist
2.
 */
+ (void)searchINFrameworkBySymtab:(char *)filepath {
    FILE *fp = fopen(filepath,"r");
    uint64_t fileSize = fileGetSize(filepath);
    if(!fp){
        LOGI(@"file isn't exist\n");
        return;
    }
    
    LOGI(@"file size is 0x%llx\n\n",fileSize);
    // 开空间
    void *fileBufer = malloc(fileSize);

    if(fread(fileBufer,1,fileSize,fp)!= fileSize){
        LOGI(@"fread error\n");
        // 释放
        if (fileBufer) {
            free(fileBufer);
        }
        
        return;
    }

    // 检查FAT头
    struct fat_header* fileFATHeader = (struct fat_header*)fileBufer;
    if(fileFATHeader->magic == FAT_CIGAM || fileFATHeader->magic == FAT_MAGIC){
        LOGI(@"is fat\n");
        
        fclose(fp);
        if (fileBufer) {
            free(fileBufer);
        }
        
        return;
    }
    
    // 存放tweak方法
    NSMutableArray *arrM = [[NSMutableArray alloc] init];
    
    struct mach_header *mh = (struct mach_header*)fileBufer;
    
    // 遍历cmd中segment和section
    const uint32_t cmdCount = mh->ncmds;
    LOGI(@"cmdCount %d\n\n",cmdCount);
    
    struct load_command *cmds = (struct load_command*)
    ((char*)mh+(sizeof(struct mach_header_64)));
    
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmdCount; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                uint32_t symoff = sym_cmd->symoff;
                uint32_t nsyms = sym_cmd->nsyms;
                uint32_t stroff = sym_cmd->stroff;
         
                LOGI(@"\n");
                for(int i =0;i<nsyms; i++){
                        struct nlist_64 *nn = (void*)((char*)mh+symoff+i*sizeof(struct nlist_64));
                
                        char *def_str = (char*)mh+(uint32_t)nn->n_un.n_strx + stroff;
                        LOGI(@"def_str %s",def_str);
                        
                        // 遍历条件
                        if(nn->n_type==0xf||nn->n_type==0xe||nn->n_type==0x1e){
                           
                            // 比较def_str中带有_logos_method的字符串
                            if (strstr(def_str, "_logos_method")) {
                                LOGI(@"\nstrstr have %s\n\n",def_str);
                        
                                // 转换char->OC
                                NSString *cChar = [NSString stringWithCString:def_str encoding:NSUTF8StringEncoding];
                                // 保存获取到的hook方法
//                                NSString *key = [NSString stringWithFormat:@"hook",i];
                                NSDictionary *dic = [NSDictionary dictionaryWithObject:cChar forKey:@"hook"];
                                [arrM addObject:dic];
                                
                            }
                        }
                        LOGI(@"\n");
                }
            }
                break;
        }
        
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
    // 关闭文件
    fclose(fp);
    if (fileBufer) {
        free(fileBufer);
    }
    
    //获取完整路径
    NSString *documentsPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *plistPath = [documentsPath stringByAppendingPathComponent:@"MY_HookList.plist"];
    NSMutableDictionary *usersDic = [[NSMutableDictionary alloc ] init];
    [usersDic setObject:arrM forKey:@"hookList"];
    //写入文件
    [usersDic writeToFile:plistPath atomically:YES];
        
}

// 获取/Libray/MobileSubstrate/DynamicLibraries下的plist文件
+ (void)searchInFrameworkByPlist {
    /*
    NSString *urlPath = [[NSBundle mainBundle] pathForResource:@"TZLoadAllLibs" ofType:@"plist"];
    NSDictionary *contentDict = [NSDictionary dictionaryWithContentsOfFile:urlPath];
       NSLog(@"contdic %@\n",contentDict);
       
    if ([contentDict.allKeys containsObject:@"Filter"]) {
        NSDictionary *filter = contentDict[@"Filter"];
        NSLog(@"bundles %@\n\n",filter);
        NSArray *bundle = filter[@"Bundles"];
        NSLog(@"bundle %@\n\n",bundle[0]);
    }
    */
    
//    NSString *urlPath = @"/Libray/MobileSubstrate/DynamicLibraries";
    
     // 待真机看是否可以使用
//    NSFileManager *manager = [NSFileManager defaultManager];
//    if (![manager fileExistsAtPath:urlPath]) {
//        NSLog(@"NOT OPEN \n\n");
//        return;
//    }
   
   
    /*
//    NSArray *tempArr = [manager contentsOfDirectoryAtPath:urlPath error:nil];
//    NSLog(@"tempArr = %@\n",tempArr);
    
    // 定义查找在数组中的谓词语句
    NSPredicate *filepread = [NSPredicate predicateWithFormat:@"ENDSWITH[d] 'plist'",tempArr];
    NSArray *filesArr = [tempArr filteredArrayUsingPredicate:filepread];
    
    // 获取单个plist名字
    for (NSString *plistName in tempArr) {
        NSLog(@"plistName %@\n",plistName);
        NSString *plistURL = [urlPath stringByAppendingPathComponent:plistName];
        NSDictionary *contentDict = [NSDictionary dictionaryWithContentsOfFile:plistURL];
        
        if ([contentDict.allKeys containsObject:@"Filter"]) {
           NSDictionary *filter = contentDict[@"Filter"];
            NSLog(@"bundles %@\n\n",filter);
            NSArray *bundle = filter[@"Bundles"];
            NSLog(@"bundle %@\n\n",bundle[0]);
        }
        
    }
    
    */
        
    
}


@end
