/*
 * port/posix/posix_flash_file.h
 */

#ifndef PORT_POSIX_POSIX_FLASH_FILE_H_
#define PORT_POSIX_POSIX_FLASH_FILE_H_

/*
 * This POSIX NVM simulator uses a single file to provide flash-like reads and
 * writes on a backend that supports only "write-once" semantics (with a
 * unit program size of 64-bits) and a large erase sector size.  In this case,
 * the erase will cover half of the entire space and atomic updates will
 * require fully copying the "active" half NVM to the "inactive" half and
 * updating the initial flags to update the state.
 */

#include "wolfhsm/wh_flash.h"

/* In memory context structure associated with a flash instance */
typedef struct posixFlashFileContext_t {
    int fd;
    int unlocked;
    uint32_t partition_size;
    uint8_t erased_byte;
} posixFlashFileContext;

/* In memory configuration structure associated with an NVM instance */
typedef struct posixFlashConfig_t {
    const char* filename;       /* Null terminated */
    uint32_t partition_size;
    uint8_t erased_byte;
} posixFlashFileConfig;

int posixFlashFile_Init(void* c, const void* cf);
int posixFlashFile_Cleanup(void* c);
uint32_t posixFlashFile_PartitionSize(void* c);
int posixFlashFile_WriteLock(void* c, uint32_t offset, uint32_t size);

int posixFlashFile_WriteUnlock(void* c, uint32_t offset, uint32_t size);
int posixFlashFile_Read(void* c, uint32_t offset, uint32_t size, uint8_t* data);
int posixFlashFile_Program(void* c, uint32_t offset, uint32_t size,
        const uint8_t* data);
int posixFlashFile_Erase(void* c, uint32_t offset, uint32_t size);
int posixFlashFile_Verify(void* c, uint32_t offset, uint32_t size,
        const uint8_t* data);
int posixFlashFile_BlankCheck(void* c, uint32_t offset, uint32_t size);

#define POSIX_FLASH_FILE_CB                         \
{                                                   \
    .Init = posixFlashFile_Init,                    \
    .Cleanup = posixFlashFile_Cleanup,              \
    .PartitionSize = posixFlashFile_PartitionSize,  \
    .WriteLock = posixFlashFile_WriteLock,          \
    .WriteUnlock = posixFlashFile_WriteUnlock,      \
    .Read = posixFlashFile_Read,                    \
    .Program = posixFlashFile_Program,              \
    .Erase = posixFlashFile_Erase,                  \
    .Verify = posixFlashFile_Verify,                \
    .BlankCheck = posixFlashFile_BlankCheck,        \
}

#endif /* PORT_POSIX_POSIX_FLASH_FILE_H_ */
