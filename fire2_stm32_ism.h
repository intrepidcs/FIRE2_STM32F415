#ifndef _ICS_ISM_HEADER_
#define _ICS_ISM_HEADER_

#include <stdint.h>

void icsISM_PreInit(void);
void icsISM_Init(void);
void icsISM_Main(void);

struct stCallBackPointers {
    void * pRegisterCallBack;
    void * pGetSetValueCallBack;
    void * pTransmitMessageCallBack;
    void * pOutputWindowCallBack;
    void * pTextAPICallBack;
    void * pGetSignalValue;
    void * pDecodeSignalValue;
    void * pTransmitMessagesFromSignalValues;
    void * pFindIndexForObjectFromNameCallBack;
    void * pShowPanelCallBack;
    void * pMessageGenericInit;
    void * pGetEcuCount;
    void * pGetMemoryBlockCount;
    void * pGetMemoryBlockInfo;
    void * pGetMemoryBlockData;
    void * pSetMemoryBlockData;
    void * pMessageRawInit;
    void * pSignalPhysicalToRaw;
    void * pTransmitMessagesFromRawSignalValues;
    void * pGetMessageName;
    void * pSetControlProp;
    void * pUpdateMessageSignalsFromBytes;
    void * pUpdateBytesFromSignals;
    void * pUpdateBytesFromRawSignals;
};

// map - exposed methods
typedef struct node_t {
    uint16_t k;
    unsigned int v;
    struct node_t * left;
    struct node_t * right;
} node_t;

typedef struct _map_t {
    unsigned int numNodes;
    unsigned int maxNodes;
    node_t * pool;
    /* BTree root will always sit at pool[0] */
} map_t;

void map_init(map_t * m, void * p, unsigned int maxNodes);
const node_t * map_lookup(const map_t * m, uint16_t key);
unsigned int map_insert(map_t * m, uint16_t key, unsigned int val);

// ccif_callback
#define CM_CALLBACKTYPE_APP_SIGNAL          0
#define CM_CALLBACKTYPE_MESSAGE             1
#define CM_CALLBACKTYPE_TIMER               2
#define CM_CALLBACKTYPE_MESSAGE_MG          3
#define CM_CALLBACKTYPE_MESSAGE_TX          4
#define CM_CALLBACKTYPE_BEFORE_MESSAGE_TX   5

map_t * icsISM_GetAppSignalMap(void);
map_t * icsISM_GetMessageMap(void);
map_t * icsISM_GetTimerMap(void);
map_t * icsISM_GetMessageTxMap(void);
map_t * icsISM_GetMessageMgMap(void);
map_t * icsISM_GetBeforeMessageTxMap(void);

typedef void (*initFunc_t)(const struct stCallBackPointers*);
typedef void (*msProcessFunc_t)(unsigned int);
typedef void (*beforeStartedCallback_t)(void);
typedef void (*startedCallback_t)(void);
typedef void (*stoppedCallback_t)(void);
typedef void (*mainProcessFunc_t)(void);
typedef void (*errorFrameCallback_t)(int,int,int,int);
typedef void (*errorStateCallback_t)(int,int,int,int);
typedef void (*everyMessageCallback_t)(int,int,uint64_t,unsigned int,int,int,const unsigned char *);

typedef int (*beforeTxCallback_t)(void *);
typedef void (*messageMgCallback_t)(void *);

extern initFunc_t ICSCoreMiniExtensionInit;
extern msProcessFunc_t ICSCoreMiniExtensionProcessMs;
extern beforeStartedCallback_t ICSCoreMiniExtensionBeforeStarted;
extern startedCallback_t ICSCoreMiniExtensionStarted;
extern stoppedCallback_t ICSCoreMiniExtensionStopped;
extern mainProcessFunc_t ICSCoreMiniExtensionMain;
extern errorFrameCallback_t ICSCoreMiniExtensionErrorFrame;
extern errorStateCallback_t ICSCoreMiniExtensionErrorState;
extern everyMessageCallback_t ICSCoreMiniExtensionEveryMessage;

void CCIF_RegisterCallback(unsigned short dataType, unsigned short index, void * pFunction);

unsigned int RegisterInitFunc(initFunc_t f);
unsigned int RegisterMsProcessFunc(msProcessFunc_t f);
unsigned int RegisterBeforeStartedFunc(beforeStartedCallback_t f);
unsigned int RegisterStartedFunc(startedCallback_t f);
unsigned int RegisterStoppedFunc(stoppedCallback_t f);
unsigned int RegisterMainFunc(mainProcessFunc_t f);
unsigned int RegisterErrorFrameFunc(errorFrameCallback_t f);
unsigned int RegisterErrorStateFunc(errorStateCallback_t f);
unsigned int RegisterEveryMessageFunc(everyMessageCallback_t f);


// AES

#define AES_CBC (0)
#define AES_ECB (1)

/** \fn int AES_Decrypt(void* data, void* key, void* iv, uint8_t keyLen, uint16_t dataLen, uint8_t algo)
    \brief Perform in-place AES decryption using Electronic Codebook (ECB) or Cipher Block Chaining (CBC) modes.
    \param data Pointer to the ciphertext. Plaintext will filled in-place.
    \param key Pointer to the decryption key.
    \param iv Pointer to the initialization vector for CBC mode operation.
    \param keyLen Number of bytes in the key. Valid values are 16, 24, or 32.
    \param dataLen Number of bytes of data.
    \param algo The algorithm to use: ALGO_AES_CBC, or ALGO_AES_ECB.
    \return 0 on success, nonzero on failure
 */
int AES_Decrypt(void* data, const void* key, const void* iv, uint8_t keyLen, uint16_t dataLen, uint8_t algo);

/** \fn int AES_Encrypt(void* data, void* key, void* iv, uint8_t keyLen, uint16_t dataLen, uint8_t algo)
    \brief Perform in-place AES Encryption using Electronic Codebook (ECB) or Cipher Block Chaining (CBC) modes.
    \param data Pointer to the plaintext. Ciphertext will filled in-place.
    \param key Pointer to the encryption key.
    \param iv Pointer to the initialization vector for CBC mode operation.
    \param keyLen Number of bytes in the key. Valid values are 16, 24, or 32.
    \param dataLen Number of bytes of data.
    \param algo The algorithm to use: ALGO_AES_CBC, or ALGO_AES_ECB.
    \return 0 on success, nonzero on failure
 */
int AES_Encrypt(void* data, const void* key, const void* iv, uint8_t keyLen, uint16_t dataLen, uint8_t algo);

typedef struct
{
    int nr;                     /*!<  number of rounds  */
    uint32_t *rk;               /*!<  AES round keys    */
    uint32_t buf[68];           /*!<  unaligned data    */
}
mbedtls_aes_context;

typedef struct mbedtls_aes_cmac_128_context {
	mbedtls_aes_context aes_key;

	uint8_t K1[16];
	uint8_t K2[16];

	uint8_t X[16];

	uint8_t last[16];
	uint32_t last_len;
}
mbedtls_aes_cmac128_context;

/*
* \brief AES-CMAC-128 context setup
*
* \param ctx      context to be initialized
* \param key      secret key for AES-128
*/
void mbedtls_aes_cmac128_starts(mbedtls_aes_cmac128_context *ctx, const uint8_t K[16]);

/*
* \brief AES-CMAC-128 process message
*
* \param ctx      context to be initialized
* \param _msg     the given message
* \param _msg_len the length of message
*/
void mbedtls_aes_cmac128_update(mbedtls_aes_cmac128_context *ctx, const uint8_t *_msg, uint32_t _msg_len);

/*
* \brief AES-CMAC-128 compute T
*
* \param ctx      context to be initialized
* \param T        the generated MAC which is used to validate the message
*/
void mbedtls_aes_cmac128_final(mbedtls_aes_cmac128_context *ctx, uint8_t T[16]);

/*
* \brief AES-CMAC-128 compute T
*
* \param key      secret key for AES-128
* \param _msg     the given message
* \param _msg_len the length of message
* \param T        the generated MAC which is used to validate the message
*/
void mbedtls_aes_cmac128(const uint8_t K[16], const uint8_t *_msg, uint32_t _msg_len, uint8_t T[16]);

#endif
