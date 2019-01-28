/*this is for debug log system*/
#ifndef __LOGS_HEADER__
#define __LOGS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
//MODULE_EBUG_TAG < 20 characters in length
#define MODULE_DEBUG_TAG "IOSM"
#define FCT_FORMAT "%2s:%-5d"
//#define FCT_FORMAT
//for print debug information to console and syslog
#define CLOG(format, ...) do { \
        crm_console(format "\n", ## __VA_ARGS__); \
        LOGD(format, ## __VA_ARGS__); \
} while (0)

#define LOGD(format, ...) crm_logs_debug(MODULE_DEBUG_TAG, FCT_FORMAT format, __FUNCTION__, __LINE__, \
                                         ## __VA_ARGS__)

#define LOGV(format, ...) crm_logs_verbose(MODULE_DEBUG_TAG, FCT_FORMAT format, __FUNCTION__, \
                                           __LINE__, ## __VA_ARGS__)

#define LOGI(format, ...) crm_logs_info(MODULE_DEBUG_TAG, FCT_FORMAT format, __FUNCTION__, \
                                        __LINE__, ## __VA_ARGS__)

#define LOGE(format, ...) crm_logs_error(MODULE_DEBUG_TAG, FCT_FORMAT format, __FUNCTION__, \
                                         __LINE__, ## __VA_ARGS__)

void crm_logs_init(int inst_id);

void crm_console(const char *format, ...);

void crm_logs_verbose(const char *tag, const char *format, ...)
#if defined(__GNUC__)
__attribute__ ((format(printf, 2, 3)))              // Used to have compiler check arguments
#endif
;

void crm_logs_info(const char *tag, const char *format, ...)
#if defined(__GNUC__)
__attribute__ ((format(printf, 2, 3)))          // Used to have compiler check arguments
#endif
;

void crm_logs_debug(const char *tag, const char *format, ...)
#if defined(__GNUC__)
__attribute__ ((format(printf, 2, 3)))          // Used to have compiler check arguments
#endif
;

void crm_logs_error(const char *tag, const char *format, ...)
#if defined(__GNUC__)
__attribute__ ((format(printf, 2, 3)))          // Used to have compiler check arguments
#endif
;

#ifdef __cplusplus
}
#endif

#endif /* __CRM_UTILS_LOGS_HEADER__ */
