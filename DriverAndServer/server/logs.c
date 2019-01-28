/*this is for debug log system*/
#include <stdarg.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>

#define LOG_FILE_TAG "GHT"
#define TAG_LEN 20
#define LOG_LEN 1024

#define VERBOSE 'V'
#define DEBUG 'D'
#define INFO 'I'
#define ERROR 'E'

static inline int gettid()
{
    return (int)syscall(SYS_gettid);
}

#define CRM_LOG(level, tag, log) do { \
	        openlog(LOG_FILE_TAG, LOG_CONS, LOG_USER); \
	        syslog(level, "%-5d %s %s",gettid(),tag,log); \
	        closelog();\
} while (0)


static void crm_log(int level, const char *tag, const char *format, va_list args)
{
    char plugin_tag[TAG_LEN];
    char log[LOG_LEN];

    // Spaces at the end of the format string is to add padding at the end of log tag to force
    // a size of TAG_LEN bytes
    snprintf(plugin_tag, sizeof(plugin_tag), "[%s]", tag);

    vsnprintf(log, sizeof(log), format, args);

    CRM_LOG(level, plugin_tag, log);
}

void crm_console(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void crm_logs_debug(const char *tag, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    crm_log(DEBUG, tag, format, args);
    va_end(args);
}

void crm_logs_verbose(const char *tag, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    crm_log(VERBOSE, tag, format, args);
    va_end(args);
}

void crm_logs_info(const char *tag, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    crm_log(INFO, tag, format, args);
    va_end(args);
}

void crm_logs_error(const char *tag, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    crm_log(ERROR, tag, format, args);
    va_end(args);
}
