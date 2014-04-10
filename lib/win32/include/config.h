#ifndef _CONFIG_H
#define _CONFIG_H

#define strcasecmp stricmp
#define strncasecmp strnicmp

#define PACKAGE "libgsasl"
#define LOCALEDIR "."
#define PACKAGE_STRING "libgsasl"

#if _MSC_VER && !__cplusplus
# define inline __inline
#endif

#include <errno.h>
#ifndef EOVERFLOW
#define EOVERFLOW E2BIG
#endif
#define GNULIB_GC_HMAC_MD5 1
#define GNULIB_GC_MD5 1
#define GNULIB_GC_RANDOM 1
#define GNULIB_GC_SHA1 1
#define GNULIB_GC_HMAC_SHA1 1
#define HAVE_ALLOCA 1
#define HAVE_DECL_GETDELIM 0
#define HAVE_DECL_GETLINE 0
#define HAVE_DECL_STRDUP 1
#define HAVE_DECL__SNPRINTF 1
#define HAVE_FLOAT_H 1
#define HAVE_INCLUDE_NEXT 1
#define HAVE_INTMAX_T 1
#define HAVE_INTTYPES_H 1
#define HAVE_INTTYPES_H_WITH_UINTMAX 1
#define HAVE_LONG_LONG_INT 1
#define HAVE_MEMORY_H 1
#define HAVE_SNPRINTF 1
#define HAVE_STDBOOL_H 1
// #define HAVE_STDINT_H 1
#define HAVE_STDINT_H_WITH_UINTMAX 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_UNSIGNED_LONG_LONG_INT 1
#define HAVE_WCHAR_H 1
#define HAVE_WCHAR_T 1
#define HAVE_WCSLEN 1
#define HAVE_WINT_T 1
#define HAVE__BOOL 1
#define NAME_OF_NONCE_DEVICE "/dev/urandom"
#define NAME_OF_PSEUDO_RANDOM_DEVICE "/dev/urandom"
#define NAME_OF_RANDOM_DEVICE "/dev/random"

#define STDC_HEADERS 1
#define USE_ANONYMOUS 1
#define USE_CLIENT 1
#define USE_CRAM_MD5 1
#define USE_DIGEST_MD5 1
#define USE_EXTERNAL 1
#define USE_LOGIN 1
#define USE_NTLM 1
#define USE_PLAIN 1
#define USE_SECURID 1
#define USE_SERVER 1
#define USE_SCRAM_SHA1 1

#define GSASL_NO_OBSOLETE 1

#define restrict
#define __attribute__(x)
#define _GL_ATTRIBUTE_CONST
#define _GL_ATTRIBUTE_PURE(x)

#define _STRING_ARCH_unaligned 1

#ifndef _AC_STDINT_H
#include <sys/types.h>
#include "ac-stdint.h"
#endif

#include <stdio.h>
ssize_t
getdelim (char **lineptr, size_t *n, int delimiter, FILE *fp);
ssize_t
getline (char **lineptr, size_t *n, FILE *stream);

#define __strverscmp strverscmp
int
__strverscmp (const char *s1, const char *s2);

#ifndef GSASL_API
#if defined _USRDLL && defined HAVE_VISIBILITY && HAVE_VISIBILITY
#define GSASL_API __attribute__((__visibility__("default")))
#elif defined _USRDLL && defined _MSC_VER && ! defined GSASL_STATIC
#define GSASL_API __declspec(dllexport)
#elif defined _MSC_VER && ! defined GSASL_STATIC
#define GSASL_API __declspec(dllimport)
#else
#define GSASL_API
#endif
#endif

#include <vasnprintf.h>
extern GSASL_API int asprintf (char **resultbuf, const char *format, ...)
       _GL_ATTRIBUTE_FORMAT ((__printf__, 3, 4));
extern GSASL_API int vasprintf (char **resultbuf, const char *format, va_list args)
       _GL_ATTRIBUTE_FORMAT ((__printf__, 3, 0));
#undef GSASL_API

#include <string.h>
#include <stdlib.h>
static char *
strndup(const char *s, size_t n)
{
size_t len = strlen(s);
char *result;

  if (n < len) {
    result = malloc(1+len);
    if (!result)
      return result;
    return strcpy(result, s);
    }
  else
    return strdup(s);
}

void *
memmem (const void *haystack_start, size_t haystack_len,
        const void *needle_start, size_t needle_len);

/* Older Visual C++ versions don't have strtok_r(), but the 
   strtok() implementation is reentrant using thread local storage */
#define strtok_r(str, delim, savptr) strtok(str, delim)

#include "internal.h"

#endif /* _CONFIG_H */
