#include <string.h>
#if defined HAVE_DECL_STRDUP && !HAVE_DECL_STRDUP && ! defined strdup
/* Duplicate S, returning an identical malloc'd string.  */
char *strdup (const char *s);
#endif
