#include <locale.h>
#include <stdio.h>
#include <gsasl.h>

/* Build using the following command:
 * gcc -o foo foo.c `libgsasl-config --cflags --libs`
 */

int
main (int argc, char *argv[])
@{
  Gsasl_ctx *ctx;
  int res;

  setlocale (LC_ALL, "");

  if (gsasl_check_version(GSASL_VERSION) == NULL)
    @{
      fprintf(stderr, "Libgsasl is %s expected %s\n",
	      gsasl_check_version(NULL), GSASL_VERSION);
      return 1;
    @}
  
  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    @{
      fprintf(stderr, "Cannot initialize libgsasl: %s\n", 
	      gsasl_strerror(res));
      return 1;
    @}

  /* Do things here ... */

  gsasl_done(ctx);

  return 0;
@}
