# Try to execute a main program, and if it fails, try adding some
# -R flag.
# LSH_RPATH_FIX
AC_DEFUN([LSH_RPATH_FIX],
[if test $cross_compiling = no -a "x$RPATHFLAG" != x ; then
  ac_success=no
  AC_TRY_RUN([int main(int argc, char **argv) { return 0; }],
    ac_success=yes, ac_success=no, :)
  
  if test $ac_success = no ; then
    AC_MSG_CHECKING([Running simple test program failed. Trying -R flags])
dnl echo RPATH_CANDIDATE_DIRS = $RPATH_CANDIDATE_DIRS
    ac_remaining_dirs=''
    ac_rpath_save_LDFLAGS="$LDFLAGS"
    for d in $RPATH_CANDIDATE_DIRS ; do
      if test $ac_success = yes ; then
  	ac_remaining_dirs="$ac_remaining_dirs $d"
      else
  	LDFLAGS="$RPATHFLAG$d $LDFLAGS"
dnl echo LDFLAGS = $LDFLAGS
  	AC_TRY_RUN([int main(int argc, char **argv) { return 0; }],
  	  [ac_success=yes
  	  ac_rpath_save_LDFLAGS="$LDFLAGS"
  	  AC_MSG_RESULT([adding $RPATHFLAG$d])
  	  ],
  	  [ac_remaining_dirs="$ac_remaining_dirs $d"], :)
  	LDFLAGS="$ac_rpath_save_LDFLAGS"
      fi
    done
    RPATH_CANDIDATE_DIRS=$ac_remaining_dirs
  fi
  if test $ac_success = no ; then
    AC_MSG_RESULT(failed)
  fi
fi
])

# AC_LIB_ARGP(ACTION-IF-OK, ACTION-IF-BAD)
AC_DEFUN([AC_LIB_ARGP],
[ ac_argp_save_LIBS="$LIBS"
  ac_argp_save_LDFLAGS="$LDFLAGS"
  ac_argp_ok=no
  # First check if we can link with argp.
  AC_SEARCH_LIBS(argp_parse, argp,
  [ LSH_RPATH_FIX
    AC_CACHE_CHECK([for working argp],
      lsh_cv_lib_argp_works,
      [ AC_TRY_RUN(
[#include <argp.h>
#include <stdlib.h>

static const struct argp_option
options[] =
{
  { NULL, 0, NULL, 0, NULL, 0 }
};

struct child_state
{
  int n;
};

static error_t
child_parser(int key, char *arg, struct argp_state *state)
{
  struct child_state *input = (struct child_state *) state->input;
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_END:
      if (!input->n)
	input->n = 1;
      break;
    }
  return 0;
}

const struct argp child_argp =
{
  options,
  child_parser,
  NULL, NULL, NULL, NULL, NULL
};

struct main_state
{
  struct child_state child;
  int m;
};

static error_t
main_parser(int key, char *arg, struct argp_state *state)
{
  struct main_state *input = (struct main_state *) state->input;

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &input->child;
      break;
    case ARGP_KEY_END:
      if (!input->m)
	input->m = input->child.n;
      
      break;
    }
  return 0;
}

static const struct argp_child
main_children[] =
{
  { &child_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static const struct argp
main_argp =
{ options, main_parser, 
  NULL,
  NULL,
  main_children,
  NULL, NULL
};

int main(int argc, char **argv)
{
  struct main_state input = { { 0 }, 0 };
  char *v[2] = { "foo", NULL };

  argp_parse(&main_argp, 1, v, 0, NULL, &input);

  if ( (input.m == 1) && (input.child.n == 1) )
    return 0;
  else
    return 1;
}
], lsh_cv_lib_argp_works=yes,
   lsh_cv_lib_argp_works=no,
   lsh_cv_lib_argp_works=no)])

  if test x$lsh_cv_lib_argp_works = xyes ; then
    ac_argp_ok=yes
  else
    # Reset link flags
    LIBS="$ac_argp_save_LIBS"
    LDFLAGS="$ac_argp_save_LDFLAGS"
  fi])

  if test x$ac_argp_ok = xyes ; then
    ifelse([$1],, true, [$1])
  else
    ifelse([$2],, true, [$2])
  fi   
])
