#include "platform.h"

#ifdef _WIN32

#include <direct.h>
#include <stdlib.h>
#include <stdio.h>

char *
mkdtemp (char *tmpl) {
  /* These are the characters used in temporary filenames.  */
  static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  int len;
  char *XXXXXX;
  static uint64_t value;
  uint64_t random_time_bits;
  int count;

  len = (int) strlen(tmpl);
  if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX")) {
      return NULL;
  }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6];

  /* Get some more or less random data.  We need 36 bits. */
  random_time_bits = rand();
  value += (random_time_bits << 8);

  for (count = 0; count < TMP_MAX; value += 7777, ++count) {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % 62];
      v /= 62;
      XXXXXX[1] = letters[v % 62];
      v /= 62;
      XXXXXX[2] = letters[v % 62];
      v /= 62;
      XXXXXX[3] = letters[v % 62];
      v /= 62;
      XXXXXX[4] = letters[v % 62];
      v /= 62;
      XXXXXX[5] = letters[v % 62];

      if ( mkdir(tmpl) == 0) {
        return (tmpl);
      }
    }

  return (NULL);
}

#endif /* _WIN32 */

