#include <stdio.h>

extern void reset_strings(void);
extern void reset_config(void);
extern void reset_args(void);
extern void reset_logging(void);

void reset(void) {
  reset_strings();
  reset_config();
  reset_args();
  reset_logging();
}
