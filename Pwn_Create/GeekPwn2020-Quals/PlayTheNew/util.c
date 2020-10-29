#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "sandbox.h"

void handler()
{
    exit(0);
}

__attribute__((constructor))
void setup()
{
    signal(SIGALRM, handler);
    alarm(30);

#ifndef SANDBOX_DISABLE
    sandbox();
#endif
}
