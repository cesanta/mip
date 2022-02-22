// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#pragma once

#define _DARWIN_UNLIMITED_SELECT 1  // No limit on file descriptors

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MG_ENABLE_SOCKET 0
#define MG_ENABLE_FILE 0

#ifndef MG_ENABLE_DIRLIST
#define MG_ENABLE_DIRLIST 0
#endif
