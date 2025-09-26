/*
 * Copyright (c) 2007-2014, Lloyd Hilaiel <me@lloyd.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef YAJL_VERSION_H_
#define YAJL_VERSION_H_

#include <yajl/yajl_common.h>

#define YAJL_MAJOR 2
#define YAJL_MINOR 1
#define YAJL_MICRO 0

#define YAJL_VERSION ((YAJL_MAJOR * 10000) + (YAJL_MINOR * 100) + YAJL_MICRO)

#ifdef __cplusplus
extern "C" {
#endif

extern int YAJL_API yajl_version(void);

#ifdef __cplusplus
}
#endif

#endif /* YAJL_VERSION_H_ */

