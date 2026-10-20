/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dhcpmgr_option17_parser.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void expect_parse(const char *input, const char *mode, const char *expected)
{
    char *actual = parse_dhcp_17_suboption(input, mode);
    assert(actual != NULL);
    assert(strcmp(actual, expected) == 0);
    free(actual);
}

static void expect_rejected(const char *input, const char *mode)
{
    assert(parse_dhcp_17_suboption(input, mode) == NULL);
}

int main(void)
{
    expect_parse("00:01:00:04:ff:ff:ff:ff:00:02:00:04:ff:ff:ff:ff",
                 "v6", "0001=ffffffff 0002=ffffffff");
    expect_parse("00010004ffffffff00020004ffffffff",
                 "v6", "0001=ffffffff 0002=ffffffff");
    expect_parse("0001000000020000", "v6", "0001= 0002=");
    expect_parse("01:02:aa:bb:02:01:cc",
                 "v4", "01=aabb 02=cc");
    expect_parse("00:01:00:00", "v6", "0001=");

    expect_rejected("00:01:00:04:ff", "v6");
    expect_rejected("00:01:ff:ff", "v6");
    expect_rejected("00::01:00:00", "v6");
    expect_rejected("00:01:00:00:gg", "v6");
    expect_rejected("000100", "v6");
    expect_rejected("00:01:00:00", "v5");
    expect_rejected(NULL, "v6");

    return 0;
}
