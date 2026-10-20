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

#ifndef DHCPMGR_OPTION17_PARSER_H
#define DHCPMGR_OPTION17_PARSER_H

/*
 * Parse nested option 17 data into a malloc-allocated "id=value id=value"
 * string. Returns NULL for malformed input or allocation failure.
 */
char *parse_dhcp_17_suboption(const char *option_value, const char *ip_mode);

#endif
