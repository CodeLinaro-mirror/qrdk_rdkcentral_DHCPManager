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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F')
    {
        return ch - 'A' + 10;
    }
    return -1;
}

static int parse_hex_field(const char *data, size_t length, size_t *value)
{
    size_t result = 0;

    for (size_t i = 0; i < length; ++i)
    {
        int digit = hex_value(data[i]);
        if (digit < 0)
        {
            return -1;
        }
        result = (result << 4) | (size_t)digit;
    }

    *value = result;
    return 0;
}

static char *remove_byte_separators(const char *input, size_t input_length)
{
    char *normalized = malloc(input_length + 1);
    size_t output_length = 0;
    size_t digits_in_byte = 0;

    if (normalized == NULL)
    {
        return NULL;
    }

    for (size_t i = 0; i < input_length; ++i)
    {
        if (input[i] == ':')
        {
            if (digits_in_byte != 2 || i + 1 == input_length)
            {
                free(normalized);
                return NULL;
            }
            digits_in_byte = 0;
            continue;
        }

        if (hex_value(input[i]) < 0)
        {
            free(normalized);
            return NULL;
        }
        normalized[output_length++] = input[i];
        ++digits_in_byte;
    }

    if (digits_in_byte % 2 != 0 || output_length == 0)
    {
        free(normalized);
        return NULL;
    }

    normalized[output_length] = '\0';
    return normalized;
}

char *parse_dhcp_17_suboption(const char *option_value, const char *ip_mode)
{
    size_t id_length;
    size_t input_length;
    size_t normalized_length;
    size_t input_offset = 0;
    size_t output_length = 0;
    size_t record_count = 0;
    char *normalized = NULL;
    char *formatted = NULL;

    if (option_value == NULL || ip_mode == NULL)
    {
        return NULL;
    }

    if (strcmp(ip_mode, "v4") == 0)
    {
        id_length = 2;
    }
    else if (strcmp(ip_mode, "v6") == 0)
    {
        id_length = 4;
    }
    else
    {
        return NULL;
    }

    input_length = strlen(option_value);
    if (input_length == SIZE_MAX)
    {
        return NULL;
    }
    normalized = remove_byte_separators(option_value, input_length);
    if (normalized == NULL)
    {
        return NULL;
    }
    normalized_length = strlen(normalized);

    formatted = malloc(input_length + 1);
    if (formatted == NULL)
    {
        free(normalized);
        return NULL;
    }

    while (input_offset < normalized_length)
    {
        size_t remaining = normalized_length - input_offset;
        size_t suboption_id;
        size_t value_bytes;
        size_t value_hex_length;
        size_t record_length;

        if (remaining < id_length * 2 ||
            parse_hex_field(normalized + input_offset, id_length, &suboption_id) != 0)
        {
            free(formatted);
            free(normalized);
            return NULL;
        }

        input_offset += id_length;
        if (parse_hex_field(normalized + input_offset, id_length, &value_bytes) != 0)
        {
            free(formatted);
            free(normalized);
            return NULL;
        }
        input_offset += id_length;

        if (value_bytes > SIZE_MAX / 2)
        {
            free(formatted);
            free(normalized);
            return NULL;
        }
        value_hex_length = value_bytes * 2;
        remaining = normalized_length - input_offset;
        if (value_hex_length > remaining)
        {
            free(formatted);
            free(normalized);
            return NULL;
        }

        record_length = id_length + 1 + value_hex_length + (record_count != 0 ? 1 : 0);
        if (output_length > input_length || record_length > input_length - output_length)
        {
            free(formatted);
            free(normalized);
            return NULL;
        }

        if (record_count != 0)
        {
            formatted[output_length++] = ' ';
        }
        memcpy(formatted + output_length, normalized + input_offset - id_length * 2, id_length);
        output_length += id_length;
        formatted[output_length++] = '=';
        memcpy(formatted + output_length, normalized + input_offset, value_hex_length);
        output_length += value_hex_length;

        input_offset += value_hex_length;
        ++record_count;
    }

    formatted[output_length] = '\0';
    free(normalized);
    return formatted;
}
