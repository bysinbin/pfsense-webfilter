/*
  Copyright (c) 2009-2017 Dave Gamble and cJSON contributors
*/

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <float.h>

#include "cJSON.h"

static void *(*cJSON_malloc)(size_t sz) = malloc;
static void (*cJSON_free)(void *ptr) = free;

static unsigned char* cJSON_strdup(const unsigned char* string)
{
    size_t length = 0;
    unsigned char *copy = NULL;
    if (string == NULL) return NULL;
    length = strlen((const char*)string) + sizeof("");
    copy = (unsigned char*)cJSON_malloc(length);
    if (copy == NULL) return NULL;
    memcpy(copy, string, length);
    return copy;
}

void cJSON_InitHooks(cJSON_Hooks* hooks)
{
    if (!hooks) {
        cJSON_malloc = malloc;
        cJSON_free = free;
        return;
    }
    cJSON_malloc = (hooks->malloc_fn != NULL) ? hooks->malloc_fn : malloc;
    cJSON_free = (hooks->free_fn != NULL) ? hooks->free_fn : free;
}

static cJSON *cJSON_New_Item(void)
{
    cJSON* node = (cJSON*)cJSON_malloc(sizeof(cJSON));
    if (node) memset(node, '\0', sizeof(cJSON));
    return node;
}

void cJSON_Delete(cJSON *item)
{
    cJSON *next = NULL;
    while (item != NULL)
    {
        next = item->next;
        if (!(item->type & cJSON_IsReference) && (item->child != NULL)) {
            cJSON_Delete(item->child);
        }
        if (!(item->type & cJSON_IsReference) && (item->valuestring != NULL)) {
            cJSON_free(item->valuestring);
        }
        if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) {
            cJSON_free(item->string);
        }
        cJSON_free(item);
        item = next;
    }
}

static const unsigned char *parse_number(cJSON * const item, const unsigned char * const input)
{
    double number = 0;
    unsigned char *after_end = NULL;
    if (input == NULL) return NULL;
    number = strtod((const char*)input, (char**)&after_end);
    if (input == after_end) return NULL;
    item->valuedouble = number;
    if (number >= INT_MAX) item->valueint = INT_MAX;
    else if (number <= (double)INT_MIN) item->valueint = INT_MIN;
    else item->valueint = (int)number;
    item->type = cJSON_Number;
    return after_end;
}

static const unsigned char *parse_string(cJSON * const item, const unsigned char * const input)
{
    const unsigned char *input_pointer = input + 1;
    unsigned char *output_pointer = NULL;
    unsigned char *output = NULL;
    size_t allocation_length = 0;

    if (*input != '\"') return NULL;
    while (*input_pointer != '\"' && *input_pointer != '\0') {
        if (*input_pointer == '\\') input_pointer++;
        input_pointer++;
    }
    if (*input_pointer != '\"') return NULL;

    allocation_length = (size_t)(input_pointer - input) + 1;
    output = (unsigned char*)cJSON_malloc(allocation_length);
    if (output == NULL) return NULL;

    input_pointer = input + 1;
    output_pointer = output;
    while (*input_pointer != '\"' && *input_pointer != '\0') {
        if (*input_pointer == '\\') {
            input_pointer++;
            switch (*input_pointer) {
                case 'b': *output_pointer++ = '\b'; break;
                case 'f': *output_pointer++ = '\f'; break;
                case 'n': *output_pointer++ = '\n'; break;
                case 'r': *output_pointer++ = '\r'; break;
                case 't': *output_pointer++ = '\t'; break;
                case '\"': case '\\': case '/': *output_pointer++ = *input_pointer; break;
                case 'u': {
                    unsigned int codepoint = 0;
                    int i;
                    for (i = 0; i < 4; i++) {
                        unsigned char c = *(input_pointer + 1 + i);
                        if (c >= '0' && c <= '9') codepoint = (codepoint << 4) | (c - '0');
                        else if (c >= 'a' && c <= 'f') codepoint = (codepoint << 4) | (c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') codepoint = (codepoint << 4) | (c - 'A' + 10);
                        else break;
                    }
                    if (i == 4) {
                        input_pointer += 4;
                        if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                            if (*(input_pointer + 1) == '\\' && *(input_pointer + 2) == 'u') {
                                unsigned int low = 0;
                                int j;
                                for (j = 0; j < 4; j++) {
                                    unsigned char c = *(input_pointer + 3 + j);
                                    if (c >= '0' && c <= '9') low = (low << 4) | (c - '0');
                                    else if (c >= 'a' && c <= 'f') low = (low << 4) | (c - 'a' + 10);
                                    else if (c >= 'A' && c <= 'F') low = (low << 4) | (c - 'A' + 10);
                                    else break;
                                }
                                if (j == 4 && low >= 0xDC00 && low <= 0xDFFF) {
                                    input_pointer += 6;
                                    codepoint = 0x10000 + (((codepoint & 0x3FF) << 10) | (low & 0x3FF));
                                }
                            }
                        }
                        if (codepoint <= 0x7F) {
                            *output_pointer++ = (unsigned char)codepoint;
                        } else if (codepoint <= 0x7FF) {
                            *output_pointer++ = (unsigned char)(0xC0 | (codepoint >> 6));
                            *output_pointer++ = (unsigned char)(0x80 | (codepoint & 0x3F));
                        } else if (codepoint <= 0xFFFF) {
                            *output_pointer++ = (unsigned char)(0xE0 | (codepoint >> 12));
                            *output_pointer++ = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3F));
                            *output_pointer++ = (unsigned char)(0x80 | (codepoint & 0x3F));
                        } else {
                            *output_pointer++ = (unsigned char)(0xF0 | (codepoint >> 18));
                            *output_pointer++ = (unsigned char)(0x80 | ((codepoint >> 12) & 0x3F));
                            *output_pointer++ = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3F));
                            *output_pointer++ = (unsigned char)(0x80 | (codepoint & 0x3F));
                        }
                    } else {
                        *output_pointer++ = *input_pointer;
                    }
                    break;
                }
                default: *output_pointer++ = *input_pointer; break;
            }
        } else {
            *output_pointer++ = *input_pointer;
        }
        input_pointer++;
    }
    *output_pointer = '\0';
    item->valuestring = (char*)output;
    item->type = cJSON_String;
    return input_pointer + 1;
}

static const unsigned char *skip_whitespace(const unsigned char *in)
{
    while (in && *in && (unsigned char)*in <= 32) in++;
    return in;
}

static const unsigned char *parse_value(cJSON * const item, const unsigned char * const input);

static const unsigned char *parse_array(cJSON * const item, const unsigned char *input)
{
    cJSON *head = NULL;
    cJSON *current_item = NULL;
    if (*input != '[') return NULL;
    input = skip_whitespace(input + 1);
    if (*input == ']') {
        item->type = cJSON_Array;
        return input + 1;
    }
    head = cJSON_New_Item();
    if (!head) return NULL;
    input = parse_value(head, skip_whitespace(input));
    if (!input) { cJSON_Delete(head); return NULL; }
    current_item = head;

    while (*(input = skip_whitespace(input)) == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) { cJSON_Delete(head); return NULL; }
        current_item->next = new_item;
        new_item->prev = current_item;
        current_item = new_item;
        input = parse_value(current_item, skip_whitespace(input + 1));
        if (!input) { cJSON_Delete(head); return NULL; }
    }
    if (*input != ']') { cJSON_Delete(head); return NULL; }
    item->type = cJSON_Array;
    item->child = head;
    return input + 1;
}

static const unsigned char *parse_object(cJSON * const item, const unsigned char *input)
{
    cJSON *head = NULL;
    cJSON *current_item = NULL;
    if (*input != '{') return NULL;
    input = skip_whitespace(input + 1);
    if (*input == '}') {
        item->type = cJSON_Object;
        return input + 1;
    }
    head = cJSON_New_Item();
    if (!head) return NULL;
    input = parse_string(head, skip_whitespace(input));
    if (!input) { cJSON_Delete(head); return NULL; }
    head->string = head->valuestring;
    head->valuestring = NULL;
    input = skip_whitespace(input);
    if (*input != ':') { cJSON_Delete(head); return NULL; }
    input = parse_value(head, skip_whitespace(input + 1));
    if (!input) { cJSON_Delete(head); return NULL; }
    current_item = head;

    while (*(input = skip_whitespace(input)) == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) { cJSON_Delete(head); return NULL; }
        current_item->next = new_item;
        new_item->prev = current_item;
        current_item = new_item;
        input = parse_string(current_item, skip_whitespace(input + 1));
        if (!input) { cJSON_Delete(head); return NULL; }
        current_item->string = current_item->valuestring;
        current_item->valuestring = NULL;
        input = skip_whitespace(input);
        if (*input != ':') { cJSON_Delete(head); return NULL; }
        input = parse_value(current_item, skip_whitespace(input + 1));
        if (!input) { cJSON_Delete(head); return NULL; }
    }
    if (*input != '}') { cJSON_Delete(head); return NULL; }
    item->type = cJSON_Object;
    item->child = head;
    return input + 1;
}

static const unsigned char *parse_value(cJSON * const item, const unsigned char * const input)
{
    if (!input) return NULL;
    if (!strncmp((const char*)input, "null", 4)) { item->type = cJSON_NULL; return input + 4; }
    if (!strncmp((const char*)input, "false", 5)) { item->type = cJSON_False; return input + 5; }
    if (!strncmp((const char*)input, "true", 4)) { item->type = cJSON_True; item->valueint = 1; return input + 4; }
    if (*input == '\"') return parse_string(item, input);
    if (*input == '-' || (*input >= '0' && *input <= '9')) return parse_number(item, input);
    if (*input == '[') return parse_array(item, input);
    if (*input == '{') return parse_object(item, input);
    return NULL;
}

cJSON *cJSON_Parse(const char *value)
{
    cJSON *item = cJSON_New_Item();
    if (!item) return NULL;
    if (!parse_value(item, skip_whitespace((const unsigned char*)value))) {
        cJSON_Delete(item);
        return NULL;
    }
    return item;
}

static void print_value(const cJSON *item, char **buf, size_t *len, size_t *cap);

static void ensure_cap(char **buf, size_t *len, size_t *cap, size_t needed)
{
    if (*len + needed + 1 >= *cap) {
        *cap = (*cap + needed + 256) * 2;
        *buf = (char*)realloc(*buf, *cap);
    }
}

static void append_str(char **buf, size_t *len, size_t *cap, const char *s)
{
    size_t slen = strlen(s);
    ensure_cap(buf, len, cap, slen);
    memcpy(*buf + *len, s, slen);
    *len += slen;
    (*buf)[*len] = '\0';
}

static void print_value(const cJSON *item, char **buf, size_t *len, size_t *cap)
{
    if (!item) return;
    switch (item->type & 0xFF) {
        case cJSON_NULL: append_str(buf, len, cap, "null"); break;
        case cJSON_False: append_str(buf, len, cap, "false"); break;
        case cJSON_True: append_str(buf, len, cap, "true"); break;
        case cJSON_Number: {
            char num[64];
            if (fabs(floor(item->valuedouble) - item->valuedouble) <= DBL_EPSILON && item->valuedouble >= INT_MIN && item->valuedouble <= INT_MAX)
                snprintf(num, sizeof(num), "%d", item->valueint);
            else
                snprintf(num, sizeof(num), "%.15g", item->valuedouble);
            append_str(buf, len, cap, num);
            break;
        }
        case cJSON_String: {
            append_str(buf, len, cap, "\"");
            const char *p = item->valuestring;
            while (p && *p) {
                if (*p == '\"') append_str(buf, len, cap, "\\\"");
                else if (*p == '\\') append_str(buf, len, cap, "\\\\");
                else if (*p == '\n') append_str(buf, len, cap, "\\n");
                else if (*p == '\r') append_str(buf, len, cap, "\\r");
                else if (*p == '\t') append_str(buf, len, cap, "\\t");
                else {
                    char ch[2] = {*p, 0};
                    append_str(buf, len, cap, ch);
                }
                p++;
            }
            append_str(buf, len, cap, "\"");
            break;
        }
        case cJSON_Array: {
            append_str(buf, len, cap, "[");
            cJSON *child = item->child;
            while (child) {
                print_value(child, buf, len, cap);
                if (child->next) append_str(buf, len, cap, ",");
                child = child->next;
            }
            append_str(buf, len, cap, "]");
            break;
        }
        case cJSON_Object: {
            append_str(buf, len, cap, "{");
            cJSON *child = item->child;
            while (child) {
                append_str(buf, len, cap, "\"");
                if (child->string) append_str(buf, len, cap, child->string);
                append_str(buf, len, cap, "\":");
                print_value(child, buf, len, cap);
                if (child->next) append_str(buf, len, cap, ",");
                child = child->next;
            }
            append_str(buf, len, cap, "}");
            break;
        }
        default: break;
    }
}

char *cJSON_PrintUnformatted(const cJSON *item)
{
    size_t cap = 256, len = 0;
    char *buf = (char*)malloc(cap);
    buf[0] = '\0';
    print_value(item, &buf, &len, &cap);
    return buf;
}

char *cJSON_Print(const cJSON *item) { return cJSON_PrintUnformatted(item); }

int cJSON_GetArraySize(const cJSON *array)
{
    int c = 0;
    cJSON *child = array ? array->child : NULL;
    while (child) { c++; child = child->next; }
    return c;
}

cJSON *cJSON_GetArrayItem(const cJSON *array, int index)
{
    cJSON *child = array ? array->child : NULL;
    while (child && index > 0) { index--; child = child->next; }
    return child;
}

cJSON *cJSON_GetObjectItem(const cJSON * const object, const char * const string)
{
    cJSON *child = object ? object->child : NULL;
    while (child) {
        if (child->string && !strcasecmp(child->string, string)) return child;
        child = child->next;
    }
    return NULL;
}

cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string)
{
    cJSON *child = object ? object->child : NULL;
    while (child) {
        if (child->string && !strcmp(child->string, string)) return child;
        child = child->next;
    }
    return NULL;
}

cJSON_bool cJSON_HasObjectItem(const cJSON *object, const char *string)
{
    return cJSON_GetObjectItem(object, string) != NULL;
}

cJSON *cJSON_CreateNull(void) { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_NULL; return i; }
cJSON *cJSON_CreateTrue(void) { cJSON *i = cJSON_New_Item(); if (i) { i->type = cJSON_True; i->valueint = 1; } return i; }
cJSON *cJSON_CreateFalse(void) { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_False; return i; }
cJSON *cJSON_CreateBool(cJSON_bool b) { return b ? cJSON_CreateTrue() : cJSON_CreateFalse(); }
cJSON *cJSON_CreateNumber(double num)
{
    cJSON *i = cJSON_New_Item();
    if (i) {
        i->type = cJSON_Number;
        i->valuedouble = num;
        i->valueint = (int)num;
    }
    return i;
}
cJSON *cJSON_CreateString(const char *string)
{
    cJSON *i = cJSON_New_Item();
    if (i) {
        i->type = cJSON_String;
        i->valuestring = (char*)cJSON_strdup((const unsigned char*)string);
    }
    return i;
}
cJSON *cJSON_CreateArray(void) { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_Array; return i; }
cJSON *cJSON_CreateObject(void) { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_Object; return i; }

cJSON_bool cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
    if (!item || !array) return cJSON_False;
    if (!array->child) {
        array->child = item;
    } else {
        cJSON *n = array->child;
        while (n->next) n = n->next;
        n->next = item;
        item->prev = n;
    }
    return cJSON_True;
}

cJSON_bool cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)
{
    if (!object || !string || !item) return cJSON_False;
    if (item->string) cJSON_free(item->string);
    item->string = (char*)cJSON_strdup((const unsigned char*)string);
    return cJSON_AddItemToArray(object, item);
}

cJSON* cJSON_AddNullToObject(cJSON * const object, const char * const name)
{
    cJSON *i = cJSON_CreateNull();
    cJSON_AddItemToObject(object, name, i);
    return i;
}
cJSON* cJSON_AddTrueToObject(cJSON * const object, const char * const name)
{
    cJSON *i = cJSON_CreateTrue();
    cJSON_AddItemToObject(object, name, i);
    return i;
}
cJSON* cJSON_AddFalseToObject(cJSON * const object, const char * const name)
{
    cJSON *i = cJSON_CreateFalse();
    cJSON_AddItemToObject(object, name, i);
    return i;
}
cJSON* cJSON_AddBoolToObject(cJSON * const object, const char * const name, const cJSON_bool boolean)
{
    cJSON *i = cJSON_CreateBool(boolean);
    cJSON_AddItemToObject(object, name, i);
    return i;
}
cJSON* cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number)
{
    cJSON *i = cJSON_CreateNumber(number);
    cJSON_AddItemToObject(object, name, i);
    return i;
}
cJSON* cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string)
{
    cJSON *i = cJSON_CreateString(string);
    cJSON_AddItemToObject(object, name, i);
    return i;
}

cJSON_bool cJSON_IsInvalid(const cJSON * const item) { return item == NULL || item->type == cJSON_Invalid; }
cJSON_bool cJSON_IsFalse(const cJSON * const item) { return item && ((item->type & 0xFF) == cJSON_False); }
cJSON_bool cJSON_IsTrue(const cJSON * const item) { return item && ((item->type & 0xFF) == cJSON_True); }
cJSON_bool cJSON_IsBool(const cJSON * const item) { return item && (((item->type & 0xFF) == cJSON_True) || ((item->type & 0xFF) == cJSON_False)); }
cJSON_bool cJSON_IsNull(const cJSON * const item) { return item && ((item->type & 0xFF) == cJSON_NULL); }
cJSON_bool cJSON_IsNumber(const cJSON * const item) { return item && ((item->type & 0xFF) == cJSON_Number); }
cJSON_bool cJSON_IsString(const cJSON * const item) { return item && ((item->type & 0xFF) == cJSON_String); }
cJSON_bool cJSON_IsArray(const cJSON * const item) { return item && ((item->type & 0xFF) == cJSON_Array); }
cJSON_bool cJSON_IsObject(const cJSON * const item) { return item && ((item->type & 0xFF) == cJSON_Object); }
