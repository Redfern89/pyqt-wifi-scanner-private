#ifndef DOT11_UTILS_H
#define DOT11_UTILS_H

#include <stdio.h>
#include <stdint.h>

typedef struct {
    //uint16_t version:2;
    uint16_t type:2;
    uint16_t subtype:4;
    uint16_t flags:8;
} __attribute__((packed)) FrameControl;



#endif