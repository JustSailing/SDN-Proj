#include "types.h"
#include <stdint.h>
#include <stdio.h>

Hosts *generateHosts(uint32_t, uint32_t);

Switch *generateSwitch(Hosts *, char *);

void writeToYamlFile(FILE*, Hosts*, Switch*);
// @INFO De-allocations
// @COMPLETE freeing of memory allocated for Interfaces has been moved to deInitHosts
// void deInitInterfaces(Interfaces *);

void deInitHosts(Hosts *);

void deInitSwitch(Switch *);