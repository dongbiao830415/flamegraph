#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

// LD_PRELOAD=./hook.so ./test 123
// LD_PRELOAD=/log/src/hook.so /opt/WiseGrid/api/bin/smartapi -c /opt/WiseGrid/api/conf/api.conf -f

//unsetenv("LD_PRELOAD"); // 清除LD_PRELOAD环境变量


// LD_PRELOAD=/log/src/hook.so /opt/WiseGrid/shell/smartctrl -d

int main(int argc, char *argv[])
{
    system("ls -l");
    
    FILE *fp ;
    fp = fopen("main.c", "r");
    
    return 0;
}
