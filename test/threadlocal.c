// RUN: %clang -fpass-plugin=%autojit_plugin -xc %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic -o %t.exe 2>&1 | FileCheck %s
// RUN: %t.exe

// CHECK: Skipping module {{.*}} (thread-local storage not yet supported)

#include <pthread.h>

// Exit code is 0 if counter is thread-local, otherwise 1
_Thread_local int counter = 0;

void *worker(void *_) {
    counter++;
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    return counter;
}
