using Fn = int (*)(int);

inline int onlyCalled(int X) { return X + 1; }
inline int addrTaken(int X) { return X + 2; }
static int callback(int X) { return X + 3; }

Fn getAddrTaken();
