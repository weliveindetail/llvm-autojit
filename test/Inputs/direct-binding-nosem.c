int inner(int X) { return X + 1; }
int (*Pointer)(int) = inner;
int outer(int X) { return Pointer == inner ? inner(X) : 0; }
