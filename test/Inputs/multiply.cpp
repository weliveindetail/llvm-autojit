int multiply(int X, int Y) {
    int Result = 1;
    for (int I = 0; I < Y; ++I) {
        Result += X;
    }
    return Result - 1;
}
