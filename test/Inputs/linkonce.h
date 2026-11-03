#pragma once

// Inline class with virtual functions: its vtable is a linkonce_odr constant
// in every lazy module that uses it
struct Shape {
  virtual ~Shape() = default;
  virtual int area() const { return 42; }
};

inline int areaOf(const Shape &S) { return S.area(); }

int callA();
int callB();
