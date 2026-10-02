#include "src/platform/linux/x11_clipboard.h"
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;
#define REQUIRE(condition) do { if (!(condition)) throw std::runtime_error( \
  std::string(__func__) + ":" + std::to_string(__LINE__) + ": " #condition); } while (0)

struct fixture_t {
  Display *display = XOpenDisplay(nullptr);
  Window window;
  Atom clipboard, utf8, property, incr;
  platf::x11::clipboard_t backend;
  fixture_t() : backend(std::move(platf::x11::clipboard_t::make().value())) {
    REQUIRE(display);
    window = make_window();
    clipboard = XInternAtom(display, "CLIPBOARD", False);
    utf8 = XInternAtom(display, "UTF8_STRING", False);
    property = XInternAtom(display, "TEST_CLIPBOARD", False);
    incr = XInternAtom(display, "INCR", False);
  }
  ~fixture_t() { XCloseDisplay(display); }
  Window make_window() {
    return XCreateSimpleWindow(display, DefaultRootWindow(display), 0, 0, 1, 1, 0, 0, 0);
  }
  void publish(std::string text = "remote text") {
    REQUIRE(backend.set_text(std::vector<std::uint8_t>(text.begin(), text.end())));
    // set_text flushes PRIMARY asynchronously. Observe its completed claim
    // before another connection steals it; otherwise the server may process
    // the steal first and the reviewed bug's negative control can pass by race.
    const auto clipboard_owner = XGetSelectionOwner(display, clipboard);
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (XGetSelectionOwner(display, XA_PRIMARY) != clipboard_owner &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(2ms);
    }
    REQUIRE(XGetSelectionOwner(display, XA_PRIMARY) == clipboard_owner);
  }
  void own() {
    XSetSelectionOwner(display, clipboard, window, CurrentTime);
    XSync(display, False);
    REQUIRE(XGetSelectionOwner(display, clipboard) == window);
  }
  bool poll(std::string &text) { return backend.poll_change(text); }
  void poll() { std::string ignored; backend.poll_change(ignored); }
  void wait() {
#ifdef PLANK_CLIPBOARD_SLEEP_POLL
    // Negative control: the old production loop slept after every poll.
    std::this_thread::sleep_for(250ms);
#else
    REQUIRE(backend.wait_for_activity());
#endif
  }
  XSelectionRequestEvent next_request() {
    // A new conversion is rate-limited separately from event/INCR servicing.
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline) {
      while (XPending(display)) {
        XEvent result {};
        XNextEvent(display, &result);
        if (result.type == SelectionRequest) return result.xselectionrequest;
      }
      std::this_thread::sleep_for(2ms);
      poll();
    }
    throw std::runtime_error("timed out waiting for the next conversion");
  }
  XEvent event(int type) {
    auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline) {
      while (XPending(display)) {
        XEvent result {};
        XNextEvent(display, &result);
        if (result.type == type) return result;
      }
      std::this_thread::sleep_for(2ms);
    }
    throw std::runtime_error("timed out waiting for X11 event " + std::to_string(type));
  }
  XSelectionRequestEvent request() {
    own();
    poll();
    return event(SelectionRequest).xselectionrequest;
  }
  void notify(const XSelectionRequestEvent &request, Atom target = None) {
    XEvent result {};
    result.xselection.type = SelectionNotify;
    result.xselection.requestor = request.requestor;
    result.xselection.selection = request.selection;
    result.xselection.target = target == None ? request.target : target;
    result.xselection.property = request.property;
    result.xselection.time = request.time;
    XSendEvent(display, request.requestor, False, 0, &result);
    XSync(display, False);
  }
  void chunk(const XSelectionRequestEvent &request, const std::string &text) {
    XChangeProperty(display, request.requestor, request.property, utf8, 8,
      PropModeReplace, reinterpret_cast<const unsigned char *>(text.data()), text.size());
    XSync(display, False);
  }
  void reply(const XSelectionRequestEvent &request, const std::string &text) {
    chunk(request, text);
    notify(request);
  }
  void begin_incr(const XSelectionRequestEvent &request, unsigned long size) {
    XSelectInput(display, request.requestor, PropertyChangeMask);
    XChangeProperty(display, request.requestor, request.property, incr, 32,
      PropModeReplace, reinterpret_cast<unsigned char *>(&size), 1);
    notify(request);
    poll();
    deletion(request);
  }
  void deletion(const XSelectionRequestEvent &request) {
    for (;;) {
      auto e = event(PropertyNotify).xproperty;
      if (e.window == request.requestor && e.atom == request.property && e.state == PropertyDelete) return;
    }
  }
  std::string paste() {
    XConvertSelection(display, clipboard, utf8, property, window, CurrentTime);
    XSync(display, False);
    poll();
    auto response = event(SelectionNotify).xselection;
    REQUIRE(response.property == property);
    Atom type; int format; unsigned long count, after; unsigned char *data = nullptr;
    REQUIRE(XGetWindowProperty(display, window, property, 0, 1024*1024/4, True,
      AnyPropertyType, &type, &format, &count, &after, &data) == Success);
    REQUIRE(type == utf8 && format == 8 && after == 0);
    std::string result(reinterpret_cast<char *>(data), count);
    XFree(data);
    return result;
  }
};

void destroyed_requestor() {
  fixture_t f;
  f.publish();
  for (int i = 0; i < 20; ++i) {
    auto doomed = f.make_window();
    XConvertSelection(f.display, f.clipboard, f.utf8, f.property, doomed, CurrentTime);
    XSync(f.display, False);
    XDestroyWindow(f.display, doomed);
    XSync(f.display, False);
    f.poll();
  }
  REQUIRE(f.paste() == "remote text");
}
void independent_selections() {
  fixture_t f;
  f.publish();
  XSetSelectionOwner(f.display, XA_PRIMARY, f.window, CurrentTime);
  XSync(f.display, False);
  f.poll();
  REQUIRE(f.paste() == "remote text");
}
void delayed_reply() {
  fixture_t f;
  auto request = f.request();
  std::this_thread::sleep_for(150ms);
  f.reply(request, "delayed text");
  std::this_thread::sleep_for(110ms);
  std::string text;
  REQUIRE(f.poll(text));
  REQUIRE(text == "delayed text");
}
void incremental_reply() {
  fixture_t f;
  auto request = f.request();
  constexpr auto limit = 512 * 1024;
  f.begin_incr(request, limit);
  std::string expected, text;
  for (int i = 0; i < 8; ++i) {
    std::string part(65536, 'a' + i);
    expected += part;
    f.chunk(request, part);
    REQUIRE(!f.poll(text));
    f.deletion(request);
  }
  f.chunk(request, "");
  REQUIRE(f.poll(text));
  REQUIRE(text == expected);
}
void incremental_worker_cadence() {
  fixture_t f;
  auto request = f.request();
  constexpr auto limit = 512 * 1024;
  f.begin_incr(request, limit);
  std::string expected, text;
  const auto start = std::chrono::steady_clock::now();
  for (int i = 0; i < 32; ++i) {
    std::string part(16384, 'a' + i % 26);
    expected += part;
    f.chunk(request, part);
    f.wait();
    REQUIRE(!f.poll(text));
    // Fail before the conversion is destroyed, to avoid provoking unrelated
    // Xlib errors in the fake owner when exercising the old polling cadence.
    REQUIRE(std::chrono::steady_clock::now() - start < 4s);
    f.deletion(request);
  }
  f.chunk(request, "");
  f.wait();
  REQUIRE(f.poll(text));
  REQUIRE(text == expected);
}
void idle_wait_is_bounded() {
  fixture_t f;
  f.poll();
  const auto start = std::chrono::steady_clock::now();
  f.wait();
  const auto elapsed = std::chrono::steady_clock::now() - start;
  REQUIRE(elapsed >= 200ms);
  REQUIRE(elapsed < 1s);
}
void conversion_rate_is_bounded() {
  fixture_t f;
  auto request = f.request();
  const auto start = std::chrono::steady_clock::now();
  f.reply(request, "unchanged text");
  std::string text;
  REQUIRE(f.poll(text));
  f.poll();
  XEvent unexpected {};
  REQUIRE(!XCheckTypedEvent(f.display, SelectionRequest, &unexpected));
  request = f.next_request();
  REQUIRE(std::chrono::steady_clock::now() - start >= 200ms);
  const auto refused = std::chrono::steady_clock::now();
  request.property = None;
  f.notify(request);
  REQUIRE(!f.poll(text));
  f.poll();
  REQUIRE(!XCheckTypedEvent(f.display, SelectionRequest, &unexpected));
  f.next_request();
  REQUIRE(std::chrono::steady_clock::now() - refused >= 200ms);
}
void wakes_for_reply() {
  fixture_t f;
  auto request = f.request();
  // Only this helper accesses the fake owner's Xlib connection while running.
  std::thread owner([&] {
    std::this_thread::sleep_for(60ms);
    f.reply(request, "wake on reply");
  });
  std::string text;
  bool healthy = true;
  const auto deadline = std::chrono::steady_clock::now() + 1s;
  while (healthy && text.empty() && std::chrono::steady_clock::now() < deadline) {
#ifdef PLANK_CLIPBOARD_SLEEP_POLL
    std::this_thread::sleep_for(250ms);
#else
    healthy = f.backend.wait_for_activity();
#endif
    f.poll(text);
  }
  owner.join();
  REQUIRE(healthy);
  REQUIRE(text == "wake on reply");
}
void oversized_advertisement() {
  fixture_t f;
  auto request = f.request();
  unsigned long size = 512 * 1024 + 1;
  XChangeProperty(f.display, request.requestor, request.property, f.incr, 32,
    PropModeReplace, reinterpret_cast<unsigned char *>(&size), 1);
  f.notify(request);
  std::string text;
  REQUIRE(!f.poll(text));
  auto next = f.next_request();
  REQUIRE(next.requestor != request.requestor);
  f.reply(next, "recovered");
  REQUIRE(f.poll(text) && text == "recovered");
}
void incremental_overflow() {
  fixture_t f;
  auto request = f.request();
  f.begin_incr(request, 0); // INCR count is a lower bound, not an allocation size.
  std::string text;
  for (int i = 0; i < 8; ++i) {
    f.chunk(request, std::string(65536, 'x'));
    REQUIRE(!f.poll(text));
    f.deletion(request);
  }
  f.chunk(request, "overflow");
  REQUIRE(!f.poll(text));
  auto next = f.next_request();
  REQUIRE(next.requestor != request.requestor);
  f.reply(next, "recovered");
  REQUIRE(f.poll(text) && text == "recovered");
}
void conversion_timeout() {
  fixture_t f;
  auto request = f.request();
  f.begin_incr(request, 12);
  std::this_thread::sleep_for(5100ms);
  std::string text;
  REQUIRE(!f.poll(text));
  auto next = f.next_request();
  REQUIRE(next.requestor != request.requestor);
  f.reply(next, "after timeout");
  REQUIRE(f.poll(text) && text == "after timeout");
}
void correlated_notify() {
  fixture_t f;
  auto request = f.request();
  f.chunk(request, "valid text");
  f.notify(request, XA_STRING); // Wrong target must not complete the request.
  std::string text;
  REQUIRE(!f.poll(text));
  f.notify(request);
  REQUIRE(f.poll(text) && text == "valid text");
}
int sentinel_errors = 0;
int sentinel(Display *, XErrorEvent *) { ++sentinel_errors; return 0; }
void unrelated_xlib_handler() {
  auto previous = XSetErrorHandler(sentinel);
  {
    fixture_t f;
    f.publish();
    auto doomed = f.make_window();
    XDestroyWindow(f.display, doomed);
    XDestroyWindow(f.display, doomed);
    XSync(f.display, False);
    REQUIRE(sentinel_errors == 1);
  }
  REQUIRE(XSetErrorHandler(previous) == sentinel);
}
int main(int argc, char **argv) {
  struct test_t { const char *name; void (*run)(); } tests[] = {
    {"destroyed requestor", destroyed_requestor},
    {"independent selections", independent_selections},
    {"150ms delayed reply", delayed_reply},
    {"512KiB INCR reply", incremental_reply},
    {"512KiB INCR worker cadence", incremental_worker_cadence},
    {"bounded idle wait", idle_wait_is_bounded},
    {"bounded conversion rate", conversion_rate_is_bounded},
    {"wake on delayed reply", wakes_for_reply},
    {"oversized INCR advertisement", oversized_advertisement},
    {"cumulative INCR overflow", incremental_overflow},
    {"INCR timeout and recovery", conversion_timeout},
    {"correlated notification", correlated_notify},
    {"unrelated Xlib handler", unrelated_xlib_handler},
  };
  for (const auto &test : tests) {
    if (argc > 1 && std::string(argv[1]) != test.name) continue;
    try { test.run(); std::cout << "PASS " << test.name << std::endl; }
    catch (const std::exception &error) { std::cerr << "FAIL " << error.what() << std::endl; return 1; }
  }
}
