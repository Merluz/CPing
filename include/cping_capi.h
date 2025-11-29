#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * C representation of a ping result.
 * Return codes follow the C convention (1=success, 0=failure).
 */
struct CPingResultC {
    int  reachable;   /* 1 = reply received, 0 = timeout/failure */
    long rtt_ms;      /* RTT in milliseconds (-1 if unavailable) */
    int  ttl;         /* Observed TTL (-1 if unavailable) */
};

/**
 * Options for the extended C ping API.
 */
struct CPingOptionsC {
    int timeout_ms;             /* Per-probe timeout */
    int retries;                /* Number of attempts */
    int payload_size;           /* Extra payload bytes (>=0) */
    int ttl;                    /* Custom TTL, -1 = default */
    int stop_on_first_success;  /* Non-zero = stop early */
    const char* if_name;        /* Optional interface name */
};

/* Platform-specific export macro */
#ifdef _WIN32
  #ifdef CPING_BUILDING_DLL
    #define CPING_API __declspec(dllexport)
  #else
    #define CPING_API __declspec(dllimport)
  #endif
#else
  #define CPING_API
#endif


// ---------------------------------------------------------------------------
// BASIC C API
// ---------------------------------------------------------------------------
CPING_API int cping_ping_host(const char* ip,
                              int timeout_ms,
                              struct CPingResultC* out);

CPING_API int cping_ping_host_ex(const char* ip,
                                 const struct CPingOptionsC* opt,
                                 struct CPingResultC* out);


// ---------------------------------------------------------------------------
// ENGINE API (raw socket + WinPcap capture)
// ---------------------------------------------------------------------------
/**
 * Initializes global engine (pcap + raw socket + listener).
 * if_name may be NULL or partial substring.
 */
CPING_API int cping_init_engine(const char* if_name);

/**
 * Shuts down global engine and releases all resources.
 */
CPING_API void cping_shutdown_engine();

/**
 * Executes a single probe using the engine.
 */
CPING_API int cping_ping_once_engine(const char* ip,
                                     int timeout_ms,
                                     int payload_size,
                                     int ttl,
                                     struct CPingResultC* out);

/**
 * Determines whether init_engine() successfully started.
 */
CPING_API int cping_engine_available();


#ifdef __cplusplus
}
#endif
