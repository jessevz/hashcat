/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What a schedule looks like across a fleet, without owning a fleet.
//
// get_work () hands one device a slice of the keyspace every time it asks, and whether that adds up
// to a balanced run is a property of the arithmetic rather than of any GPU. So the arithmetic is in
// src/dispatch_sched.c with nothing else in it, and this drives it over simulated devices that
// consume their slices at a rate we choose.
//
// It answers one question: when the keyspace runs out, how long does the fleet spend with some of
// its devices idle and work still outstanding. A real run cannot answer that cheaply, because the
// only way to see it is to own several devices and watch the end of a chunk.
//
// It does NOT model launch overhead, the candidate feed, or clocks. A device here is a rate. So it
// proves a schedule is balanced, never that a run is fast.

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "types.h"
#include "dispatch_sched.h"

#define MAX_DEV 16

// Nothing here is measured. A device is a rate, a slice costs size/rate, and every clock below is
// arithmetic on those two. -v prints each assignment so the numbers in the summary can be checked by
// hand against the schedule that produced them.

static bool g_verbose = false;

// The formula as it stood before dispatch_slice () was lifted out of get_power (), kept so the lift
// can be shown to have changed nothing. Any edit to the policy has to update this too, and the
// difference it makes then shows up as the equivalence check failing on the inputs it changed.

static u64 reference_slice (const u64 kernel_power_final, const u64 hardware_power, const u64 hardware_power_all, const u64 kernel_power)
{
  if (kernel_power_final)
  {
    const double device_factor = (double) hardware_power / hardware_power_all;
    const u64 words_left_device = (u64) CEIL (kernel_power_final * device_factor);
    const u64 work = MAX (words_left_device, hardware_power);
    const u64 work_final = MIN (work, kernel_power);
    return work_final;
  }
  return kernel_power;
}

static int check_equivalence (void)
{
  u64 checked = 0;

  const u64 hw[]    = { 1, 32, 1024, 24576, 65536 };
  const u32 accel[] = { 1, 2, 17, 64, 335, 1024 };

  for (u32 a = 0; a < sizeof (hw) / sizeof (hw[0]); a++)
  {
    for (u32 b = 0; b < sizeof (accel) / sizeof (accel[0]); b++)
    {
      const u64 hardware_power = hw[a];
      const u64 kernel_power   = hw[a] * accel[b];

      for (u32 n = 1; n <= 8; n++)
      {
        const u64 hardware_power_all = hardware_power * n;

        for (u64 kpf = 0; kpf < kernel_power * (u64) n + 7; kpf += (kernel_power / 3) + 1)
        {
          const u64 got = dispatch_slice    (kpf, hardware_power, hardware_power_all, kernel_power);
          const u64 ref = reference_slice (kpf, hardware_power, hardware_power_all, kernel_power);

          if (got != ref)
          {
            printf ("  MISMATCH kpf=%" PRIu64 " hw=%" PRIu64 " hw_all=%" PRIu64 " kp=%" PRIu64 ": got %" PRIu64 " want %" PRIu64 "\n",
                    kpf, hardware_power, hardware_power_all, kernel_power, got, ref);
            return -1;
          }

          checked++;
        }
      }
    }
  }

  printf ("equivalence vs pre-refactor formula: %" PRIu64 " input combinations, all identical\n\n", checked);

  return 0;
}

typedef struct
{
  const char *name;
  u32         devices;
  u64         hardware_power;
  u32         accel;
  double      rate[MAX_DEV];   // work units per second, per device
  double      chunk_rounds;    // chunk size as a multiple of kernel_power_all
  double      min_efficiency;  // what the schedule has to achieve
} scenario_t;

typedef struct
{
  double efficiency;
  double makespan;
  double ideal;
  double idle_total;
  u64    slices;
  u64    words_base;
  u64    handed_out;
  u64    slices_full;   // what it would take if every slice were a full kernel_power
  u64    work_done[MAX_DEV];
  double busy[MAX_DEV];
} result_t;

static void simulate (const scenario_t *sc, result_t *r)
{
  const u64 kernel_power       = sc->hardware_power * sc->accel;
  const u64 kernel_power_all   = kernel_power * sc->devices;
  const u64 hardware_power_all = sc->hardware_power * sc->devices;
  const u64 words_base         = (u64) (sc->chunk_rounds * (double) kernel_power_all);

  double free_at[MAX_DEV];
  bool   finished[MAX_DEV];

  memset (r, 0, sizeof (result_t));

  for (u32 i = 0; i < sc->devices; i++)
  {
    free_at[i]  = 0.0;
    finished[i] = false;
  }

  u64 words_off          = 0;
  u64 kernel_power_final = 0;

  // whichever device frees up first is the one that asks next, which is what the real dispatcher does

  for (;;)
  {
    int    pick = -1;
    double best = 0.0;

    for (u32 i = 0; i < sc->devices; i++)
    {
      if (finished[i] == true) continue;

      if ((pick < 0) || (free_at[i] < best))
      {
        pick = (int) i;
        best = free_at[i];
      }
    }

    if (pick < 0) break;

    bool latched = false;

    const u64 work = dispatch_take (&kernel_power_final,
                                    words_off,
                                    words_base,
                                    kernel_power_all,
                                    hardware_power_all,
                                    sc->hardware_power,
                                    kernel_power,
                                    (u64) -1,
                                    &latched);

    if (work == 0)
    {
      finished[pick] = true;

      continue;
    }

    words_off += work;

    const double secs = (double) work / sc->rate[pick];

    const double started = free_at[pick];

    free_at[pick]      += secs;
    r->busy[pick]      += secs;
    r->work_done[pick] += work;
    r->slices++;

    if (g_verbose == true)
    {
      printf ("    slice %3" PRIu64 "  dev %u  size %10" PRIu64 "  busy %12.0f -> %12.0f  left %12" PRIu64 "\n",
              r->slices, (u32) pick, work, started, free_at[pick], words_base - words_off);
    }
  }

  r->words_base  = words_base;
  r->slices_full = (words_base + kernel_power - 1) / kernel_power;

  for (u32 i = 0; i < sc->devices; i++) r->handed_out += r->work_done[i];

  double rate_all = 0.0;
  double makespan = 0.0;

  for (u32 i = 0; i < sc->devices; i++)
  {
    rate_all += sc->rate[i];

    if (free_at[i] > makespan) makespan = free_at[i];
  }

  r->ideal    = (double) words_base / rate_all;
  r->makespan = makespan;

  for (u32 i = 0; i < sc->devices; i++) r->idle_total += makespan - r->busy[i];

  r->efficiency = (makespan > 0.0) ? r->ideal / makespan : 1.0;

  if (g_verbose == true)
  {
    for (u32 i = 0; i < sc->devices; i++)
    {
      printf ("    dev %u  work %12" PRIu64 "  busy %12.0f  idle %12.0f  (makespan %.0f)\n",
              i, r->work_done[i], r->busy[i], makespan - r->busy[i], makespan);
    }

    printf ("    ideal makespan %.0f, actual %.0f, so efficiency %.1f%%\n\n", r->ideal, makespan, r->efficiency * 100.0);
  }
}

int main (int argc, char **argv)
{
  for (int i = 1; i < argc; i++)
  {
    if (strcmp (argv[i], "-v") == 0) g_verbose = true;
  }

  printf ("dispatch_sim: how the keyspace gets spread across devices\n\n");

  if (check_equivalence () != 0) return 1;

  // rounds = words_base / kernel_power_all. Measured on an RTX 2000 Ada: kernel_power is about
  // 8.2M base words for a fast or medium mode and 506k for bcrypt. So a rockyou straight attack is
  // 1.7 rounds on one GPU and 0.44 on four, a ?l x8 mask is 975, and ?a x8 is 8.5 million. Both ends
  // are here because they behave differently: the few-round end is where the tail is the whole run.

  scenario_t scenarios[] =
  {
    { "1 dev, 10 rounds",                 1, 24576, 335, {1,1,1,1}, 10.0,     0.98 },
    { "4 dev, 0.44 rounds (rockyou x4)",  4, 24576, 335, {1,1,1,1},  0.44,    0.85 },
    { "1 dev, 1.7 rounds (rockyou x1)",   1, 24576, 335, {1,1,1,1},  1.7,     0.95 },
    { "4 dev, 1.05 rounds",               4, 24576, 335, {1,1,1,1},  1.05,    0.90 },
    { "4 dev, 1.5 rounds",                4, 24576, 335, {1,1,1,1},  1.5,     0.90 },
    { "4 dev, 2 rounds",                  4, 24576, 335, {1,1,1,1},  2.0,     0.90 },
    { "4 dev, 4 rounds",                  4, 24576, 335, {1,1,1,1},  4.0,     0.92 },
    { "4 dev, 7 rounds (bcrypt rockyou)", 4, 24576, 335, {1,1,1,1},  7.0,     0.95 },
    { "4 dev, 100 rounds",                4, 24576, 335, {1,1,1,1},  100.0,   0.98 },
    { "4 dev, 1000 rounds",               4, 24576, 335, {1,1,1,1},  1000.0,  0.99 },
    { "4 dev, 100k rounds (?l x8 mask)",  4, 24576, 335, {1,1,1,1},  100000.0,0.99 },
    { "8 dev, 100k rounds",               8, 24576, 335, {1,1,1,1,1,1,1,1}, 100000.0, 0.99 },
    { "2 dev, 1.5 rounds",                2, 24576, 335, {1,1,1,1},  1.5,     0.90 },
    { "4 dev mixed 2:1, 1.5 rounds",      4, 24576, 335, {2,2,1,1},  1.5,     0.90 },
    { "4 dev mixed 2:1, 100 rounds",      4, 24576, 335, {2,2,1,1},  100.0,   0.95 },
    { "4 dev, below one slice",           4, 24576, 335, {1,1,1,1},  0.1,     0.50 },
  };

  int fails = 0;

  printf ("%-34s %8s %7s %8s %10s  %s\n", "scenario", "slices", "vs_full", "eff", "idle_s", "verdict");

  for (u32 i = 0; i < sizeof (scenarios) / sizeof (scenarios[0]); i++)
  {
    result_t r;

    if (g_verbose == true) printf ("  %s\n", scenarios[i].name);

    const bool trace_this = g_verbose;

    g_verbose = (scenarios[i].chunk_rounds <= 2.0) ? trace_this : false;

    simulate (&scenarios[i], &r);

    g_verbose = trace_this;

    // Work conservation is the one that is not a matter of degree: every word of the keyspace has to
    // be handed to exactly one device. Short means candidates never tried, over means duplicated work
    // and a progress figure past 100 percent.

    const bool conserved = (r.handed_out == r.words_base);

    const bool ok = (r.efficiency >= scenarios[i].min_efficiency) && conserved;

    if (ok == false) fails++;

    printf ("%-34s %8" PRIu64 " %6.2fx %7.1f%% %10.1f  %-4s %s\n",
            scenarios[i].name, r.slices,
            (r.slices_full > 0) ? (double) r.slices / (double) r.slices_full : 0.0,
            r.efficiency * 100.0, r.idle_total,
            ok ? "pass" : "FAIL",
            conserved ? "" : "WORK NOT CONSERVED");
  }

  printf ("\n%d of %zu scenarios failed\n", fails, sizeof (scenarios) / sizeof (scenarios[0]));

  return (fails > 0) ? 1 : 0;
}
