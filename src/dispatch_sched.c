/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "dispatch_sched.h"

u64 dispatch_slice (const u64 kernel_power_final,
                    const u64 hardware_power,
                    const u64 hardware_power_all,
                    const u64 kernel_power)
{
  if (kernel_power_final)
  {
    const double device_factor = (double) hardware_power / hardware_power_all;

    const u64 words_left_device = (u64) CEIL (kernel_power_final * device_factor);

    // work should be at least the hardware power available without any accelerator

    const u64 work = MAX (words_left_device, hardware_power);

    // we need to make sure the value is not larger than the regular kernel_power

    const u64 work_final = MIN (work, kernel_power);

    return work_final;
  }

  return kernel_power;
}

u64 dispatch_take (u64 *kernel_power_final,
                   const u64 words_off,
                   const u64 words_base,
                   const u64 kernel_power_all,
                   const u64 hardware_power_all,
                   const u64 hardware_power,
                   const u64 kernel_power,
                   const u64 max,
                   bool *latched)
{
  *latched = false;

  // words_off can start beyond the keyspace. The brain sets it to the highest position the session
  // has already reached, and a later run of the same attack can have a smaller keyspace: fewer rules,
  // a tighter --limit, a wordlist that shrank. Unsigned subtraction then wraps to about 1.8e19, work
  // never runs out and the attack never finishes.

  const u64 words_left = (words_off < words_base) ? words_base - words_off : 0;

  if (words_left < kernel_power_all)
  {
    if (*kernel_power_final == 0)
    {
      *kernel_power_final = words_left;

      *latched = true;
    }
  }

  // Once the end is in sight the slice has to come down with the work that is left, and not stay at
  // the size the latch happened to see. Sized once, it leaves whichever device took a full slice just
  // before the latch grinding that slice out alone, because by the time it asks again there is nothing
  // left to hand it and the other devices have already stopped. Dividing what is actually left instead
  // makes the slices decay, so the devices land within one floor-sized slice of each other.
  //
  // The floor in dispatch_slice () is what stops the decay turning into a launch per work item.

  const u64 split = (*kernel_power_final != 0) ? words_left : 0;

  const u64 slice = dispatch_slice (split, hardware_power, hardware_power_all, kernel_power);

  u64 work = MIN (words_left, slice);

  work = MIN (work, max);

  return work;
}
