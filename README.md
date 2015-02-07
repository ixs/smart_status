# smart_status
Python wrapper around smartctl which is supposed to make it usable

Use all available SMART data to ascertain whether a disk is probably okay or not.

As customer available SMART attributes are basically unusable to predict failure, the script will schedule selftests in order to discover disk (hopefully) before they result in loss of data.

The -n parameter will trigger nagios compatible output.

The script can autodetect disks.


Sample output:

# ./smart_status.py -a
/dev/sda: Disk healthy
/dev/sdb: Disk healthy
/dev/sdc: Disk healthy
/dev/sdd: Disk healthy
/dev/sde: Disk healthy
/dev/sdf: Disk healthy
/dev/sdg: Disk healthy
/dev/sdh: Disk healthy
/dev/sdi: Disk healthy
/dev/sdj: Disk healthy
/dev/sdk: Disk healthy
/dev/sdl: Disk healthy
/dev/sdm: Disk healthy


Verbose output:

# ./smart_status.py -a -v
Checking /dev/sda:
/dev/sda SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sda Last SMART selftest had a problem: The self-test routine was aborted by the host..
/dev/sda last extended offline selftest completed without error and finished 12 days 22 hours ago.
Checking /dev/sdb:
/dev/sdb SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdb Last SMART selftest had a problem: The self-test routine was aborted by the host..
/dev/sdb last extended offline selftest completed without error and finished 12 days 23 hours ago.
Checking /dev/sdc:
/dev/sdc SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdc Last SMART selftest had a problem: The self-test routine was aborted by the host..
/dev/sdc last extended offline selftest completed without error and finished 12 days 16 hours ago.
Checking /dev/sdd:
/dev/sdd SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdd Last SMART selftest had a problem: The self-test routine was aborted by the host..
/dev/sdd last extended offline selftest completed without error and finished 12 days 22 hours ago.
Checking /dev/sde:
/dev/sde does not support SMART attributes.
/dev/sde does not support SMART selftest.
/dev/sde SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sde cannot determine selftest status.
/dev/sde never finished a SMART selftest.
Checking /dev/sdf:
/dev/sdf SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdf No SMART selftest is currently running.
/dev/sdf last extended offline selftest completed without error and finished 7 days 5 hours ago.
Checking /dev/sdg:
/dev/sdg smartctl output: Some SMART or other ATA command to the disk failed, or there was a checksum error in a SMART data structure
/dev/sdg SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdg No SMART selftest is currently running.
/dev/sdg never finished a SMART selftest.
Checking /dev/sdh:
/dev/sdh SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdh No SMART selftest is currently running.
/dev/sdh last extended offline selftest completed without error and finished 7 days 6 hours ago.
Checking /dev/sdi:
/dev/sdi SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdi No SMART selftest is currently running.
/dev/sdi last extended offline selftest completed without error and finished 7 days 6 hours ago.
Checking /dev/sdj:
/dev/sdj SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdj No SMART selftest is currently running.
/dev/sdj last extended offline selftest completed without error and finished 12 days 10 hours ago.
Checking /dev/sdk:
/dev/sdk smartctl output: Some SMART or other ATA command to the disk failed, or there was a checksum error in a SMART data structure
/dev/sdk SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdk Last SMART selftest had a problem: The self-test routine was aborted by the host..
/dev/sdk last extended offline selftest completed without error and finished 12 days 18 hours ago.
Checking /dev/sdl:
/dev/sdl SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdl Last SMART selftest had a problem: The self-test routine was aborted by the host..
/dev/sdl last extended offline selftest completed without error and finished 13 days 9 hours ago.
Checking /dev/sdm:
/dev/sdm SMART Health status is PASSED. (This value cannot necessarily be trusted)
/dev/sdm No SMART selftest is currently running.
/dev/sdm last extended offline selftest completed without error and finished 6 days 19 hours ago.
/dev/sda: Disk healthy
/dev/sdb: Disk healthy
/dev/sdc: Disk healthy
/dev/sdd: Disk healthy
/dev/sde: Disk healthy
/dev/sdf: Disk healthy
/dev/sdg: Disk healthy
/dev/sdh: Disk healthy
/dev/sdi: Disk healthy
/dev/sdj: Disk healthy
/dev/sdk: Disk healthy
/dev/sdl: Disk healthy
/dev/sdm: Disk healthy


Nagios compatible output:

# ./smart_status.py -n -a
OK: smart_status reports 13 disk(s) as okay. /dev/sda: Ok, /dev/sdb: Ok, /dev/sdc: Ok, /dev/sdd: Ok, /dev/sde: Ok, /dev/sdf: Ok, /dev/sdg: Ok, /dev/sdh: Ok, /dev/sdi: Ok, /dev/sdj: Ok, /dev/sdk: Ok, /dev/sdl: Ok, /dev/sdm: Ok


Help output:

# ./smart_status.py -h
usage: smart_status.py [-h] (-a | -d DISKS | -b SMARTCTL) [-n]
                       [-u {warning,critical}] [-w {unknown,critical}]
                       [-i IGNORE [IGNORE ...]] [-s SCHEDULE] [-t THRESHOLD]
                       [-v] [-x] [-c]

Hard drives use Self-Monitoring, Analysis and Reporting Technology (SMART) to
export data about the health of a disk device. smart_status.py is a tool to
parse this data and tries to detect pending or post disk failures and report
on disk status. Unfortunately SMART failure prediction is rarely reliable.
Reporting on actual disk failures however generally works.

optional arguments:
  -h, --help            show this help message and exit
  -a, --autodetect, --all
                        Autodetect disks and scan.
  -d DISKS, --disks DISKS
                        Only handle specific disk device.
  -b SMARTCTL, --smartctl SMARTCTL
                        Overide smartctl binary location if not in path.
  -i IGNORE [IGNORE ...], --ignore IGNORE [IGNORE ...]
                        Ignore specific disk devices. Helpful when scanning
                        for all disks.
  -s SCHEDULE, --schedule SCHEDULE
                        Frequency in days after which a selftest is considered
                        out of date and will be rescheduled.
  -t THRESHOLD, --threshold THRESHOLD
                        Frequency in days after which a selftest is considered
                        out of date and will be warned about but not
                        rescheduled.
  -v, --verbose         Print more status information.
  -x, --strict          Strict checking. Report a device not supporting SMART
                        attributes or selftest as unknown/error instead of
                        relying on the unreliable general SMART health
                        feedback.
  -c, --color, --colour
                        Colorize output.

Nagios:
  Format output to be usable as a Nagios compatible plugin.

  -n, --nagios          Return data in a form usable as a nagios check.
  -u {warning,critical}, --unknown {warning,critical}
                        Change alert level of unknown smart status.
  -w {unknown,critical}, --warning {unknown,critical}
                        Change alert level of warning smart status.

