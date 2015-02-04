#!/usr/bin/python
#
# smartmontools disk status
#
# Copyright (c) 2015 Andreas Thienemann <andreas@bawue.net>
#
# Use all available SMART data to ascertain whether a disk is probably okay or not.
# As customer available SMART attributes are basically unusable to predict failure,
# the script will schedule selftests in order to discover disk (hopefully) before
# they result in loss of data.
#
# Licensed under the GPL v3.0 or any later version
#

import sys
import subprocess
import os
import time
import re
import pprint
import traceback
import stat
import argparse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class smart_status:
  def __init__(self):
    # The errorcode decoder map for smartctl taken from the manpage
    self.error_map = (
      'Command line did not parse.',
      'Device open failed, device did not return an IDENTIFY DEVICE structure, or device is in a low-power mode',
      'Some SMART or other ATA command to the disk failed, or there was a checksum error in a SMART data structure',
      'SMART status check returned "DISK FAILING"',
      'We found prefail Attributes <= threshold.',
      'SMART status check returned "DISK OK" but we found that some (usage or prefail) Attributes have been <= threshold at some time in the past.',
      'The device error log contains records of errors.',
      'The device self-test log contains records of errors.  [ATA only] Failed self-tests outdated by a newer successful extended self-test are ignored.'
    )

    self.cfg = dict() 
    self.cfg['smartctl_bin'] = 'smartctl'
    self.cfg['strict'] = False
    self.cfg['smartctl_test_threshold'] = 0
    self.cfg['smartctl_test_frequency'] = 0
    self.cfg['verbose'] = False
    self.cfg['color'] = False
    self.cfg['disks'] = list()

  def colorize(self, mode):
    if mode == False:
      bcolors.HEADER = ''
      bcolors.WARNING = ''
      bcolors.OKGREEN = ''
      bcolors.OKBLUE = ''
      bcolors.FAIL = ''
      bcolors.ENDC = ''


  def find_disks(self):
    disks = list()

    for dev in sorted(os.listdir('/sys/block')):
      try:
        with open('/sys/block/{}/device/type'.format(dev)) as f:
          if f.read().strip() == '0':
            disks.append('/dev/{}'.format(dev))
      except:
        continue

    return disks

  def schedule_selftest(self, dev, report = False):
    (smart_health, smart_selftest, smart_log, smart_attr) = self.fetch_smart(dev, report)

    if not self.judge_selftest(dev, smart_selftest, report = report):
      if report:
        print "{col}{dev} Cannot schedule SMART selftest.{cls}".format(col = bcolors.FAIL, dev = dev, cls=bcolors.ENDC)
      return False
    if self.judge_selftest_log(dev, smart_log, smart_attr, report = report)[1]:
      if report:
        print "{col}{dev} SMART selftest ran recently. Not scheduling a new one.{cls}".format(col = bcolors.OKBLUE, dev = dev, cls=bcolors.ENDC)
      return False
    else:
      if report:
        print "{col}{dev} Scheduling SMART selftest.{cls}".format(col = bcolors.HEADER, dev = dev, cls=bcolors.ENDC)

      output = subprocess.check_output([self.cfg['smartctl_bin'], '-t', 'long', dev])
      if 'Drive command "Execute SMART Extended self-test routine immediately in off-line mode" successful.' not in output:
        if report:
          print "{col}{dev} Scheduling SMART selftest failed.{cls}".format(col = bcolors.FAIL, dev = dev, cls=bcolors.ENDC)
          return False
      elif 'Testing has begun.' in output:
        for l in output.split("\n"):
          if l.startswith("Please wait "):
            duration = l.split()[2]
            continue
          if l.startswith("Test will complete after "):
            eta = l[len("Test will complete after "):]
        if report:
          print "{col}{dev} Scheduling SMART selftest successful. Expected duration {duration} min, ETA: {eta}.{cls}".format(col = bcolors.OKBLUE, dev = dev, duration = duration, eta = eta, cls=bcolors.ENDC)
        return True
        
      
  def judge_health(self, dev, smart_health, report = False):
    # Overall health
    try:
      if smart_health == "PASSED":
        healthy = True
        col = bcolors.HEADER
      else:
        col = bcolors.FAIL
        healthy = False
      if report:
        print "{col}{dev} SMART Health status is {health}. (This value cannot necessarily be trusted){cls}".format(col = col, dev = dev, health = smart_health, cls=bcolors.ENDC)
    except:
      if report:
        print "{col}{dev} SMART Health status cannot be determined.{cls}".format(col=bcolors.FAIL, dev = dev, health = smart_health, cls=bcolors.ENDC)
      healthy = None
    return healthy


  def judge_attributes(self, dev, smart_attr, report = False):
    healthy = None
    try:
      # Smart Attributes to watch
#     for a in ('Reallocated_Sector_Ct', 'Reported_Uncorrect', 'Command_Timeout', 'Current_Pending_Sector', 'Offline_Uncorrectable'):
#        try:
#          print a, smart_attr[a]['raw_value']
#        except:
#          print
      if int(smart_attr['Current_Pending_Sector']['raw_value']) > 0:
        if report:
          print "{col}{dev} SMART Attribute Current_Pending_Sector indicates failing disk.{cls}".format(col=bcolors.FAIL, dev = dev, health = smart_health, cls=bcolors.ENDC)
        healthy = False
      else:
        healthy = True
    except:
      pass
    return healthy

  def judge_selftest(self, dev, smart_selftest, report = False):
      """Judge whether we can schedule a selftest
      """

      try:
        (selftest_num, selftest_txt) = smart_selftest

        if selftest_num == 0:
          if report:
            print "{col}{dev} No SMART selftest is currently running.{cls}".format(col=bcolors.OKBLUE, dev = dev, txt = selftest_txt, cls=bcolors.ENDC)
          return True
        elif selftest_num >= 240 and selftest_num <= 250:
          if report:
            print "{col}{dev} SMART selftest is currently running: {txt}.{cls}".format(col=bcolors.OKBLUE, dev = dev, txt = selftest_txt, cls=bcolors.ENDC)
          return False
        elif selftest_num == 25:
          if report:
            print "{col}{dev} Last SMART selftest had a problem: {txt}.{cls}".format(col=bcolors.WARNING, dev = dev, txt = selftest_txt, cls=bcolors.ENDC)
          return True
        else:
          if report:
            print "{col}{dev} SMART selftest had a problem: {txt}.{cls}".format(col=bcolors.FAIL, dev = dev, txt = selftest_txt, cls=bcolors.ENDC)
          return True
      except:
        if report:
          print "{col}{dev} cannot determine selftest status.{cls}".format(col = bcolors.WARNING, dev = dev, cls = bcolors.ENDC)
        return False
        

  def judge_selftest_log(self, dev, smart_log, smart_attr, report = False):
      """
      returns (selftest ok, selftest current)
      """
      healthy = True
      current = None
      try:
        uptime = int(smart_attr['Power_On_Hours']['raw_value'])
      except:
        if report:
          #print "{col}{dev} cannot determine power on hours.{cls}".format(col=bcolors.WARNING, dev=dev, cls=bcolors.ENDC)
          pass
        pass

      try:
        # Iterate over the log entrys and ignore useless/invalid logs
        for entry in sorted(smart_log):
          if smart_log[entry]['Status'] in ('Self-test routine in progress', 'Interrupted (host reset)' and 'Aborted by host'):
            continue
          else:
            last_test = int(smart_log[entry]['LifeTime(hours)'])
            test_type = smart_log[entry]['Test_Description']
            test_state = smart_log[entry]['Status']
            test_diff = uptime - last_test
            break
        if test_diff < self.cfg['smartctl_test_frequency'] * 24 and test_state == 'Completed without error':
          if self.cfg['smartctl_test_frequency'] == 0:
            col = bcolors.HEADER
          else:
            col = bcolors.OKGREEN
            current = True
        elif test_diff >= self.cfg['smartctl_test_frequency'] * 24 * 2 and test_state == 'Completed without error':
          if self.cfg['smartctl_test_frequency'] == 0:
            col = bcolors.HEADER
          else:
            col = bcolors.FAIL
            current = False
        elif test_diff >= self.cfg['smartctl_test_frequency'] * 24 and test_state == 'Completed without error':
          if self.cfg['smartctl_test_frequency'] == 0:
            col = bcolors.HEADER
          else:
            col = bcolors.WARNING
            current = False
        elif test_state.startswith('Self-test routine in'):
          col = ''
          healthy = None
          current = True
        else:
          col = bcolors.FAIL
          healthy = False
          current = False
        if report:
          hrs = uptime - last_test
          if hrs < 1:
            tspec = '1 hour'
          elif hrs <= 24:
            tspec = '{} hours'.format(hrs)
          elif hrs > 24 and hrs < 24 * 2:
            tspec = '{} day {} hours'.format(hrs / 24, hrs % 24)
          elif hrs >= 24 * 2 and hrs < 24 * 14:
            tspec = '{} days {} hours'.format(hrs / 24, hrs % 24)
          else:
            tspec = '{} weeks {} days {} hours'.format(hrs / 24 / 7, hrs / 24, hrs % 24)

          print "{col}{dev} last {type} selftest {state} and finished {tspec} ago.{cls}".format(col = col, dev = dev, tspec = tspec, type = test_type.lower(), state = test_state.lower(), cls = bcolors.ENDC)
      except Exception, err:
        if report:
          print "{col}{dev} never finished a SMART selftest.{cls}".format(col = bcolors.WARNING, dev = dev, cls = bcolors.ENDC)
      return (healthy, current)


  def verify_smart(self, dev, report = False):
    """Verify the SMART status of a disk and return True or False depending on state.
    This is a guesstimate as SMART is basically unreliable"""

    health = []

    (smart_health, smart_selftest, smart_log, smart_attr) = self.fetch_smart(dev, report)
    try:
      # Overall health
      health.append(self.judge_health(dev, smart_health, report = report))

      # Attribute health
      health.append(self.judge_attributes(dev, smart_attr, report = report))

      # Smart Selftest capability
      self.judge_selftest(dev, smart_selftest, report = report)

      # Selftest log
      health.append(self.judge_selftest_log(dev, smart_log, smart_attr, report = report)[0])

    except Exception, err:
      print traceback.format_exc()
      raise(err)

    if None in health and self.cfg['strict'] == True:
      return None
    elif False in health:
      return False
    else:
      return True


  def fetch_smart(self, dev, report = False):
    """Verify the disk is still safe to use according to smartctl output.
    Yes, this is only a best effort... SMART is not trustworthy.
    """
    try:
      output = subprocess.check_output([self.cfg['smartctl_bin'], '-H', '-c', '-A', '-l', 'selftest', dev])
    except subprocess.CalledProcessError, e:
      ret = e.returncode
      output = e.output
      # Decode bitmasked return code
      msg = list()
      for i in range(0,len(self.error_map)):
        if ((ret & 2**i) >> i) != 0:
          msg.append(self.error_map[i])
      for m in msg:
        if report and self.error_map.index(m) in (2,) and smart.cfg['strict'] == False:
          col = bcolors.WARNING
        else:
          col = bcolors.FAIL
        if report:
          print "{col}{dev} smartctl output: {msg}{cls}".format(col=col, dev=dev, msg=m, cls=bcolors.ENDC)
          
        
    if report:
      if 'SMART Attributes Data Structure revision number' not in output:
        print "{col}{dev} does not support SMART attributes.{cls}".format(col=bcolors.WARNING, dev=dev, cls=bcolors.ENDC)
      if 'SMART Self-test log structure revision number' not in output:
        print "{col}{dev} does not support SMART selftest.{cls}".format(col=bcolors.WARNING, dev=dev, cls=bcolors.ENDC)

    # Simple smartctl output parser
    # Attributes we can split by whitespace
    # Log entries we need to parse by looking at str.find() based using the header as a template
    section = None
    attrs = dict()
    logs = dict()
    health = None
    selftest = list()
    linecont = False    # Is the next line a continuation of the current item? Important for capabilities
    for l in output.split("\n"):
      attr = dict()
      log = list()

      # section end
      if section is not None and l == "":
        section = None
        continue

      # Overall health
      if l.startswith("SMART overall-health self-assessment test result"):
        health = l.split(':')[1].strip()

      # Capabilities, we're only caring for the selftest status
      if l.startswith("General SMART Values"):
        section = 'cap'
        continue
      if section == 'cap':
        if l.startswith('Self-test execution status'):
          selftest.append(l)
          linecont = 'selftest'
          continue

        if linecont is not None and l.startswith("\t"):
          if linecont == 'selftest':
            selftest.append(l)
            continue
        else:
          linecont = None


      # Attr
      if l.startswith("Vendor Specific SMART Attributes with Thresholds"):
        section = 'attr'
        continue

      if section == 'attr':
        if l.startswith("ID#"):
          continue
        else:
          attr = dict(zip(('id', 'name', 'flag', 'value', 'worst', 'thresh', 'type', 'updated', 'when_failed', 'raw_value'), l.split(None, 9)))
          attrs[attr['name']] = attr


      # Log
      if l.startswith("SMART Self-test log structure revision number"):
        section = 'log'
        continue

      if section == 'log':
        if l.startswith("Num"):
          log_header = l
          log_item_pos = map(log_header.find, log_header.split())
          continue
        elif l.startswith('No self-tests have been logged.'):
          section = None
          continue

        else:
          for i in range(0, len(log_item_pos)):
            if i == 3:
              s = log_item_pos[i] + 5 # Special handling for the status where the table header doesn't line up with the table data
            else:
              s = log_item_pos[i]
            if i < len(log_item_pos) - 1:
              if i == 2:
                e = log_item_pos[i + 1] + 5 # Special handling for the status where the table header doesn't line up with the table data
              else:
                e = log_item_pos[i + 1]
            else:
              e = len(l)
            log.append(l[s:e].strip())
          logs[log[0]] = dict(zip(log_header.split(), log))

    # Fixup the selftest status
    try:
      m = re.search('\([ ]*(?P<num_status>\d+)\)\s(?P<text_status>.*)', selftest[0])
      num = int(m.group('num_status'))
      txt = ([m.group('text_status')])
      txt.extend(map(str.strip, selftest[1:]))
      txt = " ".join(txt)
      selftest = (num, txt)
    except:
      selftest = None

    return health, selftest, logs, attrs



def check_single_dev(dev, report = True):
    try:
      res = smart.verify_smart(dev, report)

      return res

    except Exception, err:
      pass
      print "{0} Error getting SMART data".format(dev)
      print traceback.format_exc()

def parse_opts():
  parser = argparse.ArgumentParser(description="""Hard drives use Self-Monitoring, Analysis and Reporting Technology (SMART) to export data about the health of a disk device.
{prog} is a tool to parse this data and tries to detect pending or post disk failures and report on disk status.
Unfortunately SMART failure prediction is rarely reliable.
Reporting on actual disk failures however generally works.""".format(prog=os.path.basename(sys.argv[0])))
  group_op_sel = parser.add_mutually_exclusive_group(required=True)
  group_op_sel.add_argument("-a", "--autodetect", "--all", action='store_true', help="Autodetect disks and scan.")
  group_op_sel.add_argument("-d", "--disks", action='append', nargs=1, help="Only handle specific disk device.")
  group_op_sel.add_argument("-b", "--smartctl", help="Overide smartctl binary location if not in path.", default = 'smartctl')
  group_nag = parser.add_argument_group('Nagios', description="Format output to be usable as a Nagios compatible plugin.")
  group_nag.add_argument("-n", "--nagios", action='store_true', help="Return data in a form usable as a nagios check.")
  group_nag.add_argument("-u", "--unknown", choices=['warning', 'critical'], help="Change alert level of unknown smart status.")
  group_nag.add_argument("-w", "--warning", choices=['unknown', 'critical'], help="Change alert level of warning smart status.")
  parser.add_argument("-i", "--ignore", action='append', nargs="+", help="Ignore specific disk devices. Helpful when scanning for all disks.", default = [])
  parser.add_argument("-s", "--schedule", type=int, help="Frequency in days after which a selftest is considered out of date and will be rescheduled.")
  parser.add_argument("-t", "--threshold", type=int, help="Frequency in days after which a selftest is considered out of date and will be warned about but not rescheduled.")
  parser.add_argument("-v", "--verbose", action='store_true', help="Print more status information.")
  parser.add_argument("-x", "--strict", action='store_true', help="Strict checking. Report a device not supporting SMART attributes or selftest as unknown/error instead of relying on the unreliable general SMART health feedback.", default = False)
  parser.add_argument("-c", "--color", "--colour", action='store_true', help="Colorize output.", default = False)
  args = parser.parse_args()
  return args

if __name__ == '__main__':
  smart = smart_status()
  args = parse_opts()

  smart.cfg['smartctl_bin'] = args.smartctl

  if args.autodetect:
    smart.cfg['disks'] = smart.find_disks()

  if args.strict:
    smart.cfg['strict'] = True

  if args.schedule == None:
    smart.cfg['smartctl_test_frequency'] = 0
  else:
    smart.cfg['smartctl_test_frequency'] = args.schedule

  if args.schedule == None:
    smart.cfg['smartctl_test_threshold'] = 0
  else:
    smart.cfg['smartctl_test_threshold'] = args.schedule

  if not args.color:
    smart.colorize(False)

  if args.verbose:
    smart.cfg['verbose'] = True

  try:
    map(lambda x: x[0], args.disks)
    smart.cfg['disks'] = sorted(list(set(map(lambda x: x[0], args.disks)) - set(map(lambda x: x[0], args.ignore))))
  except TypeError:
    print traceback.format_exc()
    pass

  if len(smart.cfg['disks']) > 0 and not args.nagios:
    col = list()
    msg = list()
    ret = list()
    sched = list()
    for disk in smart.cfg['disks']:
      try:
        if not stat.S_ISBLK(os.stat(disk).st_mode):
          raise()
      except:
        msg.append("Invalid device")
        ret.append(255)

      if smart.cfg['verbose']:
        print "Checking {}:".format(disk)
      res = check_single_dev(disk, report = smart.cfg['verbose'])

      if res == True:
        col.append(bcolors.OKGREEN)
        msg.append("Disk healthy")
        ret.append(0)
      elif res == None:
        col.append(bcolors.WARNING)
        msg.append("Insufficient SMART support")
        ret.append(2)
      else:
        col.append(bcolors.FAIL)
        msg.append("Disk failing")
        ret.append(1)

      if smart.cfg['smartctl_test_frequency'] > 0:
        if smart.cfg['verbose']:
          print "Scheduling selftest {}:".format(disk)
        if smart.schedule_selftest(disk, report = smart.cfg['verbose']):
          sched.append('New selftest scheduled.')
        else:
          sched.append('')
      else:
        sched.append('')

    for i in range(0, len(smart.cfg['disks'])):
      print "{disk}: {col}{msg}{cls} {sched}".format(col=col[i], msg=msg[i], disk=smart.cfg['disks'][i], cls=bcolors.ENDC, sched = sched[i])
    sys.exit(max(ret))

  elif 'disks' in args and args.nagios:
    res = dict()
    for disk in smart.cfg['disks']:
      res[disk] = check_single_dev(disk, report = smart.cfg['verbose'])
      if smart.cfg['smartctl_test_frequency'] > 0:
        smart.schedule_selftest(disk, report = smart.cfg['verbose'])

    # Format nagios line
    line = ''
    for disk in sorted(res):
      if res[disk] == True:
        status = 'Ok'
      elif res[disk] == None:
        status = 'Unkn'
      elif res[disk] == False:
        status = 'Err'
      line += "{}: {}, ".format(disk, status)
    line = line[:-2]

    if False in res.values():
      print 'CRITICAL: smart_status reports {} disk(s) as having errors. {}'.format(res.values().count(False), line)
      sys.exit(2)
    else:
      print 'OK: smart_status reports {} disk(s) as okay. {}'.format(res.values().count(True), line)
      sys.exit(0)

